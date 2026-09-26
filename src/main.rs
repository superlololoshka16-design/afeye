mod arch;
mod arena;
mod browser;
mod capture;
mod classify;
mod ctx;
mod drive;
mod events;
mod motor;
mod timefmt;
mod writer;
mod zipper;

use crate::ctx::{Ctx, Target};
use crate::events::{FxEvent, K_META};
use afeye::collect;
use afeye::sinkfilter;
use bytes::Bytes;
use futures::future::join_all;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Serialize)]
struct MRun {
    started: String,
    slot: String,
    browse_secs: u64,
    chrome: String,
    targets: Vec<String>,
    events: u64,
    requests: u64,
    responses: u64,
    bodies: u64,
    endpoints: u64,
    artifacts: u64,
    art_bytes: u64,
    dropped: u64,
    budget_used: u64,
    img_budget_used: u64,
    bc_instructions: u64,
    bc_funcs: u64,
    bc_live_blocks: u64,
    bc_dead_blocks: u64,
    valuebook_entries: u64,
    valuebook_bytes: u64,
    offset_mismatch: u64,
    cls_af: u64,
    cls_garbage: u64,
    cls_neutral: u64,
    cls_scripts: u64,
    cls_kept: u64,
    cls_dup: u64,
    cls_art_rm: u64,
    cls_bytes_rm: u64,
    collect_records: u64,
    collect_bytes: u64,
    collect_truncated: u64,
    collect_corrupt: u64,
    sink_chains: u64,
    sink_wasm: u64,
    proven_chains: u64,
    dead_end_proven: u64,
    unresolved_chains: u64,
    value_proven_values: u64,
    graceful_shutdown: bool,
    term_waited_ms: u64,
    gate_passed: bool,
    zip: String,
    zip_bytes: u64,
    filtered: String,
    filtered_bytes: u64,
    test: bool,
}

fn env_u64(k: &str, d: u64) -> u64 {
    match std::env::var(k) {
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("[afeye] WARN {k}={v} is not a u64, falling back to {d}");
                d
            }
        },
        Err(_) => d,
    }
}

impl Ctx {
    pub fn budget_limit(&self) -> u64 {
        env_u64("AF_BUDGET_MB", 350) * 1024 * 1024
    }
    pub fn img_budget_limit(&self) -> u64 {
        env_u64("AF_IMG_BUDGET_MB", 150) * 1024 * 1024
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

const TAB_UP: Duration = Duration::from_secs(90);

fn load_targets(p: &Path) -> Result<Vec<Target>, String> {
    let raw = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let s = simdutf8::basic::from_utf8(&raw).map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(s).map_err(|e| e.to_string())?;
    let mut out: Vec<Target> = Vec::new();
    if let Some(arr) = v.get("targets").and_then(|x| x.as_array()) {
        for t in arr.iter() {
            if let Some(u) = t.as_str() {
                if u.starts_with("http") {
                    out.push(Target {
                        host: ctx::host_of(u).to_owned(),
                        url: u.to_owned(),
                    });
                }
            }
        }
    }
    if out.is_empty() {
        return Err(format!("{}: no http targets", p.display()));
    }
    Ok(out)
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("[afeye] fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let test = args.iter().any(|a| a == "--test" || a == "-test");
    let t0 = Instant::now();
    let t0ms = now_ms();
    let root = PathBuf::from(std::env::var("AF_ROOT").unwrap_or_else(|_| ".".into()));
    let browse = Duration::from_secs(env_u64("AF_BROWSE_SECS", if test { 200 } else { 2280 }));
    let hard = Duration::from_secs(env_u64("AF_HARD_SECS", if test { 320 } else { 39 * 60 }));
    let stage = PathBuf::from("/tmp/afeye/stage");
    let out = root.join("dumps");
    let (tx, rx) = crossbeam_channel::unbounded::<FxEvent>();
    let (atx, arx) = crossbeam_channel::unbounded::<events::Art>();
    let tpath = std::env::var("AF_TARGETS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("targets.example.json"));
    let targets = load_targets(&tpath)?;
    let interner = arena::Interner::new();
    for t in &targets {
        interner.intern(&t.host);
    }
    for (_, v) in ctx::VENDORS {
        interner.intern(v);
    }
    let tun = interner.intern("local");
    let slot = timefmt::slot(t0ms, 30);
    let rid = timefmt::run_id(t0ms);
    let stage_run = stage.join(&slot);
    std::fs::create_dir_all(&stage_run).map_err(|e| e.to_string())?;
    let collect_dir = stage_run.join("collect");
    let raw_dir = PathBuf::from(
        std::env::var("AFEYE_RAW_DIR").unwrap_or_else(|_| collect::DEFAULT_RAW_DIR.to_owned()),
    );
    let _ = std::fs::create_dir_all(&raw_dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&raw_dir) {
            let mut perm = meta.permissions();
            perm.set_mode(0o777);
            let _ = std::fs::set_permissions(&raw_dir, perm);
        }
    }
    if let Ok(rd) = std::fs::read_dir(&raw_dir) {
        for e in rd.flatten() {
            if e.path().extension().map(|x| x == "rec").unwrap_or(false) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let collector = collect::Collector::spawn_dirs(raw_dir, collect_dir.clone());
    let chrome = find_chrome(&root)?;
    let ua = user_agent_for(&chrome);
    let ctx = Arc::new(Ctx {
        stage: stage_run.clone(),
        slot: slot.clone(),
        t0ms,
        deadline: t0 + hard,
        browse,
        tx: tx.clone(),
        art: atx.clone(),
        interner,
        cn: ctx::Cn::new(),
        targets,
        budget: std::sync::atomic::AtomicU64::new(0),
        img_budget: std::sync::atomic::AtomicU64::new(0),
        chrome: chrome.clone(),
        ua,
        endpoints: dashmap::DashMap::new(),
    });
    let writer = writer::spawn(rx, arx, ctx.clone());
    {
        let probe = collector.hellos_handle();
        std::thread::Builder::new()
            .name("afeye-sink-probe".into())
            .spawn(move || {
                std::thread::sleep(Duration::from_secs(30));
                let n = probe();
                if n == 0 {
                    eprintln!(
                        "[afeye] WARN no sink-hello after 30s: the integrity gate will reject this run"
                    );
                } else {
                    eprintln!("[afeye] sink layers alive: {n} sink-hello records");
                }
            })
            .ok();
    }
    eprintln!(
        "[afeye] run {rid} slot {slot} chrome {} targets {}",
        chrome.display(),
        ctx.targets.len()
    );
    let port: u16 = env_u64("AF_LOCAL_PORT", 9600) as u16;
    let child = browser::launch_chrome_local(&ctx, port).await?;
    let cdp = browser::connect(&ctx, "127.0.0.1", port).await?;
    let mut tbs: Vec<capture::Tb> = Vec::new();
    for (i, tg) in ctx.targets.iter().enumerate() {
        let page = match tokio::time::timeout(TAB_UP, cdp.new_page("about:blank")).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                eprintln!("[afeye] tab {i} open: {e}");
                continue;
            }
            Err(_) => {
                eprintln!("[afeye] tab {i} open timeout");
                continue;
            }
        };
        let site = ctx.interner.intern(&tg.host);
        let tb = capture::Tb {
            ctx: ctx.clone(),
            tun,
            site,
            tab: i as u32,
            page,
            meta: capture::Meta::default(),
        };
        let _ = tokio::time::timeout(TAB_UP, capture::instrument(tb.clone(), &tg.url)).await;
        tbs.push(tb);
    }
    eprintln!(
        "[afeye] browsing tabs={} setup={}s",
        tbs.len(),
        t0.elapsed().as_secs()
    );
    let left = ctx
        .deadline
        .saturating_duration_since(Instant::now())
        .saturating_sub(if hard.as_secs() > 600 {
            Duration::from_secs(420)
        } else {
            Duration::from_secs(90)
        })
        .max(Duration::from_secs(30));
    let want = ctx
        .browse
        .saturating_sub(Duration::from_secs(t0.elapsed().as_secs()));
    let session = want.min(left);
    let end = tokio::time::Instant::from_std(Instant::now() + session);
    let drive_tabs = tbs.clone();
    let drive_ctx = ctx.clone();
    let driver = tokio::spawn(async move {
        drive::drive(drive_ctx, drive_tabs).await;
    });
    tokio::select! {
        _ = tokio::time::sleep_until(end) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    eprintln!("[afeye] session end, finalizing");
    ctx.cn.stop.store(true, Ordering::Release);
    let _ = driver.await;
    let futs: Vec<_> = tbs
        .iter()
        .map(|tb| {
            let tb2 = tb.clone();
            tokio::spawn(async move {
                let _ = capture::finalize(&tb2).await;
            })
        })
        .collect();
    for f in join_all(futs).await {
        let _ = f;
    }
    let (graceful, term_waited_ms) = terminate(child).await;
    let mut sj = events::J::new(64);
    sj.open();
    sj.fkey("graceful");
    sj.bool(graceful);
    sj.key("term_waited_ms");
    sj.u64v(term_waited_ms);
    if let Err(e) = std::fs::write(&collect_dir.join("shutdown.json"), &sj.fin()[..]) {
        eprintln!("[afeye] shutdown.json: {e}");
    }
    let _ = tx.send(FxEvent {
        t: now_ms(),
        site: 0,
        tun: 0,
        tab: 0,
        vendor: 0,
        name: 0,
        kind: K_META,
        _pad: 0,
        d: Bytes::from_static(b"{\"end\":true}"),
    });
    ctx.cn.dead.store(true, Ordering::Release);
    drop(tx);
    drop(atx);
    let _ = writer.join();
    let cstats = collector.stop();
    let h_v8 = cstats.per_count(collect::LAYER_V8, collect::KIND_SINK_HELLO);
    let h_blink = cstats.per_count(collect::LAYER_BLINK, collect::KIND_SINK_HELLO);
    let h_net = cstats.per_count(collect::LAYER_NET, collect::KIND_SINK_HELLO);
    eprintln!(
        "[afeye] collect: records={} bytes={} truncated={} corrupt={} files={}",
        cstats.records, cstats.bytes, cstats.truncated, cstats.corrupt, cstats.files
    );
    let bc = match afeye::bctrace::run(&collect_dir) {
        Ok(bc) => {
            eprintln!(
                "[afeye] bctrace: instructions={} funcs={} blocks live={} dead={} bytes live={} dead={} valuebook entries={} bytes={} offset_mismatch={}",
                bc.instructions, bc.funcs, bc.live_blocks, bc.dead_blocks,
                bc.live_bytes, bc.dead_bytes, bc.valuebook_entries, bc.valuebook_bytes,
                bc.offset_mismatch
            );
            bc
        }
        Err(e) => {
            eprintln!("[afeye] bctrace: {e}");
            afeye::bctrace::Stats::default()
        }
    };
    if h_v8 == 0 || h_blink == 0 || h_net == 0 || bc.instructions == 0 {
        eprintln!(
            "[afeye] GATE FAIL sink-hello v8={h_v8} blink={h_blink} net={h_net} bytecode instructions={}",
            bc.instructions
        );
        eprintln!("[afeye] no zip, no manifest: this run carries no engine-layer evidence");
        return Err(format!(
            "integrity gate: sink-hello v8={h_v8} blink={h_blink} net={h_net} instructions={}",
            bc.instructions
        ));
    }
    let mut sf_stats = sinkfilter::SinkFilterStats::default();
    match sinkfilter::run(&collect_dir, &bc.func_scripts, &bc.script_ids) {
        Ok(sf) => {
            eprintln!(
                "[afeye] sinkfilter: records={} fragments={} chains={} wasm={} prune_paths={}",
                sf.records, sf.fragments, sf.chains, sf.wasm_modules, sf.prune_paths
            );
            eprintln!(
                "[afeye] verdicts: proven={} (causality={} value={}) dead_end_proven={} unresolved={} unavailable={}",
                sf.proven_chains, sf.proven_causality, sf.proven_value,
                sf.dead_end_proven, sf.unresolved_chains, sf.unavailable_chains
            );
            eprintln!(
                "[afeye] sid-attribution: attributed={} sid_zero={} causality edges={} roots={}",
                sf.sid_attributed_records, sf.sid_zero_records, sf.causality_edges, sf.causality_roots
            );
            eprintln!(
                "[afeye] value-provenance: {} executed values byte-exact in sink payloads across {} scripts (ac matches={})",
                sf.value_proven_values, sf.value_proven_scripts, sf.ac_matches
            );
            eprintln!(
                "[afeye] completeness: drop_witnesses={} cap_exhausted={} exec_jit_violations={} incomplete={:?}",
                sf.drop_witnesses, sf.cap_exhausted, sf.exec_jit_violations, sf.incomplete_reasons
            );
            sf_stats = sf;
        }
        Err(e) => eprintln!("[afeye] sinkfilter failed (raw kept for debug): {e}"),
    }
    if std::env::var("AF_DELETE_RAW").map(|v| v == "1").unwrap_or(false) {
        let _ = std::fs::remove_dir_all(collect_dir.join("raw"));
    }
    let cls = classify::run(&stage_run);
    eprintln!(
        "[afeye] classify: af={} garbage={} neutral={} scripts={} kept={} dup={} art_rm={} bytes_rm={}",
        cls.af,
        cls.garbage,
        cls.neutral,
        cls.scripts,
        cls.kept,
        cls.dup,
        cls.art_rm,
        cls.bytes_rm
    );
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let stem = timefmt::zip_stem(t0ms);
    let zp = out.join(format!("{stem}.zip"));
    let mut filtered_name = String::new();
    let mut filtered_bytes = 0u64;
    {
        let fdir = PathBuf::from("/tmp/afeye/filtered");
        let _ = std::fs::remove_dir_all(&fdir);
        if let Err(e) = arch::copy_tree(&stage_run, &fdir) {
            eprintln!("[afeye] filtered copy failed: {e}");
        } else {
            classify::strict(&fdir);
            let mut dropped = 0usize;
            if let Ok(rep) = std::fs::read(collect_dir.join("filtered/report.json")) {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&rep) {
                    if let Some(prune) = v.get("prune").and_then(|p| p.as_array()) {
                        for ch in prune {
                            let path = ch.get("path").and_then(|p| p.as_str()).unwrap_or("");
                            if !path.is_empty() {
                                let _ = std::fs::remove_file(fdir.join("collect").join(path));
                                dropped += 1;
                            }
                        }
                    }
                }
            }
            eprintln!("[afeye] filtered archive: {dropped} pruned chains removed");
            let f7z = out.join(format!("{stem}-filtered.7z"));
            if arch::have_7z() {
                match arch::sz_pack(&fdir, &f7z, 0).await {
                    Ok(vols) => {
                        filtered_bytes = vols
                            .iter()
                            .filter_map(|p| std::fs::metadata(p).ok())
                            .map(|m| m.len())
                            .sum();
                        filtered_name = f7z
                            .file_name()
                            .map(|x| x.to_string_lossy().to_string())
                            .unwrap_or_default();
                    }
                    Err(e) => eprintln!("[afeye] filtered 7z failed: {e}"),
                }
            } else {
                let fzip = out.join(format!("{stem}-filtered.zip"));
                if zipper::pack(&fdir, &fzip).is_ok() {
                    filtered_bytes = std::fs::metadata(&fzip).map(|m| m.len()).unwrap_or(0);
                    filtered_name = fzip
                        .file_name()
                        .map(|x| x.to_string_lossy().to_string())
                        .unwrap_or_default();
                }
            }
            let _ = std::fs::remove_dir_all(&fdir);
        }
    }
    if !filtered_name.is_empty() {
        eprintln!("[afeye] FILTERED {filtered_name} bytes={filtered_bytes}");
    }
    let mt = MRun {
        started: rid,
        slot,
        browse_secs: session.as_secs(),
        chrome: chrome.to_string_lossy().to_string(),
        targets: ctx.targets.iter().map(|t| t.url.clone()).collect(),
        events: ctx.cn.ev.load(Ordering::Relaxed),
        requests: ctx.cn.req.load(Ordering::Relaxed),
        responses: ctx.cn.resp.load(Ordering::Relaxed),
        bodies: ctx.cn.body.load(Ordering::Relaxed),
        endpoints: ctx.endpoints.len() as u64,
        artifacts: ctx.cn.art.load(Ordering::Relaxed),
        art_bytes: ctx.cn.bout.load(Ordering::Relaxed),
        dropped: ctx.cn.drop.load(Ordering::Relaxed),
        budget_used: ctx.budget.load(Ordering::Relaxed),
        img_budget_used: ctx.img_budget.load(Ordering::Relaxed),
        bc_instructions: bc.instructions,
        bc_funcs: bc.funcs,
        bc_live_blocks: bc.live_blocks,
        bc_dead_blocks: bc.dead_blocks,
        valuebook_entries: bc.valuebook_entries,
        valuebook_bytes: bc.valuebook_bytes,
        offset_mismatch: bc.offset_mismatch,
        cls_af: cls.af,
        cls_garbage: cls.garbage,
        cls_neutral: cls.neutral,
        cls_scripts: cls.scripts,
        cls_kept: cls.kept,
        cls_dup: cls.dup,
        cls_art_rm: cls.art_rm,
        cls_bytes_rm: cls.bytes_rm,
        collect_records: cstats.records,
        collect_bytes: cstats.bytes,
        collect_truncated: cstats.truncated,
        collect_corrupt: cstats.corrupt,
        sink_chains: sf_stats.chains,
        sink_wasm: sf_stats.wasm_modules,
        proven_chains: sf_stats.proven_chains,
        dead_end_proven: sf_stats.dead_end_proven,
        unresolved_chains: sf_stats.unresolved_chains,
        value_proven_values: sf_stats.value_proven_values,
        graceful_shutdown: graceful,
        term_waited_ms,
        gate_passed: true,
        zip: zp
            .file_name()
            .map(|x| x.to_string_lossy().to_string())
            .unwrap_or_default(),
        zip_bytes: 0,
        filtered: filtered_name,
        filtered_bytes,
        test,
    };
    let mp = stage_run.join("manifest.json");
    let _ = std::fs::write(&mp, serde_json::to_vec_pretty(&mt).unwrap_or_default());
    let n = zipper::pack(&stage_run, &zp)?;
    let size = std::fs::metadata(&zp).map(|m| m.len()).unwrap_or(0);
    if size > 95 * 1024 * 1024 {
        eprintln!("[afeye] WARN zip > 95MB, lower AF_BUDGET_MB");
    }
    let ms = out.join(format!("{stem}.manifest.json"));
    let mut mt2 = mt;
    mt2.zip_bytes = size;
    let _ = std::fs::write(&ms, serde_json::to_vec_pretty(&mt2).unwrap_or_default());
    eprintln!("[afeye] ZIP {} files={n} bytes={size}", zp.display());
    eprintln!("[afeye] done in {}s", t0.elapsed().as_secs());
    Ok(())
}

async fn terminate(mut c: tokio::process::Child) -> (bool, u64) {
    let pid = match c.id() {
        Some(p) => p as i32,
        None => return (true, 0),
    };
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let t0 = Instant::now();
    let mut exited = false;
    while t0.elapsed() < Duration::from_secs(3) {
        match c.try_wait() {
            Ok(Some(_)) | Err(_) => {
                exited = true;
                break;
            }
            Ok(None) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let waited = t0.elapsed().as_millis() as u64;
    if !exited {
        eprintln!("[afeye] chrome pid {pid} ignored SIGTERM for {waited}ms, sending SIGKILL");
        let _ = c.kill().await;
    }
    (exited, waited)
}

fn user_agent_for(chrome: &PathBuf) -> String {
    let out = std::process::Command::new(chrome)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let ver = out
        .split_whitespace()
        .find(|t| {
            t.split('.').count() >= 3
                && t.split('.')
                    .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        })
        .unwrap_or("")
        .to_owned();
    if ver.is_empty() {
        return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36".into();
    }
    eprintln!("[afeye] chrome {ver} -> UA override (no HeadlessChrome token)");
    format!("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36")
}

const SINK_MARKER: &[u8] = b"afeye-sink/";

fn find_bytes(h: &[u8], n: &[u8]) -> bool {
    let first = match n.first() {
        Some(f) => *f,
        None => return false,
    };
    if h.len() < n.len() {
        return false;
    }
    let limit = h.len() - n.len();
    for (i, &b) in h.iter().enumerate().take(limit + 1) {
        if b == first && &h[i..i + n.len()] == n {
            return true;
        }
    }
    false
}

fn has_sink_marker(p: &Path) -> bool {
    use std::io::Read;
    const CHUNK: usize = 4 << 20;
    const OVL: usize = 64;
    let mut f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = vec![0u8; CHUNK + OVL];
    let mut base = 0usize;
    loop {
        let mut got = base;
        let mut eof = false;
        while got < buf.len() {
            match f.read(&mut buf[got..]) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => got += n,
                Err(_) => return false,
            }
        }
        if got == 0 {
            return false;
        }
        if find_bytes(&buf[..got], SINK_MARKER) {
            return true;
        }
        if eof {
            return false;
        }
        let start = got - OVL;
        buf.copy_within(start..got, 0);
        base = OVL;
    }
}

fn find_chrome(root: &Path) -> Result<PathBuf, String> {
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("AF_CHROME") {
        if !p.is_empty() {
            cands.push(PathBuf::from(p));
        }
    }
    cands.push(PathBuf::from("/opt/afeye-chrome/chrome"));
    for dir in [
        root.join("out/afeye"),
        PathBuf::from("out/afeye"),
        PathBuf::from("/mnt/chromium/src/out/afeye"),
    ] {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                let name = p.file_name().map(|x| x.to_string_lossy().to_string());
                if p.is_file() && name.map(|n| n.contains("chrome")).unwrap_or(false) {
                    cands.push(p);
                }
            }
        }
    }
    for c in &cands {
        if !c.is_file() {
            continue;
        }
        if has_sink_marker(c) {
            return Ok(c.clone());
        }
        eprintln!(
            "[afeye] chrome candidate {} has no afeye-sink/ marker (stock build), skipped",
            c.display()
        );
    }
    Err("no afeye-patched chrome found: build via scripts/build-chromium.sh or set AF_CHROME".into())
}
