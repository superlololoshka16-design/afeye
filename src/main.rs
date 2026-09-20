mod arch;
mod arena;
mod browser;
mod capture;
mod classify;
mod ctx;
mod events;
mod human;
mod inject;
mod relay;
mod sinkfilter;
mod tg;
mod timefmt;
mod wg;
mod writer;
mod zipper;

use afeye::collect;
use crate::ctx::{Ctx, Cn, Target, Tunnel};
use crate::events::{FxEvent, K_META};
use bytes::Bytes;
use futures::future::join_all;
use futures::StreamExt;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Serialize)]
struct MTun {
    name: String,
    endpoint: String,
    ns: String,
    user: String,
    egress: Option<String>,
    ok: bool,
}

#[derive(Serialize)]
struct MRun {
    started: String,
    slot: String,
    browse_secs: u64,
    chrome: String,
    binding: String,
    targets: Vec<String>,
    runner_ip: String,
    tunnels: Vec<MTun>,
    events: u64,
    requests: u64,
    responses: u64,
    bodies: u64,
    scripts: u64,
    batches: u64,
    pokes: u64,
    endpoints: u64,
    artifacts: u64,
    art_bytes: u64,
    dropped: u64,
    budget_used: u64,
    relay: u64,
    tg_sent: u64,
    cls_af: u64,
    cls_garbage: u64,
    cls_neutral: u64,
    cls_scripts: u64,
    cls_kept: u64,
    cls_dup: u64,
    cls_art_rm: u64,
    cls_bytes_rm: u64,
    zip: String,
    zip_bytes: u64,
    filtered: String,
    filtered_bytes: u64,
    collect_records: u64,
    collect_bytes: u64,
    collect_truncated: u64,
    collect_corrupt: u64,
    sink_alive: bool,
    sink_chains: u64,
    sink_hot: u64,
    sink_cold: u64,
    sink_wasm: u64,
    test: bool,
}

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

impl Ctx {
    pub fn budget_limit(&self) -> u64 {
        env_u64("AF_BUDGET_MB", 350) * 1024 * 1024
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

const TAB_UP: Duration = Duration::from_secs(90);

fn meta_ev(ctx: &Ctx, tun: u32, d: Bytes) {
    let _ = ctx.tx.send(FxEvent {
        t: now_ms(),
        site: 0,
        tun,
        tab: 0,
        vendor: 0,
        name: 0,
        kind: K_META,
        _pad: 0,
        d,
    });
}

fn dummy_tunnel() -> Tunnel {
    Tunnel {
        i: 0,
        name: "local".into(),
        user: "local".into(),
        ns: "local".into(),
        wg_if: "local".into(),
        h_if: "local".into(),
        n_if: "local".into(),
        host_ip: "127.0.0.1".into(),
        ns_ip: "127.0.0.1".into(),
        port: 0,
        endpoint: "local".into(),
        pubkey: String::new(),
        privkey: String::new(),
        addr: vec![],
        dns: vec![],
        egress: None,
    }
}

fn load_targets(p: &PathBuf) -> Result<Vec<Target>, String> {
    let raw = std::fs::read(p).map_err(|e| e.to_string())?;
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
        return Err("targets.json: no http targets".into());
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
    let local = std::env::var("AF_LOCAL").is_ok() || test;
    if !local && !is_root() {
        return Err("run as root or set AF_LOCAL=1".into());
    }
    let browse = Duration::from_secs(env_u64("AF_BROWSE_SECS", if test { 200 } else { 2280 }));
    let hard = Duration::from_secs(env_u64("AF_HARD_SECS", if test { 320 } else { 39 * 60 }));
    let stage = PathBuf::from("/tmp/afeye/stage");
    let out = root.join("dumps");
    let (tx, rx) = crossbeam_channel::unbounded::<FxEvent>();
    let (atx, arx) = crossbeam_channel::unbounded::<events::Art>();
    let targets = load_targets(&root.join("targets.json"))?;
    let mut tunnels: Vec<Tunnel> = Vec::new();
    if !local {
        let wgdir = root.join("wg");
        let mut confs: Vec<(String, String)> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&wgdir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "conf").unwrap_or(false) {
                    if let Ok(b) = std::fs::read(&p) {
                        if let Ok(s) = simdutf8::basic::from_utf8(&b) {
                            let name = p.file_stem().unwrap_or_default().to_string_lossy().to_string();
                            confs.push((name, s.to_owned()));
                        }
                    }
                }
            }
        }
        confs.sort();
        for (i, (name, raw)) in confs.iter().enumerate() {
            match wg::parse_conf(i as u32 + 1, name, raw) {
                Ok(t) => tunnels.push(t),
                Err(e) => eprintln!("[afeye] skip {name}: {e}"),
            }
        }
    }
    let interner = arena::Interner::new();
    for t in &targets {
        interner.intern(&t.host);
    }
    for (_, v) in ctx::VENDORS {
        interner.intern(v);
    }
    let binding = format!("_k{}z", t0ms % 997);
    let slot = timefmt::slot(t0ms, 30);
    let rid = timefmt::run_id(t0ms);
    let stage_run = stage.join(&slot);
    std::fs::create_dir_all(&stage_run).map_err(|e| e.to_string())?;
    // C++ sink collector: up before any chrome exists, drained after every
    // chrome is dead, so the raw record timeline lands inside the zip.
    // The raw dir must start EMPTY: FileTail rescans unseen files from
    // offset 0, so stale <layer>-<pid>.rec from a previous run would blend
    // into this timeline and the sink-hello liveness probe could pass from
    // a PREVIOUS run's records (pid reuse even re-opens them for append).
    let raw_dir = std::env::var("AF_RAW_DIR").unwrap_or_else(|_| "/tmp/afeye-raw".into());
    let _ = std::fs::create_dir_all(&raw_dir);
    if let Ok(rd) = std::fs::read_dir(&raw_dir) {
        for e in rd.flatten() {
            if e.path().extension().map(|x| x == "rec").unwrap_or(false) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let collector = collect::Collector::spawn(&stage_run);
    let chrome = find_chrome().ok_or("chrome binary not found")?;
    let ua = user_agent_for(&chrome);
    let xv = if local {
        None
    } else {
        Some(browser::spawn_xvfb()?)
    };
    let ctx = Arc::new(Ctx {
        stage: stage_run.clone(),
        slot: slot.clone(),
        t0ms,
        deadline: t0 + hard,
        browse,
        tx: tx.clone(),
        art: atx.clone(),
        interner,
        cn: Cn::new(),
        targets,
        tunnels,
        binding: binding.clone(),
        budget: std::sync::atomic::AtomicU64::new(0),
        chrome: chrome.clone(),
        ua,
        display: xv.as_ref().map(|x| x.display.clone()).unwrap_or_default(),
        endpoints: dashmap::DashMap::new(),
        gl_spoof: std::env::var("AF_GL_SPOOF").is_ok(),
    });
    for t in &ctx.tunnels {
        ctx.interner.intern(&t.endpoint.replace(':', "_"));
    }
    let writer = writer::spawn(rx, arx, ctx.clone());
    // afeye: probe the sink layer once, early. A chrome without the afeye
    // patches (stock upstream) writes zero sink-hello records, and without
    // this check the run stays silent about the deep layer being dead while
    // the zip pretends to be a deep capture. Warn once, fact goes into the
    // manifest at the end (sink_alive).
    {
        let probe = collector.hellos_handle();
        std::thread::Builder::new()
            .name("afeye-sink-probe".into())
            .spawn(move || {
                std::thread::sleep(Duration::from_secs(30));
                let n = probe();
                if n == 0 {
                    eprintln!(
                        "[afeye] WARN sink layer DEAD: chrome has no afeye sinks (stock build?) - deep v8/blink/net raw records missing, CDP layer only"
                    );
                } else {
                    eprintln!("[afeye] sink layer alive: {n} sink-hello records");
                }
            })
            .ok();
    }
    let runner_ip = if local {
        "local".into()
    } else {
        wg::runner_ip().await
    };
    eprintln!(
        "[afeye] run {rid} slot {slot} runner {runner_ip} targets {} tunnels {}",
        ctx.targets.len(),
        ctx.tunnels.len()
    );
    let mut good: Vec<Arc<Tunnel>> = Vec::new();
    if !local {
        let work = PathBuf::from("/tmp/afeye/wg");
        let _ = std::fs::create_dir_all(&work);
        let setups: Vec<_> = ctx
            .tunnels
            .iter()
            .map(|t| async {
                let ok = wg::prep_user_dirs(t).await.is_ok()
                    && wg::setup(t, &work).await.is_ok();
                (t.clone(), ok)
            })
            .collect();
        for (t, ok) in join_all(setups).await {
            if !ok {
                eprintln!("[afeye] {} setup failed", t.name);
                let _ = wg::teardown(&t).await;
            }
        }
        let verifies: Vec<_> = ctx
            .tunnels
            .iter()
            .map(|t| async { (t.clone(), wg::verify(t).await) })
            .collect();
        for (t, res) in join_all(verifies).await {
            let mut tt = t;
            match res {
                Ok(ip) => {
                    tt.egress = Some(ip.clone());
                    eprintln!("[afeye] {} egress {ip}", tt.name);
                    let mut j = events::J::new(128);
                    j.open();
                    j.fkey("egress");
                    j.s(&ip);
                    j.key("endpoint");
                    j.s(&tt.endpoint);
                    j.key("ok");
                    j.bool(true);
                    meta_ev(&ctx, tt.i, j.fin());
                    good.push(Arc::new(tt));
                }
                Err(e) => {
                    eprintln!("[afeye] {} verify failed: {e}", tt.name);
                    let mut j = events::J::new(160);
                    j.open();
                    j.fkey("egress");
                    j.s("");
                    j.key("endpoint");
                    j.s(&tt.endpoint);
                    j.key("ok");
                    j.bool(false);
                    j.key("err");
                    j.s(&e);
                    meta_ev(&ctx, tt.i, j.fin());
                    let _ = wg::teardown(&tt).await;
                }
            }
        }
    }
    let mut tbs: Vec<capture::Tb> = Vec::new();
    let mut children: Vec<tokio::process::Child> = Vec::new();
    let _dummy = Arc::new(dummy_tunnel());
    let spawn_tabs = |b: chromiumoxide::Browser, tun: u32| {
        let b = Arc::new(b);
        let jobs: Vec<_> = ctx
            .targets
            .iter()
            .enumerate()
            .map(|(i, tg)| {
                let b2 = b.clone();
                let ctx3 = ctx.clone();
                async move {
                    let page = match tokio::time::timeout(TAB_UP, b2.new_page("about:blank")).await {
                        Ok(Ok(p)) => p,
                        _ => return None,
                    };
                    let site = ctx3.interner.intern(&tg.host);
                    let tb = capture::Tb {
                        ctx: ctx3.clone(),
                        tun,
                        site,
                        tab: i as u32,
                        page,
                        meta: capture::Meta::default(),
                    };
                    let _ = tokio::time::timeout(TAB_UP, capture::instrument(tb.clone(), &tg.url)).await;
                    Some(tb)
                }
            })
            .collect();
        jobs
    };
    if local {
        let port: u16 = env_u64("AF_LOCAL_PORT", 9600) as u16;
        if let Ok(c) = browser::launch_chrome_local(&ctx, port).await {
            children.push(c);
            match browser::connect(&ctx, "127.0.0.1", port).await {
                Ok(b) => {
                    let tun = ctx.interner.intern("local");
                    tbs.extend(join_all(spawn_tabs(b, tun)).await.into_iter().flatten());
                }
                Err(e) => eprintln!("[afeye] connect: {e}"),
            }
        } else {
            eprintln!("[afeye] chrome: local launch failed");
        }
    } else {
        let mut futs = futures::stream::FuturesUnordered::new();
        for t in good {
            let c2 = ctx.clone();
            futs.push(async move {
                let tun_id = c2.interner.intern(&t.endpoint.replace(':', "_"));
                match browser::run_tunnel(&c2, &t).await {
                    Ok((c, b)) => Ok((c, b, tun_id)),
                    Err(e) => Err((e, t.name.clone())),
                }
            });
        }
        while let Some(r) = futs.next().await {
            match r {
                Ok((c, b, tun_id)) => {
                    children.push(c);
                    tbs.extend(join_all(spawn_tabs(b, tun_id)).await.into_iter().flatten());
                }
                Err((e, name)) => eprintln!("[afeye] {name} browser: {e}"),
            }
        }
    }
    eprintln!(
        "[afeye] browsing tabs={} setup={}s",
        tbs.len(),
        t0.elapsed().as_secs()
    );
    let left = ctx
        .deadline
        .saturating_duration_since(Instant::now())
        .saturating_sub(if hard.as_secs() > 600 { Duration::from_secs(420) } else { Duration::from_secs(90) })
        .max(Duration::from_secs(30));
    let want = ctx.browse.saturating_sub(Duration::from_secs(t0.elapsed().as_secs()));
    let session = want.min(left);
    let end = tokio::time::Instant::from_std(Instant::now() + session);
    let tabs: Vec<capture::Tab> = tbs
        .iter()
        .map(|tb| capture::Tab {
            page: tb.page.clone(),
            site: tb.site,
            tun: tb.tun,
            tab: tb.tab,
        })
        .collect();
    let hb = tokio::spawn(human::drive(ctx.clone(), tabs.clone()));
    let relay_on = std::env::var("AFEYE_QUEUE_URL").map(|u| u.starts_with("http")).unwrap_or(false);
    let rb = if relay_on {
        Some(tokio::spawn(relay::run(ctx.clone(), tabs)))
    } else {
        None
    };
    let tb_on = !test
        && !std::env::var("AFEYE_TG_TOKEN").unwrap_or_default().is_empty()
        && !std::env::var("AFEYE_TG_CHAT").unwrap_or_default().is_empty();
    let tg_thread = if tb_on {
        let ctx2 = ctx.clone();
        std::thread::Builder::new()
            .name("afeye-tg".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(r) => r,
                    Err(_) => return tg::TgOut { sent: 0, errors: 0 },
                };
                rt.block_on(tg::run(ctx2))
            })
            .ok()
    } else {
        None
    };
    tokio::select! {
        _ = tokio::time::sleep_until(end) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    eprintln!("[afeye] session end, finalizing");
    ctx.cn.stop.store(true, Ordering::Release);
    hb.abort();
    let _ = hb.await;
    let relay_out = match rb {
        Some(h) => match h.await {
            Ok(o) => o,
            Err(_) => relay::RelayOut { executed: 0, errors: 0 },
        },
        None => relay::RelayOut { executed: 0, errors: 0 },
    };
    let tg_out = match tg_thread.and_then(|h| h.join().ok()) {
        Some(o) => o,
        None => tg::TgOut { sent: 0, errors: 0 },
    };
    let mut futs = Vec::new();
    for tb in tbs.iter() {
        let tb2 = tb.clone();
        futs.push(tokio::spawn(async move {
            let _ = capture::finalize(&tb2).await;
        }));
    }
    for f in futs {
        let _ = f.await;
    }
    // graceful first: CDP Browser.close / SIGTERM lets the C++ atexit
    // Flush(500) drain the 8 MiB rings (a SIGKILL-only shutdown loses the
    // tail records AND the loss is invisible to the kind-39 witness, which
    // would turn "ring backlog lost at kill" into a false dead-end-proven).
    for mut c in children {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            let _ = c.start_kill();
            let _ = c.wait().await;
            let _ = std::process::Command::new("pkill")
                .args(["-TERM", "-f", &chrome.to_string_lossy()])
                .status();
        }
        let _ = c.kill().await;
    }
    // grace window: drain threads write out their rings before the collector
    // takes its final scan (the drain loop flushes on atexit within 500 ms).
    tokio::time::sleep(Duration::from_millis(1200)).await;
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("pkill")
            .args(["-KILL", "-f", &chrome.to_string_lossy()])
            .status();
    }
    if !local {
        for t in &ctx.tunnels {
            wg::teardown(t).await;
        }
    }
    let cstats = collector.stop();
    let sink_alive = ["v8/sink-hello", "blink/sink-hello", "net/sink-hello"]
        .iter()
        .filter_map(|k| cstats.per.get(*k).copied())
        .sum::<u64>()
        > 0;
    if !sink_alive {
        eprintln!(
            "[afeye] FINAL sink_alive=false: zero sink-hello records - this zip carries CDP-layer capture only (chrome is not afeye-patched)"
        );
    }
    eprintln!(
        "[afeye] collect: records={} bytes={} truncated={} corrupt={} files={}",
        cstats.records, cstats.bytes, cstats.truncated, cstats.corrupt, cstats.files
    );
    // deep sink filter: merge script fragments into chains, index wasm
    // imports/exports, slice cold branches out, link input -> event ->
    // timer -> network timing chains, then prune the per-record raw files
    // (the 10k one-kilo-file problem) - index.jsonl keeps every hash/ts.
    let mut sf_stats = sinkfilter::SinkFilterStats::default();
    match sinkfilter::run(&stage_run.join("collect")) {
        Ok(sf) => {
            eprintln!(
                "[afeye] sinkfilter: fragments={} chains={} hot={} cold={} wasm={} net_chains={} token={} dead_end={} net_adjacent={}",
                sf.fragments, sf.chains, sf.hot_chains, sf.cold_chains, sf.wasm_modules, sf.net_chains,
                sf.token_chains, sf.dead_end_chains, sf.net_adjacent_chains
            );
            eprintln!(
                "[afeye] verdicts: proven={} heuristic={} dead_end_proven={} unresolved={} graph: nodes={} edges={} tainted={} seeds={} fanout_dropped={}",
                sf.proven_chains, sf.heuristic_chains, sf.dead_end_proven, sf.unresolved_chains,
                sf.graph_nodes, sf.graph_edges, sf.graph_tainted, sf.graph_sinks, sf.graph_fanout_dropped
            );
            eprintln!(
                "[afeye] dead-end split: filtered zip carries the {} token-forming chains; all {} chains stay whole in the raw run zip",
                sf.token_chains, sf.chains
            );
            let raw_dir = stage_run.join("collect/raw");
            if sf.records > 0 {
                let _ = std::fs::remove_dir_all(&raw_dir);
            }
            sf_stats = sf;
        }
        Err(e) => eprintln!("[afeye] sinkfilter failed (raw kept for debug): {e}"),
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
            // v7 dead-end cut: this FILTERED zip keeps ONLY the chains that
            // feed the challenge token (token_forming in report.json). The
            // run zip above stays untouched - it still carries every kept
            // chain, token or not; nothing is lost, the two zips just sort
            // the same capture by different rules.
            let mut dropped = 0usize;
            if let Ok(rep) = std::fs::read(fdir.join("collect/filtered/report.json")) {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&rep) {
                    // v9: the authoritative cut set is report.prunes (EVERY
                    // not-token-forming chain, uncapped). The old chains[]
                    // walk silently missed chains past the 4000-entry report
                    // cap - eval storms leaked dead ends into the token-only
                    // zip. Fall back to chains[] for reports written by older
                    // filter versions.
                    if let Some(prune) = v.get("prune").and_then(|p| p.as_array()) {
                        for ch in prune {
                            let path = ch.get("path").and_then(|p| p.as_str()).unwrap_or("");
                            if !path.is_empty() {
                                let _ = std::fs::remove_file(fdir.join("collect").join(path));
                                dropped += 1;
                            }
                        }
                    } else if let Some(chains) = v.get("chains").and_then(|c| c.as_array()) {
                        for ch in chains {
                            let token = ch.get("token_forming").and_then(|t| t.as_bool()).unwrap_or(false);
                            let path = ch.get("path").and_then(|p| p.as_str()).unwrap_or("");
                            if !token && !path.is_empty() {
                                let _ = std::fs::remove_file(fdir.join("collect").join(path));
                                dropped += 1;
                            }
                        }
                    }
                }
            }
            eprintln!("[afeye] filtered zip: {dropped} dead-end chains removed (token-only)");
            let f7z = out.join(format!("{stem}-filtered.7z"));
            if arch::have_7z() {
                match arch::sz_pack(&fdir, &f7z, 0).await {
                    Ok(vols) => {
                        filtered_bytes = vols.iter().filter_map(|p| std::fs::metadata(p).ok()).map(|m| m.len()).sum();
                        filtered_name = f7z.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
                    }
                    Err(e) => eprintln!("[afeye] filtered 7z failed: {e}"),
                }
            } else {
                let fzip = out.join(format!("{stem}-filtered.zip"));
                if zipper::pack(&fdir, &fzip).is_ok() {
                    filtered_bytes = std::fs::metadata(&fzip).map(|m| m.len()).unwrap_or(0);
                    filtered_name = fzip.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
                }
            }
            let _ = std::fs::remove_dir_all(&fdir);
        }
    }
    if !filtered_name.is_empty() {
        eprintln!("[afeye] FILTERED {filtered_name} bytes={filtered_bytes}");
    }
    let mut mt = MRun {
        started: rid.clone(),
        slot: slot.clone(),
        browse_secs: session.as_secs(),
        chrome: chrome.to_string_lossy().to_string(),
        binding: binding.clone(),
        targets: ctx.targets.iter().map(|t| t.url.clone()).collect(),
        runner_ip,
        tunnels: ctx
            .tunnels
            .iter()
            .map(|t| MTun {
                name: t.name.clone(),
                endpoint: t.endpoint.clone(),
                ns: t.ns.clone(),
                user: t.user.clone(),
                egress: t.egress.clone(),
                ok: t.egress.is_some(),
            })
            .collect(),
        events: ctx.cn.ev.load(Ordering::Relaxed),
        requests: ctx.cn.req.load(Ordering::Relaxed),
        responses: ctx.cn.resp.load(Ordering::Relaxed),
        bodies: ctx.cn.body.load(Ordering::Relaxed),
        scripts: ctx.cn.scripts.load(Ordering::Relaxed),
        batches: ctx.cn.batch.load(Ordering::Relaxed),
        pokes: ctx.cn.poke.load(Ordering::Relaxed),
        endpoints: ctx.endpoints.len() as u64,
        artifacts: ctx.cn.art.load(Ordering::Relaxed),
        art_bytes: ctx.cn.bout.load(Ordering::Relaxed),
        dropped: ctx.cn.drop.load(Ordering::Relaxed),
        budget_used: ctx.budget.load(Ordering::Relaxed),
        relay: relay_out.executed,
        tg_sent: tg_out.sent,
        cls_af: cls.af,
        cls_garbage: cls.garbage,
        cls_neutral: cls.neutral,
        cls_scripts: cls.scripts,
        cls_kept: cls.kept,
        cls_dup: cls.dup,
        cls_art_rm: cls.art_rm,
        cls_bytes_rm: cls.bytes_rm,
        zip: zp.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default(),
        zip_bytes: 0,
        filtered: filtered_name,
        filtered_bytes,
        collect_records: cstats.records,
        collect_bytes: cstats.bytes,
        collect_truncated: cstats.truncated,
        collect_corrupt: cstats.corrupt,
        sink_alive,
        sink_chains: sf_stats.chains,
        sink_hot: sf_stats.hot_chains,
        sink_cold: sf_stats.cold_chains,
        sink_wasm: sf_stats.wasm_modules,
        test,
    };
    let mp = stage.join("manifest.json");
    let _ = std::fs::write(&mp, serde_json::to_vec_pretty(&mt).unwrap_or_default());
    let n = zipper::pack(&stage, &zp)?;
    let size = std::fs::metadata(&zp).map(|m| m.len()).unwrap_or(0);
    if size > 95 * 1024 * 1024 {
        eprintln!("[afeye] WARN zip > 95MB, lower AF_BUDGET_MB");
    }
    // sidecar manifest with the REAL zip size: the in-zip manifest is written
    // before packing, so its zip_bytes cannot know the archive size. The
    // sidecar lands next to the zip in dumps/ and is the observable truth.
    let ms = out.join(format!("{stem}.manifest.json"));
    mt.zip_bytes = size;
    let _ = std::fs::write(&ms, serde_json::to_vec_pretty(&mt).unwrap_or_default());
    eprintln!("[afeye] ZIP {} files={n} bytes={size}", zp.display());
    eprintln!("[afeye] done in {}s", t0.elapsed().as_secs());
    Ok(())
}

fn is_root() -> bool {
    unsafe { geteuid() == 0 }
}

unsafe fn geteuid() -> u32 {
    #[cfg(unix)]
    {
        extern "C" {
            fn geteuid() -> u32;
        }
        geteuid()
    }
    #[cfg(not(unix))]
    {
        1
    }
}

/// Build a headed Linux Chrome UA from the binary's own --version output.
/// Headless builds send `HeadlessChrome/x.y` in every request header and
/// expose it to `navigator.userAgent` - anti-fraud keys on exactly that.
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
                && t.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        })
        .unwrap_or("")
        .to_owned();
    if ver.is_empty() {
        // keep the token-free shape even when detection fails
        return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36".into();
    }
    eprintln!("[afeye] chrome {ver} -> UA override (no HeadlessChrome token)");
    format!("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36")
}

fn find_chrome() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AF_CHROME") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    for c in [
        "google-chrome-stable",
        "google-chrome",
        "/tmp/cft/chrome-linux64/chrome",
        "chromium-browser",
        "chromium",
        "/opt/afeye-chrome/chrome",
        "/opt/afeye-chrome/headless_shell",
    ] {
        if c.starts_with('/') {
            let pb = PathBuf::from(c);
            if pb.exists() {
                return Some(pb);
            }
            continue;
        }
        if let Ok(o) = std::process::Command::new("which").arg(c).output() {
            if o.status.success() {
                let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if !p.is_empty() {
                    return Some(PathBuf::from(p));
                }
            }
        }
    }
    None
}
