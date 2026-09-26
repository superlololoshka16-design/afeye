use crate::ctx::Ctx;
use chromiumoxide::Browser;
use futures::StreamExt;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};

fn jit_allowed() -> bool {
    std::env::var("AF_ALLOW_JIT").map(|v| v == "1").unwrap_or(false)
}

/// Headful only when the caller explicitly asks for it AND an X server is
/// actually reachable. Chrome without a display fails to start, so the
/// default must be headless on the full `chrome` binary.
fn headful() -> bool {
    std::env::var("AF_HEADFUL").map(|v| v == "1").unwrap_or(false)
        && std::env::var("DISPLAY").map(|d| !d.is_empty()).unwrap_or(false)
}

pub struct Flags<'a> {
    pub port: u16,
    pub bind: &'a str,
    pub ua: &'a str,
}

pub fn chrome_flags(f: &Flags) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--disable-session-crashed-bubble".into(),
        "--hide-crash-restore-bubble".into(),
        "--disable-search-engine-choice-screen".into(),
        "--disable-features=IsolateOrigins,site-per-process,PrivacySandboxSettings4".into(),
        "--disable-site-isolation-trials".into(),
        "--enable-unsafe-swiftshader".into(),
        "--password-store=basic".into(),
        "--use-mock-keychain".into(),
        "--no-sandbox".into(),
        format!("--remote-debugging-address={}", f.bind),
        format!("--remote-debugging-port={}", f.port),
        "--user-data-dir=/tmp/afeye/local".into(),
        "--window-size=1280,832".into(),
    ];
    if !f.ua.is_empty() {
        a.push(format!("--user-agent={}", f.ua));
    }
    // ALWAYS headless, on the FULL `chrome` binary. Two separate traps here:
    //   * `headless_shell` is the stripped test binary where antifraud
    //     self-checks die silently - it must not be preferred.
    //   * headful `chrome` needs an X server. This runs on CI/WSL with no
    //     DISPLAY, so a headful launch fails before it starts. Xvfb is gone.
    // `--enable-unsafe-swiftshader` above keeps WebGL/canvas working under
    // software rasterisation, which is what the fingerprint capture needs.
    if !headful() {
        a.push("--headless".into());
        a.push("--disable-gpu".into());
    }
    if !jit_allowed() {
        // afeye 0033: keep JS in the interpreter forever (no Sparkplug
        // baseline, no Maglev mid-tier, no TurboFan optimizing tier-up) so
        // the bytecode trace sees every instruction of the hot loop.
        // Deliberately NOT --jitless: that sets v8_flags.wasm_jitless and
        // routes WebAssembly through the DrumbraKE interpreter only, which
        // this build does not enable - wasm would not execute at all and
        // WASM-based antifraud (kasada, datadome, perimeterx, shape) would
        // never run. Pinning only the JS tiers leaves Liftoff (the wasm
        // baseline compiler) alive, so wasm executes and the 0028 shadow
        // hooks still fire.
        a.push("--js-flags=--no-opt --no-sparkplug --no-maglev".into());
    }
    a.push("about:blank".into());
    a
}

pub fn raw_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("AFEYE_RAW_DIR")
            .unwrap_or_else(|_| afeye::collect::DEFAULT_RAW_DIR.to_owned()),
    )
}

pub async fn launch_chrome_local(ctx: &Ctx, port: u16) -> Result<Child, String> {
    let _ = std::fs::remove_dir_all("/tmp/afeye/local");
    let _ = std::fs::create_dir_all("/tmp/afeye");
    let flags = chrome_flags(&Flags {
        port,
        bind: "127.0.0.1",
        ua: &ctx.ua,
    });
    let mut c = Command::new(&ctx.chrome);
    c.env("AFEYE_SINK", std::env::var("AFEYE_SINK").unwrap_or_else(|_| "1".into()));
    c.env("AFEYE_RAW_DIR", raw_dir());
    // AFEYE_VIRTUAL_CLOCK is OFF by default, and that is deliberate.
    //
    // It makes performance.now()/Date.now() advance by executed instruction
    // count: 10ns per instruction (AFEYE_VCLOCK_NS_PER_INSTR). Under the
    // 0033 bytecode trace the interpreter runs at roughly 1-5M instr/s, so
    // the page's clock advances 10-50ms per SECOND of wall time:
    //
    //     60s wall  -> page sees 0.6-3s      (57-59s behind)
    //     38m wall  -> page sees 23-114s     (36-38 MINUTES behind)
    //
    // An antifraud token carries a timestamp the server compares against its
    // own clock. Tens of minutes of skew means the token is rejected
    // unconditionally - the crawl would collect a rejected token every time.
    // It also desynchronises the two APIs it virtualises from the ones it
    // does not: performance.timeOrigin, event.timeStamp, rAF timestamps and
    // all network timings stay on the real clock, so
    // timeOrigin + performance.now() != Date.now() - a contradiction far
    // easier to detect than slow JS.
    //
    // Real wall clock is the right default: the token timestamp is then
    // correct and the server accepts it. Tracing dilation shows up only in
    // intra-token deltas, which is a much smaller risk than an invalid
    // timestamp. Set AF_VCLOCK=1 to turn it on for experiments, and tune
    // AFEYE_VCLOCK_NS_PER_INSTR so vclock tracks wall time.
    if std::env::var("AF_VCLOCK").map(|v| v == "1").unwrap_or(false) {
        c.env("AFEYE_VIRTUAL_CLOCK", "1");
        if let Ok(step) = std::env::var("AFEYE_VCLOCK_NS_PER_INSTR") {
            c.env("AFEYE_VCLOCK_NS_PER_INSTR", step);
        }
    }
    c.env("AFEYE_TRACE_BYTECODE", "1");
    for f in &flags {
        c.arg(f);
    }
    c.stdout(Stdio::null());
    if std::env::var("AF_DEBUG_ARGS").is_ok() {
        eprintln!("[afeye] chrome args: {flags:?}");
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/afeye/chrome-local.log")
        .ok();
    if let Some(f) = log {
        c.stderr(Stdio::from(f));
    } else {
        c.stderr(Stdio::null());
    }
    c.kill_on_drop(true);
    c.spawn().map_err(|e| e.to_string())
}

async fn http_json_version(ip: &str, port: u16) -> Result<String, String> {
    let addr: std::net::SocketAddr = format!("{ip}:{port}")
        .parse::<std::net::SocketAddr>()
        .map_err(|e| e.to_string())?;
    let t0 = Instant::now();
    loop {
        if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
            let req = format!("GET /json/version HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n");
            use std::io::{Read, Write};
            if s.write_all(req.as_bytes()).is_ok() {
                let mut buf = Vec::with_capacity(4096);
                loop {
                    let mut chunk = [0u8; 4096];
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                    if buf.len() > 1 << 20 {
                        break;
                    }
                }
                if let Ok(body) = simdutf8::basic::from_utf8(&buf) {
                    if let Some(p) = body.find("\"webSocketDebuggerUrl\"") {
                        if let Some(q1) = body[p..].find("ws://") {
                            let rest = &body[p + q1..];
                            if let Some(q2) = rest.find('"') {
                                return Ok(rest[..q2].to_owned());
                            }
                        }
                    }
                }
            }
        }
        if t0.elapsed() > Duration::from_secs(45) {
            return Err("devtools endpoint not reachable".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub async fn connect(ctx: &Ctx, ip: &str, port: u16) -> Result<Browser, String> {
    let _ = ctx;
    let ws = http_json_version(ip, port).await?;
    let (browser, mut handler) = Browser::connect(ws).await.map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        while let Some(h) = handler.next().await {
            if let Err(e) = h {
                eprintln!("[afeye] handler: {e}");
            }
        }
    });
    Ok(browser)
}
