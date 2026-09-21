use crate::ctx::{Ctx, Tunnel};
use chromiumoxide::Browser;
use futures::StreamExt;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};

pub struct Flags<'a> {
    pub t: Option<&'a Tunnel>,
    pub port: u16,
    pub bind: &'a str,
    pub ua: &'a str,
    pub headless_shell: bool,
}

pub struct Xvfb {
    c: std::process::Child,
    pub display: String,
}

impl Drop for Xvfb {
    fn drop(&mut self) {
        let _ = self.c.kill();
        let _ = self.c.wait();
    }
}

pub fn spawn_xvfb() -> Result<Xvfb, String> {
    if std::env::var("DISPLAY").map(|d| !d.is_empty()).unwrap_or(false) {
        return Ok(Xvfb {
            c: std::process::Command::new("true").stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| e.to_string())?,
            display: std::env::var("DISPLAY").unwrap(),
        });
    }
    let _ = std::fs::remove_file("/tmp/.X11-unix/X99");
    let c = std::process::Command::new("Xvfb")
        .args([":99", "-screen", "0", "1920x1080x24", "-ac", "-nolisten", "tcp", "-noreset"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Xvfb: {e}"))?;
    let x = Xvfb {
        c,
        display: ":99".into(),
    };
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(10) {
        if PathBuf::from("/tmp/.X11-unix/X99").exists() {
            return Ok(x);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("Xvfb did not start".into())
}

fn chrome_flags(f: &Flags) -> Vec<String> {
    let profile = match f.t {
        Some(t) => format!("/tmp/afeye/p{}", t.i),
        None => "/tmp/afeye/local".to_owned(),
    };
    let idx = f.t.map(|t| t.i as usize).unwrap_or(0);
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
        format!("--user-data-dir={}", profile),
        "--window-size=1280,832".into(),
        format!("--window-position={},{}", (idx % 4) * 320, (idx / 4) * 250),
    ];
    // afeye: UA override built from the chrome binary's real version - the
    // headless token (HeadlessChrome/x.y) leaks into request headers and
    // navigator.userAgent otherwise and anti-fraud keys on it.
    if !f.ua.is_empty() {
        a.push(format!("--user-agent={}", f.ua));
    }
    // afeye: per-bytecode V8 instruction trace (extreme volume) - explicit
    // opt-in; the sinks themselves activate through the AFEYE_SINK env var,
    // not through chrome flags.
    if std::env::var("AFEYE_V8_TRACE").is_ok() {
        a.push("--js-flags=--afeye-trace".into());
    }
    if std::env::var("AF_TEST_HEADLESS").is_ok() {
        a.push("--headless".into());
        a.push("--disable-gpu".into());
    }
    // v7: the CI build target is the REAL `chrome` (full platform - the
    // antifraud self-checks stay alive). It runs headed under the crawl's
    // Xvfb display, or --headless when AF_TEST_HEADLESS is set (since 132
    // --headless IS the full new headless - the old stripped one is gone).
    // Only a legacy headless_shell build takes the old path.
    if f.headless_shell {
        a.push("--headless".into());
        a.push("--disable-gpu".into());
    }
    a.push("about:blank".into());
    a
}

pub fn is_headless_shell(chrome: &std::path::Path) -> bool {
    chrome
        .file_name()
        .map(|x| x.to_string_lossy().contains("headless_shell"))
        .unwrap_or(false)
}

pub async fn launch_chrome(ctx: &Ctx, t: &Tunnel) -> Result<Child, String> {
    let flags = chrome_flags(&Flags {
        t: Some(t),
        port: t.port,
        bind: &t.ns_ip,
        ua: &ctx.ua,
        headless_shell: is_headless_shell(&ctx.chrome),
    });
    let mut c = Command::new("ip");
    c.args(["netns", "exec", &t.ns, "runuser", "-u", &t.user, "--"]);
    c.arg("env")
        .arg(format!("HOME=/tmp/afeye/h{}", t.i))
        .arg(format!("USER={}", t.user))
        .arg(format!("DISPLAY={}", ctx.display));
    // afeye: the sinks read AFEYE_SINK / AFEYE_RAW_DIR at process start;
    // runuser strips the parent environment, so pass them explicitly.
    // v12.4 (the empty-collect fix): pass ALWAYS, with the collector's own
    // defaults when the parent does not set them. Before, a scrubbed
    // parent (CI sudo -E carries AFEYE_SINK but not AFEYE_RAW_DIR) meant
    // the sinks wrote to THEIR default /tmp/afeye-raw while main.rs's
    // collector tailed AF_RAW_DIR... also /tmp/afeye-raw - the SAME dir,
    // so this pair accidentally worked, but only by default-coincidence.
    // Making it explicit closes the whole class: any AF_RAW_DIR override
    // now reaches the chrome side too (before it silently DIDN'T - the
    // collector tailed the override dir, the sinks kept writing the
    // default, zero records, empty collect, empty filtered zip).
    {
        let raw_dir = std::env::var("AFEYE_RAW_DIR").unwrap_or_else(|_| {
            std::env::var("AF_RAW_DIR").unwrap_or_else(|_| "/tmp/afeye-raw".into())
        });
        let sink = std::env::var("AFEYE_SINK").unwrap_or_else(|_| "1".into());
        c.arg(format!("AFEYE_SINK={}", sink));
        c.arg(format!("AFEYE_RAW_DIR={}", raw_dir));
    }
    c.arg(&ctx.chrome);
    for f in &flags {
        c.arg(f);
    }
    c.stdout(Stdio::null());
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("/tmp/afeye/chrome-{}.log", t.i))
        .ok();
    if let Some(f) = log {
        c.stderr(Stdio::from(f));
    } else {
        c.stderr(Stdio::null());
    }
    c.kill_on_drop(true);
    let child = c.spawn().map_err(|e| e.to_string())?;
    Ok(child)
}

pub async fn launch_chrome_local(ctx: &Ctx, port: u16) -> Result<Child, String> {
    let _ = std::fs::remove_dir_all("/tmp/afeye/local");
    let flags = chrome_flags(&Flags {
        t: None,
        port,
        bind: "127.0.0.1",
        ua: &ctx.ua,
        headless_shell: is_headless_shell(&ctx.chrome),
    });
    let mut c = Command::new(&ctx.chrome);
    // v12.4 (the empty-collect fix): the sinks inside chrome activate on
    // AFEYE_SINK and write to AFEYE_RAW_DIR - the SAME vars main.rs's
    // collector reads (AF_RAW_DIR for the tail side). A plain spawn
    // inherits the parent env, but a scrubbed parent (CI, systemd) meant
    // the sinks stayed OFF, chrome ran stock, and the capture died at the
    // very first record: collect/stats.json records=0, sink_alive=false,
    // filtered zip empty of chains. Force-inject the pair with the same
    // defaults the collector uses - the tunnel path (run_tunnel) has
    // passed them explicitly since v6; the local path simply forgot.
    let raw_dir = std::env::var("AFEYE_RAW_DIR")
        .unwrap_or_else(|_| std::env::var("AF_RAW_DIR").unwrap_or_else(|_| "/tmp/afeye-raw".into()));
    c.env("AFEYE_SINK", std::env::var("AFEYE_SINK").unwrap_or_else(|_| "1".into()));
    c.env("AFEYE_RAW_DIR", raw_dir);
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
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
            let req = format!("GET /json/version HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n");
            use std::io::{Read, Write};
            let w = s.write_all(req.as_bytes());
            if std::env::var("AF_DEBUG_HTTP").is_ok() {
                eprintln!("[afeye] http attempt {attempt} write={w:?}");
            }
            if w.is_ok() {
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
                if std::env::var("AF_DEBUG_HTTP").is_ok() {
                    eprintln!("[afeye] http read {} bytes", buf.len());
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

pub async fn run_tunnel(ctx: &Ctx, t: &Tunnel) -> Result<(Child, Browser), String> {
    let c = launch_chrome(ctx, t).await?;
    let b = connect(ctx, &t.ns_ip, t.port).await?;
    Ok((c, b))
}
