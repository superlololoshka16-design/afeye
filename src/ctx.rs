use crate::arena::Interner;
use crate::events::{Art, FxEvent};
use crossbeam_channel::Sender;
use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const VENDORS: &[(&str, &str)] = &[
    ("challenges.cloudflare.com", "cloudflare"),
    ("cloudflare.com", "cloudflare"),
    ("cloudflareclient.com", "cloudflare"),
    ("datadome.co", "datadome"),
    ("kasada.io", "kasada"),
    ("perimeterx.net", "human"),
    ("px-cdn.net", "human"),
    ("px-client.net", "human"),
    ("humansecurity.com", "human"),
    ("humanbehavior.co", "human"),
    ("perfdrive.com", "human"),
    ("edgesuite.net", "akamai"),
    ("akamaiedge.net", "akamai"),
    ("akamai.com", "akamai"),
    ("akamaitech.net", "akamai"),
    ("fpjs.io", "fpjs"),
    ("fingerprintjs.com", "fpjs"),
    ("seon.io", "seon"),
    ("arkoselabs.com", "arkose"),
    ("funcaptcha.com", "arkose"),
    ("hcaptcha.com", "hcaptcha"),
    ("recaptcha.net", "recaptcha"),
    ("incapsula.com", "imperva"),
    ("imperva.com", "imperva"),
    ("incapdns.net", "imperva"),
    ("threatmetrix.net", "threatmetrix"),
    ("iovation.com", "iovation"),
    ("shapesecurity.com", "shape"),
    ("shape.com", "shape"),
];

pub fn char_floor(s: &str, n: usize) -> usize {
    if n >= s.len() {
        return s.len();
    }
    let b = s.as_bytes();
    let mut i = n;
    while i > 0 && (b[i] & 0xc0) == 0x80 {
        i -= 1;
    }
    i
}

pub fn host_of(url: &str) -> &str {
    let s = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => return "",
    };
    let auth_end = s.find(['/', '?', '#']).unwrap_or(s.len());
    let auth = &s[..auth_end];
    let hostport = match auth.rfind('@') {
        Some(i) => &auth[i + 1..],
        None => auth,
    };
    match hostport.rfind(':') {
        Some(i) if !hostport[..i].contains(':') || hostport.starts_with('[') => {
            if hostport.starts_with('[') {
                &hostport[..hostport.find(']').map(|j| j + 1).unwrap_or(hostport.len())]
            } else {
                &hostport[..i]
            }
        }
        _ => hostport,
    }
}

pub fn endpoint_of(url: &str) -> &str {
    let h = host_of(url);
    if h.is_empty() {
        return "";
    }
    let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
    let auth_end = url[scheme_end..]
        .find(['/', '?', '#'])
        .map(|i| scheme_end + i)
        .unwrap_or(url.len());
    let cut = url[auth_end..]
        .find(['?', '#'])
        .map(|i| auth_end + i)
        .unwrap_or(url.len());
    &url[..cut]
}

pub fn vendor_of_url(url: &str) -> Option<&'static str> {
    let h = host_of(url);
    if h.is_empty() {
        return None;
    }
    if url.contains("/cdn-cgi/") || url.contains("/turnstile") {
        return Some("cloudflare");
    }
    if url.contains("/recaptcha") {
        return Some("recaptcha");
    }
    for (suf, v) in VENDORS {
        if h == *suf || (h.len() > suf.len() && h.ends_with(suf) && h.as_bytes()[h.len() - suf.len() - 1] == b'.') {
            return Some(v);
        }
    }
    None
}

pub fn vendor_of_stack(s: &str) -> Option<&'static str> {
    let head = &s[..char_floor(s, 600)];
    for (suf, v) in VENDORS {
        if head.contains(suf) {
            return Some(v);
        }
    }
    None
}

#[repr(C, align(64))]
pub struct Cn {
    pub ev: AtomicU64,
    pub req: AtomicU64,
    pub resp: AtomicU64,
    pub body: AtomicU64,
    pub art: AtomicU64,
    pub scripts: AtomicU64,
    pub batch: AtomicU64,
    pub drop: AtomicU64,
    pub bin: AtomicU64,
    pub bout: AtomicU64,
    pub poke: AtomicU64,
    pub stop: AtomicBool,
    pub dead: AtomicBool,
    // afeye v123: our own driver footprint must be visible, never silent.
    // pauses = debugger-statement traps auto-resumed; ownskip = our own
    // evaluation/boot scripts excluded from the executing-script capture.
    pub pauses: AtomicU64,
    pub ownskip: AtomicU64,
}

impl Cn {
    pub fn new() -> Self {
        Cn {
            ev: AtomicU64::new(0),
            req: AtomicU64::new(0),
            resp: AtomicU64::new(0),
            body: AtomicU64::new(0),
            art: AtomicU64::new(0),
            scripts: AtomicU64::new(0),
            batch: AtomicU64::new(0),
            drop: AtomicU64::new(0),
            bin: AtomicU64::new(0),
            bout: AtomicU64::new(0),
            poke: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            dead: AtomicBool::new(false),
            pauses: AtomicU64::new(0),
            ownskip: AtomicU64::new(0),
        }
    }

    pub fn inc(f: &AtomicU64) -> u64 {
        f.fetch_add(1, Ordering::Relaxed) + 1
    }
}

pub struct Target {
    pub url: String,
    pub host: String,
}

#[derive(Clone)]
pub struct Tunnel {
    pub i: u32,
    pub name: String,
    pub user: String,
    pub ns: String,
    pub wg_if: String,
    pub h_if: String,
    pub n_if: String,
    pub host_ip: String,
    pub ns_ip: String,
    pub port: u16,
    pub endpoint: String,
    pub pubkey: String,
    pub privkey: String,
    pub addr: Vec<String>,
    pub dns: Vec<String>,
    pub egress: Option<String>,
}

pub struct Ctx {
    pub stage: PathBuf,
    pub slot: String,
    pub t0ms: u64,
    pub deadline: Instant,
    pub browse: Duration,
    pub tx: Sender<FxEvent>,
    pub art: Sender<Art>,
    pub interner: Interner,
    pub cn: Cn,
    pub targets: Vec<Target>,
    pub tunnels: Vec<Tunnel>,
    pub binding: String,
    pub gl_spoof: bool,
    pub budget: AtomicU64,
    pub chrome: PathBuf,
    pub display: String,
    pub endpoints: DashMap<u32, u64>,
    // afeye v123 stealth: one consistent UA everywhere (flag + CDP override +
    // full Sec-CH-UA brand list). No HeadlessChrome token can ever leave the
    // process, headless or not, patched build or stock.
    pub ua: String,
    pub ua_major: String,
    pub ua_full: String,
    pub inject_hash: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extract() {
        assert_eq!(host_of("https://accounts.x.ai/sign-up?x=1"), "accounts.x.ai");
        assert_eq!(host_of("http://127.0.0.1:8899/a"), "127.0.0.1");
        assert_eq!(host_of("https://u:p@ex.com/"), "ex.com");
    }

    #[test]
    fn vendors() {
        assert_eq!(vendor_of_url("https://challenges.cloudflare.com/v0/abc.js"), Some("cloudflare"));
        assert_eq!(vendor_of_url("https://js.datadome.co/tags.js"), Some("datadome"));
        assert_eq!(vendor_of_url("https://cdn.px-cdn.net/PX.js"), Some("human"));
        assert_eq!(vendor_of_url("https://t.fpjs.io/x"), Some("fpjs"));
        assert_eq!(vendor_of_url("https://ex.com/cdn-cgi/trace"), Some("cloudflare"));
        assert_eq!(vendor_of_url("https://ok.com/app.js"), None);
    }

    #[test]
    fn stack_multibyte_no_panic() {
        let s = "й".repeat(700);
        assert!(vendor_of_stack(&s).is_none());
        let s2 = format!("https://js.datadome.co/tags.js:1:1 {}", "д".repeat(700));
        assert_eq!(vendor_of_stack(&s2), Some("datadome"));
    }

    #[test]
    fn floor_boundaries() {
        assert_eq!(char_floor("abc", 10), 3);
        assert_eq!(char_floor("abcd", 2), 2);
        assert_eq!(char_floor("abйd", 3), 2);
    }

    #[test]
    fn endpoint_strip() {
        assert_eq!(endpoint_of("https://a.com/x/y?z=1&w=2"), "https://a.com/x/y");
        assert_eq!(endpoint_of("https://a.com/x#f"), "https://a.com/x");
        assert_eq!(endpoint_of("https://a.com"), "https://a.com");
        assert_eq!(endpoint_of("https://a.com/?q"), "https://a.com/");
    }
}
