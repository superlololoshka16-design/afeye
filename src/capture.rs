use crate::arena::fx64;
use crate::ctx::{char_floor, vendor_of_stack, vendor_of_url, Cn, Ctx};
use crate::events::*;
use crate::inject;
use base64::Engine;
use bytes::{BufMut, Bytes};
use chromiumoxide::cdp::browser_protocol::emulation::SetUserAgentOverrideParams;
use chromiumoxide::cdp::browser_protocol::network::*;
use chromiumoxide::cdp::browser_protocol::page::*;
use chromiumoxide::cdp::js_protocol::debugger::*;
use chromiumoxide::cdp::js_protocol::runtime::*;
use chromiumoxide::cdp::IntoEventKind;
use chromiumoxide::Page;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::SystemTime;

pub type Meta = Arc<DashMap<u64, (u8, bool)>>;
/// Execution-context ids that belong to OUR OWN driver (the chromiumoxide
/// utility world `__chromiumoxide_utility_world__`). Anything compiled inside
/// them is our probe, never target content - excluded from the capture.
pub type OwnCtx = Arc<DashMap<i64, ()>>;

// chromiumoxide 0.9 internal markers (src/handler/frame.rs): the const is
// "____chromiumoxide_utility_world___n__" but the observed scriptParsed url is
// "____chromiumoxide_utility_world___evaluation_script__" - match by shape, not
// by exact string, so any driver-side variant stays excluded.
const DRIVER_EVAL_URL_TAIL: &str = "___evaluation_script__";
const DRIVER_WORLD: &str = "__chromiumoxide_utility_world__";

/// Browser-internal pages (net error pages, devtools, chrome://) compile
/// Chromium's own JS - never target content.
fn browser_internal(url: &str) -> bool {
    url.starts_with("chrome-error://")
        || url.starts_with("chrome://")
        || url.starts_with("devtools://")
        || url.starts_with("edge://")
}

#[derive(Clone)]
pub struct Tab {
    pub page: Page,
    pub site: u32,
    pub tun: u32,
    pub tab: u32,
}

#[derive(Clone)]
pub struct Tb {
    pub ctx: Arc<Ctx>,
    pub tun: u32,
    pub site: u32,
    pub tab: u32,
    pub page: Page,
    pub meta: Meta,
    pub own: OwnCtx,
}

impl Tb {
    fn emit(&self, kind: u16, d: Bytes) {
        let _ = self.ctx.tx.send(FxEvent {
            t: now_ms(),
            site: self.site,
            tun: self.tun,
            tab: self.tab,
            vendor: 0,
            name: 0,
            kind,
            _pad: 0,
            d,
        });
        let _ = Cn::inc(&self.ctx.cn.ev);
    }

    fn emit_v(&self, vendor: u32, kind: u16, d: Bytes) {
        let _ = self.ctx.tx.send(FxEvent {
            t: now_ms(),
            site: self.site,
            tun: self.tun,
            tab: self.tab,
            vendor,
            name: 0,
            kind,
            _pad: 0,
            d,
        });
        let _ = Cn::inc(&self.ctx.cn.ev);
    }

    fn file(&self, path: &str, data: Vec<u8>) {
        let nm = self.ctx.interner.intern(path);
        let _ = self.ctx.tx.send(FxEvent {
            t: now_ms(),
            site: self.site,
            tun: self.tun,
            tab: self.tab,
            vendor: 0,
            name: nm,
            kind: K_FILE,
            _pad: 0,
            d: Bytes::from(data),
        });
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn storable(mime: &str, resource: &str) -> Option<u8> {
    let m = mime.to_ascii_lowercase();
    if m.contains("wasm") {
        return Some(E_WASM);
    }
    if m.contains("javascript") || m.contains("ecmascript") || resource == "Script" {
        return Some(E_JS);
    }
    if m.contains("json") || resource == "Xhr" || resource == "Fetch" || resource == "Preflight" {
        return Some(E_JSON);
    }
    if m.contains("html") || m.contains("xhtml") || resource == "Document" {
        return Some(E_HTML);
    }
    if m.contains("css") {
        return Some(E_CSS);
    }
    if m.contains("text/plain") || m.contains("xml") || m.contains("svg") || m.contains("form-urlencoded") {
        return Some(E_TXT);
    }
    None
}

fn sniff(b: &[u8]) -> u8 {
    if b.starts_with(&[0, b'a', b's', b'm']) {
        return E_WASM;
    }
    let t = b
        .iter()
        .take_while(|&&c| c == b' ' || c == b'\n' || c == b'\r' || c == b'\t')
        .count();
    match b.get(t) {
        Some(b'{') | Some(b'[') => E_JSON,
        Some(b'<') => E_HTML,
        _ => E_TXT,
    }
}

fn post_art(ctx: &Ctx, code: u8, data: Vec<u8>) -> Option<([u8; 32], u64)> {
    let n = data.len() as u64;
    if n == 0 || n > 16_777_216 {
        return None;
    }
    if ctx.budget.load(std::sync::atomic::Ordering::Relaxed) + n > ctx.budget_limit() {
        let _ = Cn::inc(&ctx.cn.drop);
        return None;
    }
    let h = blake3::hash(&data);
    let hb = *h.as_bytes();
    let _ = ctx.art.send(Art {
        code,
        hash: hb,
        data: Bytes::from(data),
    });
    ctx.budget.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    let _ = Cn::inc(&ctx.cn.bin);
    Some((hb, n))
}

fn hdrs(j: &mut J, k: &str, h: &Headers) {
    j.key(k);
    match h.inner() {
        serde_json::Value::Object(m) => {
            j.b.put_u8(b'{');
            let mut first = true;
            for (hk, hv) in m {
                if first {
                    first = false;
                } else {
                    j.b.put_u8(b',');
                }
                j.s(hk);
                j.b.put_u8(b':');
                if let serde_json::Value::String(s) = hv {
                    j.s(s);
                } else {
                    let s = hv.to_string();
                    j.s(&s);
                }
            }
            j.b.put_u8(b'}');
        }
        _ => {
            j.b.put_slice(b"{}");
        }
    }
}

pub async fn instrument(tb: Tb, url: &str) {
    // afeye v123: pin the identity BEFORE anything navigates. This kills the
    // HeadlessChrome leak in three places at once - UA header, navigator.userAgent,
    // and every Sec-CH-UA brand - and keeps them consistent with the engine
    // version actually running. Anti-fraud that fingerprints UA-vs-CH
    // consistency sees a coherent stock Linux Chrome.
    {
        use chromiumoxide::cdp::browser_protocol::emulation::{
            UserAgentBrandVersion, UserAgentMetadata,
        };
        let major = tb.ctx.ua_major.clone();
        let full = tb.ctx.ua_full.clone();
        let brands = vec![
            UserAgentBrandVersion::new("Chromium", major.clone()),
            UserAgentBrandVersion::new("Google Chrome", major.clone()),
            UserAgentBrandVersion::new("Not A;Brand", "99"),
        ];
        let fulls = vec![
            UserAgentBrandVersion::new("Chromium", full.clone()),
            UserAgentBrandVersion::new("Google Chrome", full.clone()),
            UserAgentBrandVersion::new("Not A;Brand", "99"),
        ];
        if let Ok(md) = UserAgentMetadata::builder()
            .brands(brands)
            .full_version_lists(fulls)
            .platform("Linux")
            .platform_version("6.8.0")
            .architecture("x86")
            .model("")
            .mobile(false)
            .bitness("64")
            .wow64(false)
            .build()
        {
            if let Ok(p) = SetUserAgentOverrideParams::builder()
                .user_agent(tb.ctx.ua.clone())
                .accept_language("en-US,en;q=0.9")
                .platform("Linux x86_64")
                .user_agent_metadata(md)
                .build()
            {
                if let Err(e) = tb.page.execute(p).await {
                    eprintln!("[afeye] ua override: {e}");
                }
            }
        }
    }
    if let Err(e) = tb
        .page
        .execute(AddBindingParams::new(tb.ctx.binding.clone()))
        .await
    {
        eprintln!("[afeye] addbinding: {e}");
    }
    if let Err(e) = tb
        .page
        .execute(AddScriptToEvaluateOnNewDocumentParams::new(inject::source(
            &tb.ctx.binding,
            tb.ctx.gl_spoof,
        )))
        .await
    {
        eprintln!("[afeye] addscript: {e}");
    }
    // afeye v123: listeners attach BEFORE the domains are enabled - otherwise
    // executionContextCreated events replayed by Runtime.enable (which is how
    // pre-existing utility worlds announce themselves) are missed and our own
    // driver scripts leak into the capture again.
    spawn_ev(&tb, on_req).await;
    spawn_ev(&tb, on_resp).await;
    spawn_ev(&tb, on_rhdr).await;
    spawn_ev(&tb, on_qhdr).await;
    spawn_ev(&tb, on_fin).await;
    spawn_ev(&tb, on_fail).await;
    spawn_ev(&tb, on_wsc).await;
    spawn_ev(&tb, on_wsf).await;
    spawn_ev(&tb, on_wsr).await;
    spawn_ev(&tb, on_script).await;
    spawn_ev(&tb, on_pause).await;
    spawn_ev(&tb, on_bind).await;
    spawn_ev(&tb, on_console).await;
    spawn_ev(&tb, on_exc).await;
    spawn_ev(&tb, on_ctxt).await;
    spawn_ev(&tb, on_nav).await;
    spawn_ev(&tb, on_dcl).await;
    spawn_ev(&tb, on_load).await;
    {
        use chromiumoxide::cdp::browser_protocol::network::EnableParams as NEnable;
        use chromiumoxide::cdp::browser_protocol::page::EnableParams as PEnable;
        use chromiumoxide::cdp::browser_protocol::target::SetAutoAttachParams;
        use chromiumoxide::cdp::js_protocol::debugger::EnableParams as DEnable;
        use chromiumoxide::cdp::js_protocol::runtime::EnableParams as REnable;
        if let Ok(p) = SetAutoAttachParams::builder()
            .flatten(true)
            .auto_attach(true)
            .wait_for_debugger_on_start(false)
            .build()
        {
            let _ = tb.page.execute(p).await;
        }
        let _ = tb.page.execute(NEnable::default()).await;
        let _ = tb.page.execute(DEnable::default()).await;
        // afeye v123: `debugger;` traps are the classic anti-debugging hang.
        // With the Debugger agent enabled they would pause the page on every
        // statement; skipping all pauses makes them a no-op while the
        // scriptParsed stream (the executing-source capture) keeps flowing.
        // EventPaused below is the second line of defense.
        let _ = tb.page.execute(SetSkipAllPausesParams::new(true)).await;
        let _ = tb.page.execute(REnable::default()).await;
        let _ = tb.page.execute(PEnable::default()).await;
    }
    match tokio::time::timeout(std::time::Duration::from_secs(60), tb.page.goto(url.to_owned())).await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => eprintln!("[afeye] goto err (kept alive): {e}"),
        Err(_) => eprintln!("[afeye] goto slow (kept alive): {url}"),
    }
}

async fn spawn_ev<E, F>(tb: &Tb, f: F)
where
    E: IntoEventKind + Send + Unpin + 'static,
    F: Fn(&Tb, Arc<E>) + Send + Sync + Clone + 'static,
{
    let tb = tb.clone();
    let mut s = match tb.page.event_listener::<E>().await {
        Ok(s) => s,
        Err(_) => return,
    };
    tokio::spawn(async move {
        use futures::StreamExt;
        while let Some(e) = s.next().await {
            f(&tb, e);
        }
    });
}

fn frame_str(out: &mut String, name: &str, url: &str, ln: i64) {
    if out.len() > 700 {
        return;
    }
    if !out.is_empty() {
        out.push(';');
    }
    if !name.is_empty() {
        out.push_str(&name[..char_floor(name, 48)]);
        out.push('@');
    }
    out.push_str(&url[..char_floor(url, 120)]);
    out.push(':');
    out.push_str(&ln.to_string());
}

fn on_req(tb: &Tb, e: Arc<EventRequestWillBeSent>) {
    let _ = Cn::inc(&tb.ctx.cn.req);
    let vendor = match vendor_of_url(&e.request.url) {
        Some(v) => tb.ctx.interner.intern(v),
        None => 0,
    };
    let mut j = J::new(384);
    j.open();
    j.fkey("rid");
    j.s(e.request_id.as_ref());
    j.key("m");
    j.s(&e.request.method);
    j.key("u");
    j.s(&e.request.url);
    if let Some(ty) = &e.r#type {
        j.key("ty");
        j.s(ty.as_ref());
    }
    j.key("ini");
    j.s(e.initiator.r#type.as_ref());
    if let Some(u) = &e.initiator.url {
        j.key("iniu");
        j.s(u);
    }
    j.key("wt");
    j.f64v(*e.wall_time.inner());
    if let Some(rr) = &e.redirect_response {
        j.key("red");
        j.i64v(rr.status);
    }
    if let Some(st) = &e.initiator.stack {
        let mut s = String::with_capacity(768);
        for fr in st.call_frames.iter().take(10) {
            frame_str(&mut s, &fr.function_name, &fr.url, fr.line_number);
        }
        if let Some(p) = &st.parent {
            for fr in p.call_frames.iter().take(4) {
                frame_str(&mut s, &fr.function_name, &fr.url, fr.line_number);
            }
        }
        if !s.is_empty() {
            j.key("stk");
            j.s(&s);
        }
    }
    hdrs(&mut j, "h", &e.request.headers);
    tb.emit_v(vendor, K_REQ, j.fin());
    if e.request.has_post_data.unwrap_or(false) {
        let tb2 = tb.clone();
        let rid = e.request_id.clone();
        let url = e.request.url[..char_floor(&e.request.url, 300)].to_owned();
        tokio::spawn(async move {
            if let Ok(r) = tb2.page.execute(GetRequestPostDataParams::new(rid.clone())).await {
                let pd: &String = &r.result.post_data;
                if !pd.is_empty() && pd.len() <= 8_388_608 {
                    if let Some((h, n)) = post_art(&tb2.ctx, E_POST, pd.clone().into_bytes()) {
                        let _ = Cn::inc(&tb2.ctx.cn.body);
                        let mut j = J::new(192);
                        j.open();
                        j.fkey("rid");
                        j.s(rid.as_ref());
                        j.key("u");
                        j.s(&url);
                        j.key("a");
                        j.hex(&h);
                        j.key("x");
                        j.s("post");
                        j.key("n");
                        j.u64v(n);
                        tb2.emit(K_BODY, j.fin());
                    }
                }
            }
        });
    }
}

fn on_resp(tb: &Tb, e: Arc<EventResponseReceived>) {
    let _ = Cn::inc(&tb.ctx.cn.resp);
    let r = &e.response;
    let tys = e.r#type.as_ref();
    let code = storable(&r.mime_type, tys);
    let vendor = match vendor_of_url(&r.url) {
        Some(v) => tb.ctx.interner.intern(v),
        None => 0,
    };
    let mut j = J::new(512);
    j.open();
    j.fkey("rid");
    j.s(e.request_id.as_ref());
    j.key("u");
    j.s(&r.url);
    j.key("st");
    j.i64v(r.status);
    if !r.mime_type.is_empty() {
        j.key("ct");
        j.s(&r.mime_type);
    }
    if let Some(p) = &r.protocol {
        j.key("pr");
        j.s(p);
    }
    if let Some(ip) = &r.remote_ip_address {
        j.key("rip");
        j.s(ip);
    }
    if let Some(pt) = r.remote_port {
        j.key("rpt");
        j.i64v(pt);
    }
    if let Some(sec) = &r.security_details {
        j.key("tls");
        j.b.put_u8(b'{');
        j.fkey("v");
        j.s(&sec.protocol);
        j.key("c");
        j.s(&sec.cipher);
        j.key("k");
        j.s(&sec.key_exchange);
        j.key("kg");
        j.s(sec.key_exchange_group.as_deref().unwrap_or(""));
        j.b.put_u8(b'}');
    }
    if let Some(tm) = &r.timing {
        j.key("tm");
        j.b.put_u8(b'{');
        j.fkey("dns");
        j.f64v(tm.dns_end - tm.dns_start);
        j.key("con");
        j.f64v(tm.connect_end - tm.connect_start);
        j.key("ssl");
        j.f64v(tm.ssl_end - tm.ssl_start);
        j.key("snd");
        j.f64v(tm.send_end - tm.send_start);
        j.b.put_u8(b'}');
    }
    j.key("size");
    j.f64v(r.encoded_data_length);
    if r.from_disk_cache.unwrap_or(false) {
        j.key("cache");
        j.bool(true);
    }
    hdrs(&mut j, "h", &r.headers);
    tb.emit_v(vendor, K_RESP, j.fin());
    let xhr = tys == "Xhr" || tys == "Fetch";
    if code.is_some() || xhr {
        tb.meta
            .insert(fx64(e.request_id.as_ref().as_bytes()), (code.unwrap_or(E_BIN), true));
    }
}

fn on_rhdr(tb: &Tb, e: Arc<EventResponseReceivedExtraInfo>) {
    let mut j = J::new(256);
    j.open();
    j.fkey("rid");
    j.s(e.request_id.as_ref());
    j.key("ph");
    j.s("resp_ex");
    j.key("st");
    j.i64v(e.status_code);
    hdrs(&mut j, "h", &e.headers);
    tb.emit(K_HDR, j.fin());
}

fn on_qhdr(tb: &Tb, e: Arc<EventRequestWillBeSentExtraInfo>) {
    let mut j = J::new(256);
    j.open();
    j.fkey("rid");
    j.s(e.request_id.as_ref());
    j.key("ph");
    j.s("req_ex");
    hdrs(&mut j, "h", &e.headers);
    tb.emit(K_HDR, j.fin());
}

fn on_fin(tb: &Tb, e: Arc<EventLoadingFinished>) {
    let code = match tb.meta.get(&fx64(e.request_id.as_ref().as_bytes())) {
        Some(g) => g.value().0,
        None => return,
    };
    let tb2 = tb.clone();
    let rid2 = e.request_id.clone();
    tokio::spawn(async move {
        if let Ok(res) = tb2.page.execute(GetResponseBodyParams::new(rid2.clone())).await {
            let rr = res.result;
            let body: String = rr.body;
            if !body.is_empty() && body.len() <= 16_777_216 {
                let raw: Vec<u8> = if rr.base64_encoded {
                    match base64::engine::general_purpose::STANDARD.decode(body) {
                        Ok(v) => v,
                        Err(_) => return,
                    }
                } else {
                    body.into_bytes()
                };
                let code2 = if code == E_BIN { sniff(&raw) } else { code };
                if let Some((h, n)) = post_art(&tb2.ctx, code2, raw) {
                    let _ = Cn::inc(&tb2.ctx.cn.body);
                    let mut j = J::new(160);
                    j.open();
                    j.fkey("rid");
                    j.s(rid2.as_ref());
                    j.key("a");
                    j.hex(&h);
                    j.key("x");
                    j.s(code2.ext());
                    j.key("n");
                    j.u64v(n);
                    tb2.emit(K_BODY, j.fin());
                }
            }
        } else {
            let _ = Cn::inc(&tb2.ctx.cn.drop);
        }
    });
}

fn on_fail(tb: &Tb, e: Arc<EventLoadingFailed>) {
    let mut j = J::new(160);
    j.open();
    j.fkey("rid");
    j.s(e.request_id.as_ref());
    j.key("err");
    j.s(&e.error_text);
    tb.emit(K_FAIL, j.fin());
}

fn on_wsc(tb: &Tb, e: Arc<EventWebSocketCreated>) {
    let vendor = match vendor_of_url(&e.url) {
        Some(v) => tb.ctx.interner.intern(v),
        None => 0,
    };
    let mut j = J::new(256);
    j.open();
    j.fkey("rid");
    j.s(e.request_id.as_ref());
    j.key("f");
    j.s("created");
    j.key("u");
    j.s(&e.url);
    tb.emit_v(vendor, K_WS, j.fin());
}

fn on_wsf(tb: &Tb, e: Arc<EventWebSocketFrameSent>) {
    ws_line(tb, &e.request_id, "sent", e.response.opcode, &e.response.payload_data);
}

fn on_wsr(tb: &Tb, e: Arc<EventWebSocketFrameReceived>) {
    ws_line(tb, &e.request_id, "recv", e.response.opcode, &e.response.payload_data);
}

fn ws_line(tb: &Tb, rid: &RequestId, dir: &str, op: f64, payload: &str) {
    let mut j = J::new(512);
    j.open();
    j.fkey("rid");
    j.s(rid.as_ref());
    j.key("f");
    j.s(dir);
    j.key("op");
    j.f64v(op);
    let n = payload.len();
    j.key("n");
    j.u64v(n as u64);
    j.key("p");
    j.s(&payload[..char_floor(payload, 2048)]);
    tb.emit(K_WS, j.fin());
}

fn on_script(tb: &Tb, e: Arc<EventScriptParsed>) {
    // our own driver footprint never enters the capture:
    // 1. chromiumoxide evaluates every high-level call through a marker script
    //    in its utility world - the exact "evaluation_script" junk the runs
    //    used to be polluted with (matched by shape, both known spellings);
    // 2. anything compiled inside the utility world context itself;
    // 3. our injected boot script (main world, matched by hash/prefix);
    // 4. Chromium's own internal pages (net-error page scripts etc).
    if e.url.contains("chromiumoxide")
        || e.url.ends_with(DRIVER_EVAL_URL_TAIL)
        || browser_internal(&e.url)
    {
        let _ = Cn::inc(&tb.ctx.cn.ownskip);
        return;
    }
    if tb.own.contains_key(&*e.execution_context_id.inner()) {
        let _ = Cn::inc(&tb.ctx.cn.ownskip);
        return;
    }
    let _ = Cn::inc(&tb.ctx.cn.scripts);
    let vendor = match vendor_of_url(&e.url) {
        Some(v) => tb.ctx.interner.intern(v),
        None => 0,
    };
    let mut j = J::new(256);
    j.open();
    j.fkey("sid");
    j.s(e.script_id.as_ref());
    j.key("u");
    j.s(&e.url);
    j.key("hl");
    match e.length {
        Some(l) => j.i64v(l),
        None => j.b.put_slice(b"null"),
    }
    j.key("ch");
    j.s(&e.hash);
    tb.emit_v(vendor, K_SCRIPT, j.fin());
    if e.url.starts_with("extensions://") {
        return;
    }
    let tb2 = tb.clone();
    let sid = e.script_id.clone();
    let url = e.url[..char_floor(&e.url, 300)].to_owned();
    let inject_hash = tb.ctx.inject_hash;
    let binding = tb.ctx.binding.clone();
    tokio::spawn(async move {
        let src = match tb2.page.execute(GetScriptSourceParams::new(sid.clone())).await {
            Ok(x) => x.result.script_source,
            Err(_) => return,
        };
        // injected boot script: blake3 of the source equals the hash of what
        // we passed to AddScriptToEvaluateOnNewDocument, or the cheap prefix
        // heuristic (marker + per-run binding name) if V8 normalized the tail.
        let own_boot = blake3::hash(src.as_bytes()).as_bytes() == &inject_hash[..]
            || (src.starts_with("(function(){")
                && src.contains(&binding)
                && src.len() < 12_288);
        if own_boot {
            let _ = Cn::inc(&tb2.ctx.cn.ownskip);
            return;
        }
        let wasm = url.starts_with("wasm://");
        let code = if wasm { E_WASM } else { E_JS };
        let raw: Vec<u8> = if wasm {
            match base64::engine::general_purpose::STANDARD.decode(src) {
                Ok(v) => v,
                Err(_) => return,
            }
        } else {
            src.into_bytes()
        };
        if raw.is_empty() {
            return;
        }
        if let Some((h, n)) = post_art(&tb2.ctx, code, raw) {
            let mut j = J::new(200);
            j.open();
            j.fkey("sid");
            j.s(sid.as_ref());
            j.key("u");
            j.s(&url);
            j.key("a");
            j.hex(&h);
            j.key("x");
            j.s(code.ext());
            j.key("n");
            j.u64v(n);
            tb2.emit_v(vendor, K_SRC, j.fin());
        }
    });
}

fn on_bind(tb: &Tb, e: Arc<EventBindingCalled>) {
    if e.name != tb.ctx.binding {
        return;
    }
    let _ = Cn::inc(&tb.ctx.cn.batch);
    let pl = match Arc::try_unwrap(e) {
        Ok(ev) => ev.payload,
        Err(a) => a.payload.clone(),
    };
    let n = char_floor(&pl, 600);
    let vendor = match vendor_of_stack(&pl[..n]) {
        Some(v) => tb.ctx.interner.intern(v),
        None => 0,
    };
    if vendor != 0 {
        tb.emit_v(vendor, K_BATCH, Bytes::from(pl));
    } else {
        tb.emit(K_BATCH, Bytes::from(pl));
    }
}

fn on_console(tb: &Tb, e: Arc<EventConsoleApiCalled>) {
    let mut j = J::new(512);
    j.open();
    j.fkey("ty");
    j.s(e.r#type.as_ref());
    j.key("args");
    j.b.put_u8(b'[');
    let mut first = true;
    for a in &e.args {
        if !first {
            j.b.put_u8(b',');
        }
        first = false;
        let mut s = a.description.clone().unwrap_or_default();
        if s.is_empty() {
            if let Some(v) = &a.value {
                s = v.to_string();
            }
        }
        s.truncate(512);
        j.s(&s);
    }
    j.b.put_u8(b']');
    j.key("ctx");
    j.i64v(*e.execution_context_id.inner());
    tb.emit(K_CONSOLE, j.fin());
}

fn on_exc(tb: &Tb, e: Arc<EventExceptionThrown>) {
    let x = &e.exception_details;
    let mut j = J::new(512);
    j.open();
    j.fkey("t");
    j.s(&x.text);
    if let Some(u) = &x.url {
        j.key("u");
        j.s(u);
    }
    j.key("ln");
    j.i64v(x.line_number);
    j.key("c");
    j.i64v(x.column_number);
    if let Some(st) = &x.stack_trace {
        let mut s = String::new();
        for fr in st.call_frames.iter().take(12) {
            s.push_str(&fr.function_name);
            s.push('@');
            s.push_str(&fr.url);
            s.push('\n');
        }
        j.key("st");
        j.s(&s);
    }
    tb.emit(K_EXC, j.fin());
}

fn on_ctxt(tb: &Tb, e: Arc<EventExecutionContextCreated>) {
    let c = &e.context;
    if c.name.contains(DRIVER_WORLD) {
        // our utility world - remember the id so every script compiled inside
        // it can be excluded from the capture
        tb.own.insert(*c.id.inner(), ());
    }
    let mut j = J::new(192);
    j.open();
    j.fkey("id");
    j.i64v(*c.id.inner());
    j.key("o");
    j.s(&c.origin);
    j.key("n");
    j.s(&c.name);
    tb.emit(K_CTX, j.fin());
}

/// `debugger;` statements with the Debugger agent on pause the page. We resume
/// instantly; SetSkipAllPauses makes this a fallback, but a resume storm is
/// still better than a hung tab while the anti-fraud keeps executing.
fn on_pause(tb: &Tb, _e: Arc<EventPaused>) {
    let _ = Cn::inc(&tb.ctx.cn.pauses);
    let tb2 = tb.clone();
    tokio::spawn(async move {
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(900),
            tb2.page.execute(ResumeParams::default()),
        )
        .await;
    });
}

fn on_nav(tb: &Tb, e: Arc<EventFrameNavigated>) {
    let f = &e.frame;
    let mut j = J::new(256);
    j.open();
    j.fkey("fid");
    j.s(f.id.as_ref());
    j.key("u");
    j.s(&f.url);
    if let Some(n) = &f.name {
        if !n.is_empty() {
            j.key("n");
            j.s(n);
        }
    }
    tb.emit(K_NAV, j.fin());
}

fn on_dcl(tb: &Tb, _e: Arc<EventDomContentEventFired>) {
    let mut j = J::new(64);
    j.open();
    j.fkey("ph");
    j.s("dcl");
    tb.emit(K_LIFE, j.fin());
}

fn on_load(tb: &Tb, _e: Arc<EventLoadEventFired>) {
    let mut j = J::new(64);
    j.open();
    j.fkey("ph");
    j.s("load");
    tb.emit(K_LIFE, j.fin());
}

async fn eval_str(page: &Page, expr: &str) -> Option<String> {
    let r = page
        .execute(
            EvaluateParams::builder()
                .expression(expr)
                .return_by_value(true)
                .build()
                .ok()?,
        )
        .await
        .ok()?;
    match r.result.result.value {
        Some(serde_json::Value::String(s)) => Some(s),
        _ => None,
    }
}

pub async fn eval_list(page: &Page) -> Vec<(f64, f64, String)> {
    let expr = "(function(){try{var o=[],e=document.querySelectorAll('button:not([type=submit]),a[href],[role=button],[onclick],input:not([type=submit]):not([type=hidden]):not([type=checkbox]):not([type=radio]),select,textarea,[tabindex]:not([tabindex=-1])'),v=window.innerWidth||1280,h=window.innerHeight||800;for(var i=0;i<e.length&&o.length<40;i++){var r=e[i].getBoundingClientRect();if(r.width>4&&r.height>4&&r.bottom>0&&r.top<h&&r.right>0&&r.left<v){var s=document.defaultView.getComputedStyle(e[i]);if(s.visibility!=='hidden'&&s.display!=='none'&&!e[i].disabled){o.push([Math.round(r.x+r.width/2),Math.round(r.y+r.height/2),e[i].tagName])}}}return JSON.stringify(o)}catch(x){return '[]'}})()";
    match tokio::time::timeout(std::time::Duration::from_secs(3), eval_str(page, expr)).await {
        Ok(Some(s)) => serde_json::from_str(&s).unwrap_or_default(),
        _ => Vec::new(),
    }
}

pub async fn finalize(tb: &Tb) {
    let site_n = tb.ctx.interner.resolve(tb.site);
    let tun_n = tb.ctx.interner.resolve(tb.tun);
    let t_short = std::time::Duration::from_secs(5);
    if let Ok(Some(html)) = tokio::time::timeout(
        t_short,
        eval_str(
            &tb.page,
            "(function(){try{return document.documentElement.outerHTML}catch(x){return ''}})()",
        ),
    )
    .await
    {
        tb.file(
            &format!("sites/{}/tunnels/{}/tabs/{}.final.html", site_n, tun_n, tb.tab),
            html.into_bytes(),
        );
    }
    let p = CaptureScreenshotParams::builder()
        .format(CaptureScreenshotFormat::Png)
        .build();
    if let Ok(Ok(r)) = tokio::time::timeout(t_short, tb.page.execute(p)).await {
        if let Ok(png) = base64::engine::general_purpose::STANDARD.decode(r.result.data) {
            tb.file(
                &format!("sites/{}/tunnels/{}/tabs/{}.shot.png", site_n, tun_n, tb.tab),
                png,
            );
        }
    }
    if let Ok(Ok(cookies)) = tokio::time::timeout(t_short, tb.page.get_cookies()).await {
        let mut buf = Vec::with_capacity(4096);
        if serde_json::to_writer_pretty(&mut buf, &cookies).is_ok() {
            tb.file(&format!("sites/{}/tunnels/{}/cookies.json", site_n, tun_n), buf);
        }
    }
    if let Ok(Some(st)) = tokio::time::timeout(
        t_short,
        eval_str(
            &tb.page,
            "(function(){try{return JSON.stringify([location.href,Array.from(Object.entries(localStorage)),Array.from(Object.entries(sessionStorage))])}catch(x){return '[]'}})()",
        ),
    )
    .await
    {
        tb.file(
            &format!("sites/{}/tunnels/{}/tabs/{}.storage.json", site_n, tun_n, tb.tab),
            st.into_bytes(),
        );
    }
}
