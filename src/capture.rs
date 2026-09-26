use crate::arena::fx64;
use crate::ctx::{char_floor, vendor_of_url, Cn, Ctx};
use crate::events::*;
use base64::Engine;
use bytes::{BufMut, Bytes};
use chromiumoxide::cdp::browser_protocol::dom::{GetDocumentParams, GetOuterHtmlParams};
use chromiumoxide::cdp::browser_protocol::dom_storage::{GetDomStorageItemsParams, StorageId};
use chromiumoxide::cdp::browser_protocol::network::*;
use chromiumoxide::cdp::browser_protocol::page::*;
use chromiumoxide::cdp::js_protocol::runtime::*;
use chromiumoxide::cdp::IntoEventKind;
use chromiumoxide::Page;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::SystemTime;

pub type Meta = Arc<DashMap<u64, (u8, bool)>>;

#[derive(Clone)]
pub struct Tb {
    pub ctx: Arc<Ctx>,
    pub tun: u32,
    pub site: u32,
    pub tab: u32,
    pub page: Page,
    pub meta: Meta,
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
    // images: the crawler records every rendered/loaded image byte-for-byte
    // and its hash. mime image/* or CDP resource type "Image" -> stored as
    // E_BIN; on_fin's sniff() resolves the real format from magic bytes.
    if m.starts_with("image/")
        || m.contains("icon")
        || resource == "Image"
        || resource == "Media"
        || resource == "Font"
    {
        return Some(E_BIN);
    }
    None
}

fn sniff(b: &[u8]) -> u8 {
    if b.starts_with(&[0, b'a', b's', b'm']) {
        return E_WASM;
    }
    if b.starts_with(&[0x89, b'P', b'N', b'G']) {
        return E_PNG;
    }
    if b.starts_with(&[0xff, 0xd8, 0xff]) {
        return E_JPG;
    }
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return E_GIF;
    }
    if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        return E_WEBP;
    }
    if b.starts_with(b"BM") {
        return E_BMP;
    }
    if b.starts_with(&[0, 0, 1, 0]) {
        return E_ICO;
    }
    if b.starts_with(&[0x77, 0x4f, 0x46]) || b.starts_with(&[0x4f, 0x54, 0x54, 0x4f]) {
        return E_BIN;
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

fn is_media(code: u8) -> bool {
    // images + fonts + unknown binary draw from the separate media budget so
    // a banner-heavy page can never starve the crown jewels (JS / POST
    // bodies carrying tokens / JSON / WASM). critical = JS, WASM, JSON,
    // HTML, CSS, TXT, POST.
    matches!(code, E_BIN | E_PNG | E_JPG | E_GIF | E_WEBP | E_BMP | E_ICO)
}

fn post_art(ctx: &Ctx, code: u8, data: Vec<u8>) -> Option<([u8; 32], u64)> {
    let n = data.len() as u64;
    if n == 0 || n > 16_777_216 {
        return None;
    }
    let (counter, limit) = if is_media(code) {
        (&ctx.img_budget, ctx.img_budget_limit())
    } else {
        (&ctx.budget, ctx.budget_limit())
    };
    if counter.load(std::sync::atomic::Ordering::Relaxed) + n > limit {
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
    counter.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
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
    {
        use chromiumoxide::cdp::browser_protocol::network::EnableParams as NEnable;
        use chromiumoxide::cdp::browser_protocol::page::EnableParams as PEnable;
        use chromiumoxide::cdp::browser_protocol::target::SetAutoAttachParams;
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
        let _ = tb.page.execute(REnable::default()).await;
        let _ = tb.page.execute(PEnable::default()).await;
    }
    spawn_ev(&tb, on_req).await;
    spawn_ev(&tb, on_resp).await;
    spawn_ev(&tb, on_fin).await;
    spawn_ev(&tb, on_fail).await;
    spawn_ev(&tb, on_console).await;
    spawn_ev(&tb, on_exc).await;
    spawn_ev(&tb, on_ctxt).await;
    spawn_ev(&tb, on_nav).await;
    spawn_ev(&tb, on_dcl).await;
    spawn_ev(&tb, on_load).await;
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

fn on_fin(tb: &Tb, e: Arc<EventLoadingFinished>) {
    // remove (not get): the meta entry is single-use, consumed here so the
    // per-tab DashMap does not grow unbounded over a long crawl.
    let code = match tb.meta.remove(&fx64(e.request_id.as_ref().as_bytes())) {
        Some((_, (c, _))) => c,
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
    // A failed request never fires loadingFinished, so its meta entry (set in
    // on_resp) would leak forever. Remove it here - the only job of this
    // listener now; the K_FAIL timeline emission was dropped on purpose.
    tb.meta.remove(&fx64(e.request_id.as_ref().as_bytes()));
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
        let n = char_floor(&s, 512);
        s.truncate(n);
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

pub async fn finalize(tb: &Tb) {
    let site_n = tb.ctx.interner.resolve(tb.site);
    let tun_n = tb.ctx.interner.resolve(tb.tun);
    let t_short = std::time::Duration::from_secs(5);
    let doc = GetDocumentParams::builder().depth(-1).pierce(false).build();
    let root_id = match tokio::time::timeout(t_short, tb.page.execute(doc)).await {
        Ok(Ok(r)) => Some(r.result.root.node_id),
        _ => None,
    };
    if let Some(nid) = root_id {
        let oh = GetOuterHtmlParams::builder().node_id(nid).build();
        if let Ok(Ok(r)) = tokio::time::timeout(t_short, tb.page.execute(oh)).await {
            let html = r.result.outer_html;
            if !html.is_empty() {
                tb.file(
                    &format!("sites/{}/tunnels/{}/tabs/{}.final.html", site_n, tun_n, tb.tab),
                    html.into_bytes(),
                );
            }
        }
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
            tb.file(
                &format!("sites/{}/tunnels/{}/cookies.json", site_n, tun_n),
                buf,
            );
        }
    }
    let origin = match tokio::time::timeout(t_short, tb.page.url()).await {
        Ok(Ok(Some(u))) => u,
        _ => return,
    };
    let scheme_end = origin.find("://").map(|i| i + 3).unwrap_or(0);
    let security_origin = origin[scheme_end..]
        .find('/')
        .map(|i| &origin[..scheme_end + i])
        .unwrap_or(&origin[..]);
    let mut store = serde_json::Map::new();
    for (name, local) in [("localStorage", true), ("sessionStorage", false)] {
        let sid = StorageId::builder()
            .security_origin(security_origin.to_owned())
            .is_local_storage(local)
            .build();
        let sid = match sid {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Ok(Ok(r)) =
            tokio::time::timeout(t_short, tb.page.execute(GetDomStorageItemsParams::new(sid))).await
        {
            let mut items = serde_json::Map::new();
            for it in &r.result.entries {
                let v = it.inner();
                for kv in v.chunks(2) {
                    if kv.len() == 2 {
                        items.insert(kv[0].clone(), serde_json::Value::String(kv[1].clone()));
                    }
                }
            }
            store.insert(name.to_owned(), serde_json::Value::Object(items));
        }
    }
    if !store.is_empty() {
        let mut doc = serde_json::Map::new();
        doc.insert("url".into(), serde_json::Value::String(origin));
        doc.insert("storage".into(), serde_json::Value::Object(store));
        if let Ok(b) = serde_json::to_vec_pretty(&doc) {
            tb.file(
                &format!("sites/{}/tunnels/{}/tabs/{}.storage.json", site_n, tun_n, tb.tab),
                b,
            );
        }
    }
}
