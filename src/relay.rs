use crate::arch;
use crate::capture::Tab;
use crate::ctx::Ctx;
use crate::events::{FxEvent, K_META};
use base64::Engine;
use bytes::{BufMut, Bytes, BytesMut};
use chromiumoxide::cdp::js_protocol::runtime::EvaluateParams;
use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

pub struct RelayOut {
    pub executed: u64,
    pub errors: u64,
}

fn meta_ev(ctx: &Ctx, d: Bytes) {
    let _ = ctx.tx.send(FxEvent {
        t: now_ms(),
        site: 0,
        tun: 0,
        tab: 0,
        vendor: 0,
        name: 0,
        kind: K_META,
        _pad: 0,
        d,
    });
}

fn relay_line(kind: &str, id: &str, extra: &str) -> Bytes {
    let mut b = BytesMut::with_capacity(160);
    b.put_u8(b'{');
    b.put_slice(b"\"relay\":\"");
    b.put_slice(kind.as_bytes());
    b.put_slice(b"\",\"id\":\"");
    b.put_slice(id.as_bytes());
    b.put_slice(b"\"");
    if !extra.is_empty() {
        b.put_u8(b',');
        b.put_slice(&extra.as_bytes()[1..]);
    }
    b.put_u8(b'}');
    b.freeze()
}

struct Item {
    id: String,
    js: String,
}

fn parse_items(body: &str, api_json: bool) -> Vec<Item> {
    let txt = if api_json {
        let v: Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let c = match v.get("content").and_then(|x| x.as_str()) {
            Some(c) => c.to_owned(),
            None => return Vec::new(),
        };
        match base64::engine::general_purpose::STANDARD.decode(c) {
            Ok(b) => String::from_utf8_lossy(&b).to_string(),
            Err(_) => return Vec::new(),
        }
    } else {
        body.to_owned()
    };
    let v: Value = match serde_json::from_str(txt.trim_start_matches('\u{feff}')) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(arr) = v.get("items").and_then(|x| x.as_array()) {
        for it in arr {
            let id = it.get("id").and_then(|x| x.as_str()).unwrap_or("").to_owned();
            let js = it.get("js").and_then(|x| x.as_str()).unwrap_or("").to_owned();
            if !id.is_empty() && !js.is_empty() {
                out.push(Item { id, js });
            }
        }
    }
    out
}

fn wrap_js(js: &str) -> String {
    let b = base64::engine::general_purpose::STANDARD.encode(js.as_bytes());
    format!(
        "(function(){{var t0=performance.now();try{{var r=eval(atob('{b}'));var ms=performance.now()-t0;try{{var s=String(r);return JSON.stringify({{ok:1,ms:Math.round(ms*10)/10,r:s.slice(0,384)}})}}catch(x){{return JSON.stringify({{ok:1,ms:Math.round(ms*10)/10,r:''}})}}}}catch(x){{return JSON.stringify({{ok:0,ms:Math.round((performance.now()-t0)*10)/10,e:String(x&&x.message||x).slice(0,384)}})}}}})()"
    )
}

async fn eval_tab(page: &chromiumoxide::Page, expr: &str) -> Option<String> {
    let p = EvaluateParams::builder()
        .expression(expr.to_owned())
        .return_by_value(true)
        .build()
        .ok()?;
    let r = tokio::time::timeout(Duration::from_secs(20), page.execute(p)).await.ok()?.ok()?;
    match r.result.result.value {
        Some(serde_json::Value::String(s)) => Some(s),
        _ => None,
    }
}

fn load_processed(path: &PathBuf) -> HashSet<String> {
    let mut s = HashSet::new();
    if let Ok(t) = std::fs::read_to_string(path) {
        for line in t.lines() {
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
                    s.insert(id.to_owned());
                }
            }
        }
    }
    s
}

pub async fn run(ctx: Arc<Ctx>, tabs: Vec<Tab>) -> RelayOut {
    let mut out = RelayOut { executed: 0, errors: 0 };
    let url = match std::env::var("AFEYE_QUEUE_URL") {
        Ok(u) if u.starts_with("http") => u,
        _ => return out,
    };
    let api_json = url.contains("api.github.com");
    let hdr = std::env::var("AFEYE_QUEUE_TOKEN")
        .ok()
        .map(|t| format!("Authorization: Bearer {t}"));
    let every = Duration::from_secs(env_u64("AFEYE_RELAY_POLL", 30).max(5));
    let state_path = ctx.stage.join("relay-state.jsonl");
    let mut processed = load_processed(&state_path);
    let mut dump_path = PathBuf::from(".");
    if let Ok(r) = std::env::var("AF_ROOT") {
        dump_path = PathBuf::from(r);
    }
    dump_path = dump_path.join("dumps").join("relay-state.jsonl");
    let mut dump_processed = load_processed(&dump_path);
    let mut err_n = 0u64;
    meta_ev(
        &ctx,
        relay_line("poll-on", "", &format!(",\"tabs\":{}", tabs.len())),
    );
    loop {
        if ctx.cn.stop.load(Ordering::Acquire) || ctx.cn.dead.load(Ordering::Acquire) {
            break;
        }
        if std::time::Instant::now() > ctx.deadline {
            break;
        }
        let bust = format!("{url}?t={}", now_ms());
        match arch::curl_get(&bust, hdr.as_deref(), 12).await {
            Ok(body) => {
                err_n = 0;
                for it in parse_items(&body, api_json) {
                    if processed.contains(&it.id) || dump_processed.contains(&it.id) {
                        continue;
                    }
                    if ctx.cn.stop.load(Ordering::Acquire) {
                        break;
                    }
                    let expr = wrap_js(&it.js);
                    let mut ok_n = 0u32;
                    let mut max_ms = 0.0f64;
                    let mut last = String::new();
                    for tb in &tabs {
                        if let Some(r) = eval_tab(&tb.page, &expr).await {
                            if let Ok(v) = serde_json::from_str::<Value>(&r) {
                                if v.get("ok").and_then(|x| x.as_i64()) == Some(1) {
                                    ok_n += 1;
                                }
                                if let Some(ms) = v.get("ms").and_then(|x| x.as_f64()) {
                                    if ms > max_ms {
                                        max_ms = ms;
                                    }
                                }
                            }
                            last = r;
                        }
                    }
                    let _ = arch::write_append(
                        &dump_path,
                        &format!("{{\"id\":\"{}\",\"t\":{},\"tabs\":{},\"ok\":{}}}", it.id, now_ms(), tabs.len(), ok_n),
                    );
                    let _ = arch::write_append(
                        &state_path,
                        &format!("{{\"id\":\"{}\",\"t\":{},\"tabs\":{},\"ok\":{}}}", it.id, now_ms(), tabs.len(), ok_n),
                    );
                    processed.insert(it.id.clone());
                    dump_processed.insert(it.id.clone());
                    let prev = if last.is_empty() {
                        String::new()
                    } else {
                        format!(",\"r\":{}", last)
                    };
                    meta_ev(
                        &ctx,
                        relay_line(
                            "exec",
                            &it.id,
                            &format!(",\"ms\":{},\"tabs\":{},\"ok\":{}{}", max_ms, tabs.len(), ok_n, prev),
                        ),
                    );
                    out.executed += 1;
                    if ok_n == 0 && !tabs.is_empty() {
                        out.errors += 1;
                    }
                }
            }
            Err(e) => {
                err_n += 1;
                if err_n == 1 || err_n.is_multiple_of(10) {
                    meta_ev(&ctx, relay_line("poll-err", "", &format!(",\"e\":\"{e}\",\"n\":{}", err_n)));
                }
            }
        }
        let mut waited = 0u64;
        while waited < every.as_secs() {
            if ctx.cn.stop.load(Ordering::Acquire) || ctx.cn.dead.load(Ordering::Acquire) {
                return out;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            waited += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_raw_and_api() {
        let raw = r#"{"items":[{"id":"a1","js":"console.log(1)"},{"id":"","js":"x"},{"js":"y"}]}"#;
        let v = parse_items(raw, false);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id, "a1");
        assert_eq!(v[0].js, "console.log(1)");
        let api = serde_json::json!({"content": base64::engine::general_purpose::STANDARD.encode(raw)});
        let v2 = parse_items(&api.to_string(), true);
        assert_eq!(v2.len(), 1);
        assert!(parse_items("not json", false).is_empty());
        assert!(parse_items("{}", false).is_empty());
    }

    #[test]
    fn wrapper_is_valid_js() {
        let w = wrap_js("var x=1;x+1");
        assert!(w.starts_with("(function(){"));
        assert!(w.contains("atob('"));
        assert!(w.ends_with("})()"));
        assert!(!w.contains("\""));
        std::fs::write(std::env::temp_dir().join("afeye_relay_check.js"), &w).unwrap();
        let o = std::process::Command::new("node")
            .arg("--check")
            .arg(std::env::temp_dir().join("afeye_relay_check.js"))
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
}
