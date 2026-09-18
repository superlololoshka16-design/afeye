use crate::arch;
use crate::classify;
use crate::ctx::Ctx;
use crate::events::{FxEvent, K_META};
use crate::timefmt;
use bytes::{BufMut, Bytes, BytesMut};
use serde_json::Value;
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

pub struct TgOut {
    pub sent: u64,
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

fn tg_line(kind: &str, extra: &str) -> Bytes {
    let mut b = BytesMut::with_capacity(128);
    b.put_u8(b'{');
    b.put_slice(b"\"tg\":\"");
    b.put_slice(kind.as_bytes());
    b.put_slice(b"\"");
    if !extra.is_empty() {
        b.put_u8(b',');
        b.put_slice(&extra.as_bytes()[1..]);
    }
    b.put_u8(b'}');
    b.freeze()
}

fn esc_num(s: &str) -> String {
    s.chars().filter(|c| *c != '"' && *c != '\\' && *c != '\n' && *c != '\r').take(200).collect()
}

async fn send_doc(token: &str, chat: &str, path: &std::path::Path) -> Result<bool, String> {
    let url = format!("https://api.telegram.org/bot{token}/sendDocument");
    let resp = arch::curl_post_file(&url, &[("chat_id", chat)], "document", path).await?;
    let v: Value = match serde_json::from_str(&resp) {
        Ok(v) => v,
        Err(_) => return Err(format!("bad json: {}", esc_num(&resp))),
    };
    if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
        Ok(true)
    } else {
        Err(esc_num(&resp))
    }
}

async fn checkpoint(ctx: &Arc<Ctx>, idx: u64, out: &mut TgOut) {
    let ck_root = PathBuf::from("/tmp/afeye/tg");
    let ck = ck_root.join(format!("ck{idx}"));
    let _ = std::fs::remove_dir_all(&ck);
    if arch::copy_tree(&ctx.stage, &ck).is_err() {
        meta_ev(ctx, tg_line("copy-err", ""));
        out.errors += 1;
        return;
    }
    let cls = classify::run(&ck);
    let in_bytes = arch::dir_bytes(&ck);
    let stem = timefmt::zip_stem(now_ms());
    let target = ck_root.join(format!("{stem}.7z"));
    let vols = if arch::have_7z() {
        match arch::sz_pack(&ck, &target, 49).await {
            Ok(v) => v,
            Err(e) => {
                meta_ev(ctx, tg_line("7z-err", &format!(",\"e\":\"{}\"", esc_num(&e))));
                out.errors += 1;
                let _ = std::fs::remove_dir_all(&ck);
                return;
            }
        }
    } else {
        let zp = ck_root.join(format!("{stem}.zip"));
        match crate::zipper::pack(&ck, &zp) {
            Ok(_) => {
                meta_ev(ctx, tg_line("7z-missing", ""));
                vec![zp]
            }
            Err(e) => {
                meta_ev(ctx, tg_line("zip-err", &format!(",\"e\":\"{}\"", esc_num(&e))));
                out.errors += 1;
                let _ = std::fs::remove_dir_all(&ck);
                return;
            }
        }
    };
    let mut total = 0u64;
    for v in &vols {
        if let Ok(m) = std::fs::metadata(v) {
            total += m.len();
        }
    }
    let token = std::env::var("AFEYE_TG_TOKEN").unwrap_or_default();
    let chat = std::env::var("AFEYE_TG_CHAT").unwrap_or_default();
    let mut ok_n = 0u64;
    for v in &vols {
        match send_doc(&token, &chat, v).await {
            Ok(_) => ok_n += 1,
            Err(e) => {
                meta_ev(ctx, tg_line("send-err", &format!(",\"e\":\"{}\"", esc_num(&e))));
                out.errors += 1;
            }
        }
    }
    meta_ev(
        ctx,
        tg_line(
            "sent",
            &format!(
                ",\"ck\":{},\"vols\":{},\"ok\":{},\"in\":{},\"out\":{},\"af\":{},\"garbage\":{},\"kept\":{}",
                idx, vols.len(), ok_n, in_bytes, total, cls.af, cls.garbage, cls.kept
            ),
        ),
    );
    if ok_n > 0 {
        out.sent += 1;
    }
    for v in &vols {
        let _ = std::fs::remove_file(v);
    }
    let _ = std::fs::remove_dir_all(&ck);
}

pub async fn run(ctx: Arc<Ctx>) -> TgOut {
    let mut out = TgOut { sent: 0, errors: 0 };
    if std::env::var("AFEYE_TG_TOKEN").unwrap_or_default().is_empty()
        || std::env::var("AFEYE_TG_CHAT").unwrap_or_default().is_empty()
    {
        return out;
    }
    let every = Duration::from_secs(env_u64("AFEYE_TG_EVERY", 300).max(5));
    let mut idx = 0u64;
    loop {
        if ctx.cn.stop.load(Ordering::Acquire) || ctx.cn.dead.load(Ordering::Acquire) {
            break;
        }
        if std::time::Instant::now() + Duration::from_secs(20) > ctx.deadline {
            break;
        }
        let mut waited = 0u64;
        while waited < every.as_secs() {
            if ctx.cn.stop.load(Ordering::Acquire) || ctx.cn.dead.load(Ordering::Acquire) {
                return out;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            waited += 1;
        }
        if ctx.cn.stop.load(Ordering::Acquire) || ctx.cn.dead.load(Ordering::Acquire) {
            break;
        }
        if std::time::Instant::now() + Duration::from_secs(20) > ctx.deadline {
            break;
        }
        idx += 1;
        checkpoint(&ctx, idx, &mut out).await;
    }
    out
}
