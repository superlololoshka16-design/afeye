use crate::capture::Tab;
use crate::ctx::{char_floor, Cn, Ctx, host_of};
use chromiumoxide::cdp::browser_protocol::input::*;
use chromiumoxide::cdp::browser_protocol::page::ReloadParams;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use std::sync::Arc;
use std::time::Duration;

const CDP: Duration = Duration::from_secs(2);
const CDP_IN: Duration = Duration::from_millis(600);
const DEGRADE: Duration = Duration::from_secs(15);

struct Mv {
    x: f64,
    y: f64,
}

fn bez(p: &[f64; 4], t: f64) -> f64 {
    let u = 1.0 - t;
    u * u * u * p[0] + 3.0 * u * u * t * p[1] + 3.0 * u * t * t * p[2] + t * t * t * p[3]
}

struct Me {
    x: f64,
    y: f64,
    ty: DispatchMouseEventType,
    btn: Option<MouseButton>,
    clicks: i64,
    dy: Option<f64>,
}

async fn mouse(page: &chromiumoxide::Page, m: &Me) -> bool {
    let mut b = DispatchMouseEventParams::builder().x(m.x).y(m.y).r#type(m.ty.clone());
    if let Some(btn) = m.btn.as_ref() {
        b = b.button(btn.clone());
    }
    if m.clicks > 0 {
        b = b.click_count(m.clicks);
    }
    if let Some(d) = m.dy {
        b = b.delta_y(d).delta_x(0.0);
    }
    match b.build() {
        Ok(p) => matches!(tokio::time::timeout(CDP_IN, page.execute(p)).await, Ok(Ok(_))),
        Err(_) => false,
    }
}

async fn key(page: &chromiumoxide::Page, c: char) -> bool {
    let s = c.to_string();
    let kd = DispatchKeyEventParams::builder()
        .r#type(DispatchKeyEventType::KeyDown)
        .key(&s)
        .text(&s)
        .build();
    let ku = DispatchKeyEventParams::builder()
        .r#type(DispatchKeyEventType::KeyUp)
        .key(&s)
        .build();
    if let (Ok(kd), Ok(ku)) = (kd, ku) {
        if !matches!(tokio::time::timeout(CDP_IN, page.execute(kd)).await, Ok(Ok(_))) {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
        matches!(tokio::time::timeout(CDP_IN, page.execute(ku)).await, Ok(Ok(_)))
    } else {
        false
    }
}

async fn enter(page: &chromiumoxide::Page) -> bool {
    let kd = DispatchKeyEventParams::builder()
        .r#type(DispatchKeyEventType::KeyDown)
        .key("Enter")
        .code("Enter")
        .text("\r")
        .windows_virtual_key_code(13)
        .native_virtual_key_code(13)
        .build();
    let ku = DispatchKeyEventParams::builder()
        .r#type(DispatchKeyEventType::KeyUp)
        .key("Enter")
        .code("Enter")
        .windows_virtual_key_code(13)
        .native_virtual_key_code(13)
        .build();
    if let (Ok(kd), Ok(ku)) = (kd, ku) {
        if !matches!(tokio::time::timeout(CDP_IN, page.execute(kd)).await, Ok(Ok(_))) {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(70)).await;
        matches!(tokio::time::timeout(CDP_IN, page.execute(ku)).await, Ok(Ok(_)))
    } else {
        false
    }
}

fn rand_text(rng: &mut SmallRng, n: usize) -> String {
    let mut s = String::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.7) {
            s.push(rng.gen_range(b'0'..=b'9') as char);
        } else {
            s.push(rng.gen_range(b'a'..=b'z') as char);
        }
    }
    s
}

fn input_ev(ctx: &Ctx, t: &Tab, a: &str, n: u64) {
    let mut d = bytes::BytesMut::with_capacity(64);
    bytes::BufMut::put_slice(&mut d, b"{\"a\":\"");
    bytes::BufMut::put_slice(&mut d, a.as_bytes());
    bytes::BufMut::put_slice(&mut d, b"\",\"n\":");
    let mut ib = itoa::Buffer::new();
    bytes::BufMut::put_slice(&mut d, ib.format(n).as_bytes());
    bytes::BufMut::put_u8(&mut d, b'}');
    let _ = ctx.tx.send(crate::events::FxEvent {
        t: now_ms(),
        site: t.site,
        tun: t.tun,
        tab: t.tab,
        vendor: 0,
        name: 0,
        kind: crate::events::K_INPUT,
        _pad: 0,
        d: d.freeze(),
    });
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn poke(ctx: &Ctx, tb: &Tab, ep: &str) {
    let e = ep.replace('\\', "\\\\").replace('\'', "\\'");
    let expr = format!(
        "try{{fetch('{}',{{credentials:'include'}}).catch(function(){{}})}}catch(x){{}}",
        e
    );
    if let Ok(p) = chromiumoxide::cdp::js_protocol::runtime::EvaluateParams::builder()
        .expression(expr)
        .build()
    {
        let _ = tokio::time::timeout(CDP, tb.page.execute(p)).await;
    }
    let _ = Cn::inc(&ctx.cn.poke);
}

pub async fn drive(ctx: Arc<Ctx>, tabs: Vec<Tab>) {
    let seed = ctx.t0ms ^ 0x9E37_79B9_7F4A_7C15;
    let mut rng = SmallRng::seed_from_u64(seed);
    let reload_every = Duration::from_secs(
        std::env::var("AF_RELOAD_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(70u64),
    );
    let mut pos: Vec<Mv> = tabs.iter().map(|_| Mv { x: 640.0, y: 400.0 }).collect();
    let mut cands: Vec<Vec<(f64, f64, String)>> = vec![Vec::new(); tabs.len()];
    let mut last_ref: Vec<std::time::Instant> = tabs.iter().map(|_| std::time::Instant::now()).collect();
    let mut last_poke: Vec<std::time::Instant> = tabs.iter().map(|_| std::time::Instant::now()).collect();
    let mut last_reload: Vec<std::time::Instant> = tabs.iter().map(|_| std::time::Instant::now()).collect();
    let mut bad_until: Vec<Option<std::time::Instant>> = vec![None; tabs.len()];
    loop {
        if ctx.cn.dead.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        if std::time::Instant::now() > ctx.deadline {
            break;
        }
        if tabs.is_empty() {
            break;
        }
        let i = rng.gen_range(0..tabs.len());
        if let Some(t) = bad_until[i] {
            if std::time::Instant::now() < t {
                continue;
            }
            bad_until[i] = None;
        }
        if last_ref[i].elapsed() > Duration::from_secs(12) {
            last_ref[i] = std::time::Instant::now();
            cands[i] = crate::capture::eval_list(&tabs[i].page).await;
        }
        let tb = &tabs[i];
        if reload_every.as_secs() > 0
            && last_reload[i].elapsed()
                > reload_every + Duration::from_secs(rng.gen_range(0..20))
        {
            last_reload[i] = std::time::Instant::now();
            cands[i].clear();
            let _ = tokio::time::timeout(CDP, tb.page.execute(ReloadParams::default())).await;
            input_ev(&ctx, tb, "reload", 1);
            tokio::time::sleep(Duration::from_millis(rng.gen_range(400..900))).await;
            continue;
        }
        let cur = &mut pos[i];
        let pick = if !cands[i].is_empty() && rng.gen_bool(0.75) {
            let c = &cands[i][rng.gen_range(0..cands[i].len())];
            Some((c.0, c.1, c.2.clone()))
        } else {
            None
        };
        let (tx, ty) = match &pick {
            Some(p) => (p.0, p.1),
            None => (rng.gen_range(30.0..1250.0), rng.gen_range(30.0..780.0)),
        };
        let steps = rng.gen_range(10..28);
        let jx = rng.gen_range(-180.0..180.0);
        let jy = rng.gen_range(-160.0..160.0);
        let x0 = cur.x;
        let y0 = cur.y;
        let mut alive = true;
        for s in 1..=steps {
            let t = s as f64 / steps as f64;
            let x = bez(&[x0, (x0 + tx) / 2.0 + jx, (x0 + tx) / 2.0, tx], t);
            let y = bez(&[y0, (y0 + ty) / 2.0 + jy, (y0 + ty) / 2.0, ty], t);
            if !mouse(
                &tb.page,
                &Me {
                    x,
                    y,
                    ty: DispatchMouseEventType::MouseMoved,
                    btn: None,
                    clicks: 0,
                    dy: None,
                },
            )
            .await
            {
                alive = false;
                break;
            }
            tokio::time::sleep(Duration::from_millis(rng.gen_range(8..17))).await;
        }
        cur.x = tx;
        cur.y = ty;
        if !alive {
            bad_until[i] = Some(std::time::Instant::now() + DEGRADE);
            continue;
        }
        let act = rng.gen_range(0..100);
        if act < 30 {
            input_ev(&ctx, tb, "down", 1);
            if mouse(
                &tb.page,
                &Me {
                    x: tx,
                    y: ty,
                    ty: DispatchMouseEventType::MousePressed,
                    btn: Some(MouseButton::Left),
                    clicks: 1,
                    dy: None,
                },
            )
            .await
            {
                tokio::time::sleep(Duration::from_millis(rng.gen_range(40..110))).await;
                alive = mouse(
                    &tb.page,
                    &Me {
                        x: tx,
                        y: ty,
                        ty: DispatchMouseEventType::MouseReleased,
                        btn: Some(MouseButton::Left),
                        clicks: 1,
                        dy: None,
                    },
                )
                .await;
            } else {
                alive = false;
            }
            if alive {
                if let Some(p) = &pick {
                    let tag = p.2.as_str();
                    if (tag == "INPUT" || tag == "TEXTAREA" || tag == "SELECT") && rng.gen_bool(0.7) {
                        tokio::time::sleep(Duration::from_millis(rng.gen_range(150..400))).await;
                        let n = rng.gen_range(3..12);
                        let txt = rand_text(&mut rng, n);
                        for c in txt.chars() {
                            if !key(&tb.page, c).await {
                                alive = false;
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(rng.gen_range(55..170))).await;
                        }
                        if alive {
                            input_ev(&ctx, tb, "type", n as u64);
                            if rng.gen_bool(0.3) {
                                enter(&tb.page).await;
                                input_ev(&ctx, tb, "enter", 1);
                            }
                        }
                    }
                }
            }
        } else if act < 60 {
            let d = rng.gen_range(-700.0..-120.0);
            for _ in 0..rng.gen_range(2..5) {
                if !mouse(
                    &tb.page,
                    &Me {
                        x: tx,
                        y: ty,
                        ty: DispatchMouseEventType::MouseWheel,
                        btn: None,
                        clicks: 0,
                        dy: Some(d / 3.0),
                    },
                )
                .await
                {
                    alive = false;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(rng.gen_range(30..90))).await;
            }
        } else if act < 68 {
            let c: char = rng.gen_range(b'a'..=b'z') as char;
            if !key(&tb.page, c).await {
                alive = false;
            }
        } else if act < 76 && last_poke[i].elapsed() > Duration::from_secs(25) {
            last_poke[i] = std::time::Instant::now();
            let host = ctx.interner.resolve(tb.site);
            let mut pick_ep: Option<(u32, u64)> = None;
            let mut n = 0u32;
            for e in ctx.endpoints.iter() {
                let ep = ctx.interner.resolve(*e.key());
                if host_of(ep) == host {
                    n += 1;
                    if rng.gen_bool(1.0 / n as f64) {
                        pick_ep = Some((*e.key(), *e.value()));
                    }
                }
            }
            if let Some((eid, _)) = pick_ep {
                let ep = ctx.interner.resolve(eid);
                let cut = &ep[..char_floor(ep, 290)];
                poke(&ctx, tb, cut).await;
                input_ev(&ctx, tb, "poke", 1);
            }
        }
        if !alive {
            bad_until[i] = Some(std::time::Instant::now() + DEGRADE);
        }
        tokio::time::sleep(Duration::from_millis(rng.gen_range(300..1600))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bez_bounds() {
        for t in [0.0, 0.25, 0.5, 0.75, 1.0] {
            let v = bez(&[0.0, 50.0, 100.0, 200.0], t);
            assert!((0.0..=200.0).contains(&v));
        }
        assert_eq!(bez(&[1.0, 2.0, 3.0, 4.0], 0.0), 1.0);
        assert_eq!(bez(&[1.0, 2.0, 3.0, 4.0], 1.0), 4.0);
    }

    #[test]
    fn rand_text_shape() {
        let mut r = SmallRng::seed_from_u64(42);
        let s = rand_text(&mut r, 10);
        assert_eq!(s.len(), 10);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
        let d = rand_text(&mut r, 5);
        assert_ne!(s, d);
    }
}
