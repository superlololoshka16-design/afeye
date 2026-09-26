use crate::arena::Interner;
use crate::ctx::{endpoint_of, vendor_of_url, Cn, Ctx};
use crate::events::{Art, ExtCode, FxEvent, K_BATCH, K_FILE, K_META, KIND_NAMES};
use bumpalo::Bump;
use bumpalo::collections::Vec as BVec;
use crossbeam_channel::Receiver;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;

struct Sink {
    w: BufWriter<File>,
    n: u64,
}

impl Sink {
    fn open(p: &Path) -> std::io::Result<Sink> {
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        let f = OpenOptions::new().create(true).append(true).open(p)?;
        Ok(Sink {
            w: BufWriter::with_capacity(1 << 17, f),
            n: 0,
        })
    }

    fn line(&mut self, b: &[u8]) {
        let _ = self.w.write_all(b);
        let _ = self.w.write_all(b"\n");
        self.n += 1;
        if self.n.is_multiple_of(256) {
            let _ = self.w.flush();
        }
    }
}

struct Agg {
    n: f64,
    ms: f64,
    mx: f64,
}

#[derive(Clone, Copy)]
enum Pm {
    Cnt,
    Sum,
    Max,
}

pub struct Tok {
    pub tag: u8,
    pub a: usize,
    pub b: usize,
}

fn skip_ws(s: &[u8], i: &mut usize) -> bool {
    while *i < s.len() && (s[*i] == b' ' || s[*i] == b'\t' || s[*i] == b'\n' || s[*i] == b'\r') {
        *i += 1;
    }
    *i < s.len()
}

fn scan_val(s: &[u8], i: &mut usize) -> Option<Tok> {
    let a = *i;
    match *s.get(*i)? {
        b'"' => {
            *i += 1;
            while *i < s.len() {
                if s[*i] == b'\\' {
                    *i += 2;
                    continue;
                }
                if s[*i] == b'"' {
                    *i += 1;
                    return Some(Tok { tag: 0, a, b: *i });
                }
                *i += 1;
            }
            None
        }
        b'-' | b'0'..=b'9' => {
            while *i < s.len() && matches!(s[*i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                *i += 1;
            }
            Some(Tok { tag: 1, a, b: *i })
        }
        b'[' | b'{' => {
            let (open, close, tag) = if s[*i] == b'[' {
                (b'[', b']', 2u8)
            } else {
                (b'{', b'}', 3u8)
            };
            let mut d = 0usize;
            while *i < s.len() {
                let c = s[*i];
                if c == b'"' {
                    *i += 1;
                    while *i < s.len() {
                        if s[*i] == b'\\' {
                            *i += 2;
                            continue;
                        }
                        if s[*i] == b'"' {
                            break;
                        }
                        *i += 1;
                    }
                } else if c == open {
                    d += 1;
                } else if c == close {
                    d -= 1;
                    if d == 0 {
                        *i += 1;
                        return Some(Tok { tag, a, b: *i });
                    }
                }
                *i += 1;
            }
            None
        }
        _ => {
            while *i < s.len() && s[*i] != b',' && s[*i] != b']' && s[*i] != b'}' {
                *i += 1;
            }
            if *i == a {
                return None;
            }
            Some(Tok { tag: 4, a, b: *i })
        }
    }
}

fn scan_arr<'a>(s: &'a [u8], bump: &'a Bump) -> Option<BVec<'a, Tok>> {
    let mut i = 0usize;
    if !skip_ws(s, &mut i) || s[i] != b'[' {
        return None;
    }
    i += 1;
    let mut out = BVec::new_in(bump);
    loop {
        if !skip_ws(s, &mut i) {
            return None;
        }
        if s[i] == b']' {
            break;
        }
        out.push(scan_val(s, &mut i)?);
        if !skip_ws(s, &mut i) {
            return None;
        }
        if s[i] == b',' {
            i += 1;
            if !skip_ws(s, &mut i) {
                return None;
            }
            if s[i] == b']' {
                return None;
            }
        } else if s[i] == b']' {
            break;
        } else {
            return None;
        }
    }
    Some(out)
}

fn unq(s: &[u8]) -> &str {
    if s.len() < 2 {
        return "";
    }
    simdutf8::basic::from_utf8(&s[1..s.len() - 1]).unwrap_or("")
}

struct Wc<'a> {
    ctx: &'a Arc<Ctx>,
    tl: Vec<Sink>,
    tix: HashMap<(u32, u32), usize>,
    vd: Vec<Sink>,
    vix: HashMap<(u32, u32), usize>,
    dig: HashMap<u32, Agg>,
    meta: Option<Sink>,
}

impl<'a> Wc<'a> {
    fn ensure_tun(&mut self, ev: &FxEvent) -> Option<usize> {
        let key = (ev.tun, ev.site);
        if let Some(n) = self.tix.get(&key) {
            return Some(*n);
        }
        let sn = self.ctx.interner.resolve(ev.site);
        let tn = self.ctx.interner.resolve(ev.tun);
        let p = self
            .ctx
            .stage
            .join("sites")
            .join(sn)
            .join("tunnels")
            .join(tn)
            .join(&self.ctx.slot)
            .join("timeline.jsonl");
        match Sink::open(&p) {
            Ok(s) => {
                let n = self.tl.len();
                self.tl.push(s);
                self.tix.insert(key, n);
                Some(n)
            }
            Err(_) => None,
        }
    }

    fn ensure_vd(&mut self, ev: &FxEvent, vendor: u32) -> Option<usize> {
        let key = (ev.site, vendor);
        if let Some(n) = self.vix.get(&key) {
            return Some(*n);
        }
        let sn = self.ctx.interner.resolve(ev.site);
        let vn = self.ctx.interner.resolve(vendor);
        let p = self
            .ctx
            .stage
            .join("sites")
            .join(sn)
            .join("antifraud")
            .join(vn)
            .join("timeline.jsonl");
        match Sink::open(&p) {
            Ok(s) => {
                let n = self.vd.len();
                self.vd.push(s);
                self.vix.insert(key, n);
                Some(n)
            }
            Err(_) => None,
        }
    }

    fn dig_add(&mut self, id: u32, pm: Pm, cv: f64) {
        let e = self.dig.entry(id).or_insert(Agg { n: 0.0, ms: 0.0, mx: 0.0 });
        match pm {
            Pm::Cnt => e.n += cv,
            Pm::Sum => e.ms += cv,
            Pm::Max => {
                if cv > e.mx {
                    e.mx = cv;
                }
            }
        }
    }

    fn flat_pairs(&mut self, vb: &[u8], pm: Pm, bump: &Bump) {
        if let Some(inner) = scan_arr(vb, bump) {
            for c in inner.chunks(2) {
                if c.len() < 2 || c[0].tag != 0 || c[1].tag != 1 {
                    continue;
                }
                let ck = unq(&vb[c[0].a..c[0].b]);
                let cv = simdutf8::basic::from_utf8(&vb[c[1].a..c[1].b])
                    .unwrap_or("")
                    .parse::<f64>()
                    .unwrap_or(0.0);
                let cid = self.ctx.interner.intern(ck);
                self.dig_add(cid, pm, cv);
            }
        }
    }

    fn batch(&mut self, ev: &FxEvent, bump: &mut Bump) {
        let b = &*bump;
        let pl = match std::str::from_utf8(&ev.d) {
            Ok(v) => v,
            Err(_) => {
                let _ = Cn::inc(&self.ctx.cn.drop);
                return;
            }
        };
        let toks = match scan_arr(pl.as_bytes(), b) {
            Some(v) => v,
            None => {
                let _ = Cn::inc(&self.ctx.cn.drop);
                return;
            }
        };
        let tix = self.ensure_tun(ev);
        for tri in toks.chunks(3) {
            if tri.len() < 3 || tri[0].tag != 0 || tri[2].tag != 1 {
                continue;
            }
            let k = unq(&pl.as_bytes()[tri[0].a..tri[0].b]);
            if k.is_empty() {
                continue;
            }
            let vb = &pl.as_bytes()[tri[1].a..tri[1].b];
            if simdutf8::basic::from_utf8(vb).is_err() {
                let _ = Cn::inc(&self.ctx.cn.drop);
                continue;
            }
            let t = match pl[tri[2].a..tri[2].b].parse::<f64>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let kid = self.ctx.interner.intern(k);
            self.dig_add(kid, Pm::Cnt, 1.0);
            let mut vendor = 0u32;
            if k == "_c" {
                self.flat_pairs(vb, Pm::Cnt, b);
            } else if k == "_m" {
                self.flat_pairs(vb, Pm::Sum, b);
            } else if k == "_mm" {
                self.flat_pairs(vb, Pm::Max, b);
            } else if k == "net:send" {
                if let Some(inner) = scan_arr(vb, b) {
                    if let Some(u) = inner.first() {
                        if u.tag == 0 {
                            let url = unq(&vb[u.a..u.b]);
                            let ep = endpoint_of(url);
                            if !ep.is_empty() {
                                let eid = self.ctx.interner.intern(ep);
                                *self.ctx.endpoints.entry(eid).or_insert(0) += 1;
                            }
                            if let Some(v) = vendor_of_url(url) {
                                vendor = self.ctx.interner.intern(v);
                            }
                        }
                    }
                }
            }
            let mut ln = BVec::new_in(b);
            ln.extend_from_slice(b"{\"t\":");
            let mut ib = itoa::Buffer::new();
            ln.extend_from_slice(ib.format(ev.t).as_bytes());
            ln.extend_from_slice(b",\"b\":");
            ln.extend_from_slice(ib.format(ev.tab).as_bytes());
            ln.extend_from_slice(b",\"j\":");
            let mut rb = ryu::Buffer::new();
            ln.extend_from_slice(rb.format(t).as_bytes());
            ln.extend_from_slice(b",\"kk\":");
            ln.extend_from_slice(&pl.as_bytes()[tri[0].a..tri[0].b]);
            ln.extend_from_slice(b",\"v\":");
            ln.extend_from_slice(vb);
            ln.push(b'}');
            if let Some(n) = tix {
                if let Some(s) = self.tl.get_mut(n) {
                    s.line(&ln);
                }
            }
            if vendor != 0 {
                let vix = self.ensure_vd(ev, vendor);
                if let Some(n) = vix {
                    if let Some(s) = self.vd.get_mut(n) {
                        s.line(&ln);
                    }
                }
            }
        }
        drop(toks);
        bump.reset();
    }

    fn handle(&mut self, ev: FxEvent, bump: &mut Bump) {
        if ev.kind == K_FILE {
            let name = self.ctx.interner.resolve(ev.name);
            if name.is_empty() {
                return;
            }
            let p = self.ctx.stage.join(name);
            if let Some(d) = p.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            let _ = std::fs::write(&p, &ev.d);
            return;
        }
        if ev.kind == K_META {
            let mut b2 = bytes::BytesMut::with_capacity(192 + ev.d.len());
            use bytes::BufMut;
            b2.put_slice(b"{\"t\":");
            let mut ib2 = itoa::Buffer::new();
            b2.put_slice(ib2.format(ev.t).as_bytes());
            b2.put_slice(b",\"d\":");
            b2.put_slice(&ev.d);
            b2.put_u8(b'}');
            if let Some(s) = &mut self.meta {
                s.line(&b2);
            }
            return;
        }
        if ev.kind == K_BATCH {
            self.batch(&ev, bump);
            return;
        }
        let b = &*bump;
        let mut ln = BVec::new_in(b);
        ln.extend_from_slice(b"{\"t\":");
        let mut ib = itoa::Buffer::new();
        ln.extend_from_slice(ib.format(ev.t).as_bytes());
        ln.extend_from_slice(b",\"u\":");
        ln.extend_from_slice(ib.format(ev.tun).as_bytes());
        ln.extend_from_slice(b",\"s\":");
        ln.extend_from_slice(ib.format(ev.site).as_bytes());
        ln.extend_from_slice(b",\"b\":");
        ln.extend_from_slice(ib.format(ev.tab).as_bytes());
        if ev.vendor != 0 {
            ln.extend_from_slice(b",\"v\":");
            ln.extend_from_slice(ib.format(ev.vendor).as_bytes());
        }
        ln.extend_from_slice(b",\"k\":");
        ln.extend_from_slice(ib.format(ev.kind).as_bytes());
        ln.extend_from_slice(b",\"d\":");
        ln.extend_from_slice(&ev.d);
        ln.push(b'}');
        if let Some(n) = self.ensure_tun(&ev) {
            if let Some(s) = self.tl.get_mut(n) {
                s.line(&ln);
            }
        }
        if ev.vendor != 0 {
            if let Some(n) = self.ensure_vd(&ev, ev.vendor) {
                if let Some(s) = self.vd.get_mut(n) {
                    s.line(&ln);
                }
            }
        }
        drop(ln);
        bump.reset();
    }
}

pub fn spawn(rx: Receiver<FxEvent>, art: Receiver<Art>, ctx: Arc<Ctx>) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("afeye-writer".into())
        .spawn(move || run(rx, art, ctx))
        .expect("writer thread")
}

fn run(rx: Receiver<FxEvent>, art: Receiver<Art>, ctx: Arc<Ctx>) {
    if let Some(cores) = core_affinity::get_core_ids() {
        if let Some(c) = cores.last() {
            let _ = core_affinity::set_for_current(*c);
        }
    }
    let mut bump = Bump::with_capacity(1 << 21);
    let mut wc = Wc {
        ctx: &ctx,
        tl: Vec::new(),
        tix: HashMap::new(),
        vd: Vec::new(),
        vix: HashMap::new(),
        dig: HashMap::new(),
        meta: Sink::open(&ctx.stage.join("meta.jsonl")).ok(),
    };
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let art_root = ctx.stage.join("artifacts");
    let _ = std::fs::create_dir_all(&art_root);
    let mut art_n = 0u64;
    let mut art_b = 0u64;
    loop {
        crossbeam_channel::select! {
            recv(rx) -> msg => match msg {
                Ok(ev) => wc.handle(ev, &mut bump),
                Err(_) => break,
            },
            recv(art) -> msg => match msg {
                Ok(a) => {
                    if seen.insert(a.hash) {
                        let name = format!("{}.{}", hexs(&a.hash), a.code.ext());
                        let p = art_root.join(name);
                        if std::fs::write(&p, &a.data).is_ok() {
                            art_n += 1;
                            art_b += a.data.len() as u64;
                        } else {
                            seen.remove(&a.hash);
                        }
                    }
                }
                Err(_) => {
                    if ctx.cn.dead.load(Ordering::Acquire) {
                        break;
                    }
                }
            },
            default(std::time::Duration::from_millis(250)) => {
                if ctx.cn.dead.load(Ordering::Acquire) {
                    if rx.try_recv().is_ok() || art.try_recv().is_ok() {
                        continue;
                    }
                    break;
                }
            }
        }
    }
    for s in wc.tl.iter_mut() {
        let _ = s.w.flush();
    }
    for s in wc.vd.iter_mut() {
        let _ = s.w.flush();
    }
    if let Some(s) = wc.meta.as_mut() {
        let _ = s.w.flush();
    }
    ctx.cn.art.store(art_n, Ordering::Release);
    ctx.cn.bout.store(art_b, Ordering::Release);
    let _ = write_lexicon(&ctx.stage.join("lexicon.json"), &ctx.interner);
    let _ = write_digest(&ctx, &wc.dig);
    eprintln!("[afeye] writer flushed");
}

fn hexs(h: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &c in h {
        s.push(char::from_digit((c >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((c & 15) as u32, 16).unwrap());
    }
    s
}

fn write_lexicon(p: &Path, lex: &Interner) -> std::io::Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut w = BufWriter::new(File::create(p)?);
    w.write_all(b"{\"kinds\":{")?;
    for (i, (n, k)) in KIND_NAMES.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        let mut ib = itoa::Buffer::new();
        w.write_all(ib.format(*k).as_bytes())?;
        w.write_all(b":")?;
        crate::events::esc_json(&mut w, n)?;
    }
    w.write_all(b"},\"strings\":{")?;
    for (i, (id, name)) in lex.all().iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        let mut ib = itoa::Buffer::new();
        w.write_all(ib.format(*id).as_bytes())?;
        w.write_all(b":")?;
        crate::events::esc_json(&mut w, name)?;
    }
    w.write_all(b"}}\n")?;
    w.flush()
}

fn write_digest(p: &Arc<Ctx>, dig: &HashMap<u32, Agg>) -> std::io::Result<()> {
    let dp = p.stage.join("digest.json");
    let mut w = BufWriter::new(File::create(dp)?);
    w.write_all(b"{\"counts\":{")?;
    let mut cs: Vec<(&str, &Agg)> = dig
        .iter()
        .filter(|(_, a)| a.n > 0.0)
        .map(|(id, a)| (p.interner.resolve(*id), a))
        .collect();
    cs.sort_by(|x, y| x.0.cmp(y.0));
    for (i, (k, a)) in cs.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        crate::events::esc_json(&mut w, k)?;
        w.write_all(b":")?;
        let mut rb = ryu::Buffer::new();
        w.write_all(rb.format(a.n).as_bytes())?;
    }
    w.write_all(b"},\"ms\":{")?;
    let mut ms: Vec<(&str, &Agg)> = dig
        .iter()
        .filter(|(_, a)| a.ms > 0.0)
        .map(|(id, a)| (p.interner.resolve(*id), a))
        .collect();
    ms.sort_by(|x, y| x.0.cmp(y.0));
    for (i, (k, a)) in ms.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        crate::events::esc_json(&mut w, k)?;
        w.write_all(b":")?;
        let mut rb = ryu::Buffer::new();
        w.write_all(rb.format(a.ms).as_bytes())?;
    }
    w.write_all(b"},\"max\":{")?;
    let mut mx: Vec<(&str, &Agg)> = dig
        .iter()
        .filter(|(_, a)| a.mx > 0.0)
        .map(|(id, a)| (p.interner.resolve(*id), a))
        .collect();
    mx.sort_by(|x, y| x.0.cmp(y.0));
    for (i, (k, a)) in mx.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        crate::events::esc_json(&mut w, k)?;
        w.write_all(b":")?;
        let mut rb = ryu::Buffer::new();
        w.write_all(rb.format(a.mx).as_bytes())?;
    }
    w.write_all(b"},\"endpoints\":[")?;
    let mut eps: Vec<(u32, u64)> = p
        .endpoints
        .iter()
        .map(|e| (*e.key(), *e.value()))
        .collect();
    eps.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
    for (i, (id, n)) in eps.iter().take(64).enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        w.write_all(b"{\"u\":")?;
        crate::events::esc_json(&mut w, p.interner.resolve(*id))?;
        w.write_all(b",\"n\":")?;
        let mut ib = itoa::Buffer::new();
        w.write_all(ib.format(*n).as_bytes())?;
        w.write_all(b"}")?;
    }
    w.write_all(b"]}\n")?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_flat_batch() {
        let b = Bump::new();
        let s = r#"["_boot",["Mozilla/5.0 x","https://a.com/p",12.5,0],3.25,"net:send",["https://api.x.com/t?z=1","GET","a=1",44.5],100.1]"#;
        let t = scan_arr(s.as_bytes(), &b).unwrap();
        assert_eq!(t.len(), 6);
        assert_eq!(t[0].tag, 0);
        assert_eq!(t[1].tag, 2);
        assert_eq!(t[2].tag, 1);
        assert_eq!(unq(&s.as_bytes()[t[0].a..t[0].b]), "_boot");
        assert_eq!(&s[t[2].a..t[2].b], "3.25");
        assert_eq!(unq(&s.as_bytes()[t[3].a..t[3].b]), "net:send");
    }

    #[test]
    fn scan_nested_and_esc() {
        let b = Bump::new();
        let s = r#"["k",{"x":[1,2,{"y":"\"z\""}]},"n",7]"#;
        let t = scan_arr(s.as_bytes(), &b).unwrap();
        assert_eq!(t.len(), 4);
        assert_eq!(t[1].tag, 3);
        assert_eq!(t[2].tag, 0);
        let inner = &s.as_bytes()[t[1].a..t[1].b];
        let it = scan_arr(inner, &b);
        assert!(it.is_none());
        let nt = scan_arr(b"[1,2,3]", &b).unwrap();
        assert_eq!(nt.len(), 3);
    }

    #[test]
    fn scan_garbage_rejected() {
        let b = Bump::new();
        assert!(scan_arr(b"not json", &b).is_none());
        assert!(scan_arr(b"[1,2", &b).is_none());
        assert!(scan_arr(b"[\"a\",]", &b).is_none());
    }

    #[test]
    fn scan_empty_and_literals() {
        let b = Bump::new();
        let t = scan_arr(b"[]", &b).unwrap();
        assert_eq!(t.len(), 0);
        let t2 = scan_arr(b"[null,true,false,0.5]", &b).unwrap();
        assert_eq!(t2.len(), 4);
        assert_eq!(t2[0].tag, 4);
    }
}
