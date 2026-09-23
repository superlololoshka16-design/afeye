use dashmap::DashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const SLAB: usize = 48 << 20;
const ENTS: usize = 1 << 21;

#[repr(C)]
struct Ent {
    off: u32,
    len: u32,
}

#[derive(Default)]
pub struct FxHasher {
    h: u64,
}

impl Hasher for FxHasher {
    fn write(&mut self, b: &[u8]) {
        for &c in b {
            self.h = (self.h.rotate_left(5) ^ c as u64).wrapping_mul(0x517c_c1b7_2722_0a95);
        }
    }
    fn finish(&self) -> u64 {
        self.h
    }
}

pub type FxBuild = BuildHasherDefault<FxHasher>;

pub fn fx64(b: &[u8]) -> u64 {
    let mut h = FxHasher::default();
    h.write(b);
    h.finish()
}

pub struct Interner {
    slab: *mut u8,
    ents: *mut Ent,
    slab_cur: AtomicU64,
    ent_cur: AtomicU32,
    idx: DashMap<u64, Vec<u32>, FxBuild>,
}

unsafe impl Send for Interner {}
unsafe impl Sync for Interner {}

#[cfg(unix)]
fn mmap_anon(len: usize, huge: bool) -> *mut u8 {
    unsafe {
        let mut f = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        if huge {
            f |= libc::MAP_HUGETLB;
        }
        let p = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            f,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            if huge {
                mmap_anon(len, false)
            } else {
                std::ptr::null_mut()
            }
        } else {
            p as *mut u8
        }
    }
}

#[cfg(windows)]
fn mmap_anon(len: usize, huge: bool) -> *mut u8 {
    let _ = huge;
    let mut v: Vec<u8> = Vec::with_capacity(len);
    v.resize(len, 0);
    Box::into_raw(v.into_boxed_slice()) as *mut u8
}


impl Interner {
    pub fn new() -> Interner {
        let slab = mmap_anon(SLAB, true);
        let ents = mmap_anon(ENTS * std::mem::size_of::<Ent>(), false) as *mut Ent;
        assert!(!slab.is_null() && !ents.is_null(), "arena mmap");
        Interner {
            slab,
            ents,
            slab_cur: AtomicU64::new(1),
            ent_cur: AtomicU32::new(1),
            idx: DashMap::default(),
        }
    }

    pub fn intern(&self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }
        let h = fx64(s.as_bytes());
        if let Some(v) = self.idx.get(&h) {
            for &id in v.iter() {
                if self.resolve(id) == s {
                    return id;
                }
            }
        }
        let b = s.as_bytes();
        let cap = b.len() <= 0xffff
            && (self.ent_cur.load(Ordering::Relaxed) as usize) < ENTS
            && (self.slab_cur.load(Ordering::Relaxed) as usize) + b.len() < SLAB;
        if !cap {
            return self
                .idx
                .get(&h)
                .and_then(|v| v.first().copied())
                .unwrap_or(0);
        }
        let off = self.slab_cur.fetch_add(b.len() as u64 + 1, Ordering::AcqRel) as u32;
        unsafe {
            std::ptr::copy_nonoverlapping(b.as_ptr(), self.slab.add(off as usize), b.len());
        }
        let id = self.ent_cur.fetch_add(1, Ordering::AcqRel);
        unsafe {
            *self.ents.add(id as usize) = Ent {
                off,
                len: b.len() as u32,
            };
        }
        let mut e = self.idx.entry(h).or_default();
        for &oid in e.value().iter() {
            if oid != id && self.resolve(oid) == s {
                return oid;
            }
        }
        e.value_mut().push(id);
        id
    }

    pub fn resolve(&self, id: u32) -> &'static str {
        if id == 0 {
            return "";
        }
        unsafe {
            let e = self.ents.add(id as usize).read();
            let sl = std::slice::from_raw_parts(self.slab.add(e.off as usize), e.len as usize);
            simdutf8::basic::from_utf8(sl).unwrap_or("")
        }
    }

    pub fn all(&self) -> Vec<(u32, &'static str)> {
        let n = self.ent_cur.load(Ordering::Relaxed);
        (1..n).map(|i| (i, self.resolve(i))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_dedup() {
        let a = Interner::new();
        let x = a.intern("challenges.cloudflare.com");
        let y = a.intern("challenges.cloudflare.com");
        assert_eq!(x, y);
        assert_ne!(x, a.intern("datadome.co"));
        assert_eq!(a.resolve(x), "challenges.cloudflare.com");
        assert_eq!(a.intern(""), 0);
    }

    #[test]
    fn intern_bytes() {
        let a = Interner::new();
        let s = "POST /api/v1/challenge?x=1 HTTP/1.1";
        let id = a.intern(s);
        assert_eq!(a.resolve(id), s);
        assert!(a.all().iter().any(|(i, _)| *i == id));
    }

    #[test]
    fn intern_threads() {
        let a = std::sync::Arc::new(Interner::new());
        let mut j = Vec::new();
        for t in 0..4u32 {
            let a2 = a.clone();
            j.push(std::thread::spawn(move || {
                let mut last = 0;
                for i in 0..200u32 {
                    last = a2.intern("parallel-key");
                    let _ = a2.intern(&format!("uq-{t}-{i}"));
                }
                last
            }));
        }
        let ids: Vec<u32> = j.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(ids.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn fx_stable() {
        assert_eq!(fx64(b"abc"), fx64(b"abc"));
        assert_ne!(fx64(b"abc"), fx64(b"abd"));
    }
}
