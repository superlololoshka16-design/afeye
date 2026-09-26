use bytes::{BufMut, Bytes, BytesMut};

pub const K_REQ: u16 = 1;
pub const K_RESP: u16 = 2;
pub const K_BODY: u16 = 3;
pub const K_FAIL: u16 = 4;
pub const K_HDR: u16 = 5;
pub const K_WS: u16 = 6;
pub const K_SCRIPT: u16 = 7;
pub const K_SRC: u16 = 8;
pub const K_BATCH: u16 = 9;
pub const K_INPUT: u16 = 10;
pub const K_CONSOLE: u16 = 11;
pub const K_EXC: u16 = 12;
pub const K_CTX: u16 = 13;
pub const K_NAV: u16 = 14;
pub const K_LIFE: u16 = 15;
pub const K_FILE: u16 = 16;
pub const K_META: u16 = 17;

pub const KIND_NAMES: [(&str, u16); 17] = [
    ("net.request", K_REQ),
    ("net.response", K_RESP),
    ("net.body", K_BODY),
    ("net.fail", K_FAIL),
    ("net.headers", K_HDR),
    ("net.ws", K_WS),
    ("js.script", K_SCRIPT),
    ("js.source", K_SRC),
    ("js.batch", K_BATCH),
    ("input", K_INPUT),
    ("console", K_CONSOLE),
    ("exception", K_EXC),
    ("execcontext", K_CTX),
    ("navigation", K_NAV),
    ("lifecycle", K_LIFE),
    ("file", K_FILE),
    ("meta", K_META),
];

pub const E_JS: u8 = 0;
pub const E_WASM: u8 = 1;
pub const E_JSON: u8 = 2;
pub const E_HTML: u8 = 3;
pub const E_CSS: u8 = 4;
pub const E_TXT: u8 = 5;
pub const E_BIN: u8 = 6;
pub const E_PNG: u8 = 7;
pub const E_POST: u8 = 8;
pub const E_JPG: u8 = 9;
pub const E_GIF: u8 = 10;
pub const E_WEBP: u8 = 11;
pub const E_BMP: u8 = 12;
pub const E_ICO: u8 = 13;

pub const EXT: [&str; 14] = [
    "js", "wasm", "json", "html", "css", "txt", "bin", "png", "post", "jpg",
    "gif", "webp", "bmp", "ico",
];

#[repr(C, align(64))]
pub struct FxEvent {
    pub t: u64,
    pub site: u32,
    pub tun: u32,
    pub tab: u32,
    pub vendor: u32,
    pub name: u32,
    pub kind: u16,
    pub _pad: u16,
    pub d: Bytes,
}

pub struct Art {
    pub code: u8,
    pub hash: [u8; 32],
    pub data: Bytes,
}

pub struct J {
    pub b: BytesMut,
}

impl J {
    pub fn new(cap: usize) -> Self {
        J {
            b: BytesMut::with_capacity(cap),
        }
    }

    pub fn open(&mut self) {
        self.b.put_u8(b'{');
    }

    pub fn fkey(&mut self, k: &str) {
        self.b.put_u8(b'"');
        self.b.put_slice(k.as_bytes());
        self.b.put_slice(b"\":");
    }

    pub fn key(&mut self, k: &str) {
        self.b.put_u8(b',');
        self.fkey(k);
    }

    pub fn u64v(&mut self, v: u64) {
        let mut buf = itoa::Buffer::new();
        self.b.put_slice(buf.format(v).as_bytes());
    }

    pub fn i64v(&mut self, v: i64) {
        let mut buf = itoa::Buffer::new();
        self.b.put_slice(buf.format(v).as_bytes());
    }

    pub fn f64v(&mut self, v: f64) {
        if v.is_finite() {
            let mut buf = ryu::Buffer::new();
            self.b.put_slice(buf.format(v).as_bytes());
        } else {
            self.b.put_slice(b"null");
        }
    }

    pub fn bool(&mut self, v: bool) {
        self.b.put_slice(if v { b"true" } else { b"false" });
    }

    pub fn s(&mut self, v: &str) {
        esc(&mut self.b, v);
    }

    pub fn hex(&mut self, h: &[u8; 32]) {
        self.b.put_u8(b'"');
        hex32(&mut self.b, h);
        self.b.put_u8(b'"');
    }

    pub fn fin(mut self) -> Bytes {
        self.b.put_u8(b'}');
        self.b.freeze()
    }
}

pub trait ExtCode {
    fn ext(&self) -> &'static str;
}

impl ExtCode for u8 {
    fn ext(&self) -> &'static str {
        EXT[(*self as usize).min(EXT.len() - 1)]
    }
}

pub fn esc_json<W: std::io::Write>(w: &mut W, s: &str) -> std::io::Result<()> {
    let mut buf = bytes::BytesMut::with_capacity(s.len() + 2);
    esc(&mut buf, s);
    w.write_all(&buf)
}

pub fn esc(b: &mut BytesMut, s: &str) {
    b.put_u8(b'"');
    let src = s.as_bytes();
    if !src.iter().any(|&c| c < 0x20 || c == b'"' || c == b'\\') {
        b.put_slice(src);
        b.put_u8(b'"');
        return;
    }
    static H: &[u8; 16] = b"0123456789abcdef";
    for &c in src {
        match c {
            b'"' => b.put_slice(b"\\\""),
            b'\\' => b.put_slice(b"\\\\"),
            b'\n' => b.put_slice(b"\\n"),
            b'\r' => b.put_slice(b"\\r"),
            b'\t' => b.put_slice(b"\\t"),
            0x00..=0x1f => {
                b.put_slice(b"\\u00");
                b.put_u8(H[(c >> 4) as usize]);
                b.put_u8(H[(c & 15) as usize]);
            }
            _ => b.put_u8(c),
        }
    }
    b.put_u8(b'"');
}

pub fn hex32(dst: &mut BytesMut, h: &[u8; 32]) {
    static H: &[u8; 16] = b"0123456789abcdef";
    for &c in h {
        dst.put_u8(H[(c >> 4) as usize]);
        dst.put_u8(H[(c & 15) as usize]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esc_roundtrip() {
        let cases = ["plain", "with \"quote\"", "back\\slash", "nl\nhere", "\u{1}\u{1f}", "кириллица ✓"];
        for c in cases {
            let mut b = BytesMut::new();
            esc(&mut b, c);
            let s = String::from_utf8(b.to_vec()).unwrap();
            let back: String = serde_json::from_str(&s).unwrap();
            assert_eq!(back, c);
        }
    }

    #[test]
    fn j_line_valid() {
        let mut j = J::new(64);
        j.open();
        j.fkey("a");
        j.u64v(42);
        j.key("b");
        j.f64v(-1.5e10);
        j.key("c");
        j.s("x\"y");
        let d = j.fin();
        let s = String::from_utf8(d.to_vec()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["a"], 42);
        assert_eq!(v["c"], "x\"y");
    }

    #[test]
    fn ext_map() {
        assert_eq!(E_JS.ext(), "js");
        assert_eq!(E_WASM.ext(), "wasm");
        assert_eq!(E_POST.ext(), "post");
        assert_eq!(E_PNG.ext(), "png");
        assert_eq!(E_JPG.ext(), "jpg");
        assert_eq!(E_WEBP.ext(), "webp");
        assert_eq!(E_ICO.ext(), "ico");
    }
}
