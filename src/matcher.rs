// afeye low-level value provenance: Aho-Corasick multi-pattern matcher.
//
// Values that an executed bytecode instruction really carried (accumulator /
// register strings from the 0033 trace, constant-pool literals from func-def
// blobs, streamed out of filtered/valuebook.bin) are patterns; sink payloads
// (crypto raw_data, req-body, ws-frame-out, webtransport / RTC / WebGPU
// egress tags) are the text. A pattern occurrence inside a payload is a
// byte-exact fact: this value crossed the C++ boundary here.
//
// One pass over the payload, O(n + m + z). No windows, no strides, no
// hash collisions, no monotone-region skipping, no time windows, no fanout
// caps. A shift of any length still matches, because the match is
// content-positioned, not window-aligned.
//
// Transitions are sorted Vec<(u8,u32)> probed by binary search; output sets
// are per-node self_out plus a single out_link to the nearest output node on
// the fail chain - overlapping matches are reported by walking that chain,
// with no merged/cloned output vectors.

use std::collections::VecDeque;

const NO_OUT: u32 = u32::MAX;

struct Node {
    next: Vec<(u8, u32)>, // sorted by byte
    fail: u32,
    self_out: Vec<u32>, // pattern ids ending exactly at this node
    out_link: u32,      // nearest output node via fail chain, NO_OUT if none
    depth: u32,
}

pub struct AhoCorasick {
    nodes: Vec<Node>,
    patterns: Vec<Vec<u8>>,
}

fn child_of(nodes: &[Node], u: u32, c: u8) -> Option<u32> {
    let nx = &nodes[u as usize].next;
    let pos = nx.partition_point(|(b, _)| *b < c);
    if pos < nx.len() && nx[pos].0 == c {
        Some(nx[pos].1)
    } else {
        None
    }
}

impl AhoCorasick {
    pub fn new() -> Self {
        AhoCorasick {
            nodes: vec![Node {
                next: Vec::new(),
                fail: 0,
                self_out: Vec::new(),
                out_link: NO_OUT,
                depth: 0,
            }],
            patterns: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn pattern(&self, id: usize) -> &[u8] {
        &self.patterns[id]
    }

    /// Insert a pattern. Empty patterns are ignored. Returns the pattern
    /// id (index in insertion order).
    pub fn insert(&mut self, p: &[u8]) -> u32 {
        let id = self.patterns.len() as u32;
        self.patterns.push(p.to_vec());
        if p.is_empty() {
            return id;
        }
        let mut cur = 0u32;
        for &b in p {
            // resolve the child for byte b, creating it if absent. The
            // mutable borrow of self.nodes[cur] must not overlap the
            // self.nodes.len()/push() below, so read what is needed first.
            let ci = cur as usize;
            let pos = self.nodes[ci].next.partition_point(|(c, _)| *c < b);
            let n = if pos < self.nodes[ci].next.len()
                && self.nodes[ci].next[pos].0 == b
            {
                self.nodes[ci].next[pos].1
            } else {
                let depth = self.nodes[ci].depth + 1;
                let n = self.nodes.len() as u32;
                self.nodes.push(Node {
                    next: Vec::new(),
                    fail: 0,
                    self_out: Vec::new(),
                    out_link: NO_OUT,
                    depth,
                });
                self.nodes[ci].next.insert(pos, (b, n));
                n
            };
            cur = n;
        }
        self.nodes[cur as usize].self_out.push(id);
        id
    }

    /// Build failure links + output links. Must be called once after all
    /// inserts and before any find().
    pub fn build(&mut self) {
        let mut q: VecDeque<u32> = VecDeque::new();
        for i in 0..self.nodes[0].next.len() {
            let n = self.nodes[0].next[i].1;
            self.nodes[n as usize].fail = 0;
            self.nodes[n as usize].out_link = NO_OUT;
            q.push_back(n);
        }
        while let Some(u) = q.pop_front() {
            // fail(u) is a proper suffix: strictly smaller depth, so the
            // fail walk below never touches u and every node it probes was
            // already restored by an earlier BFS pop.
            let children = std::mem::take(&mut self.nodes[u as usize].next);
            for &(c, v) in &children {
                let mut f = self.nodes[u as usize].fail;
                loop {
                    if let Some(n) = child_of(&self.nodes, f, c) {
                        if n != v {
                            self.nodes[v as usize].fail = n;
                            break;
                        }
                    }
                    if f == 0 {
                        self.nodes[v as usize].fail = 0;
                        break;
                    }
                    f = self.nodes[f as usize].fail;
                }
                let fl = self.nodes[v as usize].fail as usize;
                self.nodes[v as usize].out_link = if self.nodes[fl].self_out.is_empty() {
                    self.nodes[fl].out_link
                } else {
                    fl as u32
                };
                q.push_back(v);
            }
            self.nodes[u as usize].next = children;
        }
    }

    /// One pass over `text`. Calls `f(pattern_id, start_offset)` for every
    /// occurrence. Overlapping occurrences are all reported.
    pub fn find<F: FnMut(u32, usize)>(&self, text: &[u8], mut f: F) {
        if self.patterns.is_empty() {
            return;
        }
        let mut cur = 0u32;
        for (i, &b) in text.iter().enumerate() {
            loop {
                if let Some(n) = child_of(&self.nodes, cur, b) {
                    cur = n;
                    break;
                }
                if cur == 0 {
                    break;
                }
                cur = self.nodes[cur as usize].fail;
            }
            let node = &self.nodes[cur as usize];
            let mut o = if node.self_out.is_empty() {
                node.out_link
            } else {
                cur
            };
            while o != NO_OUT {
                let n = &self.nodes[o as usize];
                for &pid in &n.self_out {
                    let plen = self.patterns[pid as usize].len();
                    f(pid, i + 1 - plen);
                }
                o = n.out_link;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(ac: &AhoCorasick, text: &[u8]) -> Vec<(u32, usize)> {
        let mut v = Vec::new();
        ac.find(text, |id, off| v.push((id, off)));
        v.sort_unstable();
        v
    }

    #[test]
    fn finds_all_occurrences_in_one_pass() {
        let mut ac = AhoCorasick::new();
        ac.insert(b"abc");
        ac.insert(b"bc");
        ac.build();
        // "abc" at 0, "bc" at 1, both inside "xabcx"
        assert_eq!(collect(&ac, b"xabcx"), vec![(0, 1), (1, 2)]);
    }

    #[test]
    fn overlapping_and_repeated_matches() {
        let mut ac = AhoCorasick::new();
        ac.insert(b"aa");
        ac.build();
        // "aaa" contains "aa" at 0 and at 1
        assert_eq!(collect(&ac, b"aaa"), vec![(0, 0), (0, 1)]);
    }

    #[test]
    fn suffix_link_match_without_prefix() {
        // classic fail-link case: "she" inside "ushers", and "he"
        let mut ac = AhoCorasick::new();
        ac.insert(b"she");
        ac.insert(b"he");
        ac.insert(b"hers");
        ac.build();
        let got = collect(&ac, b"ushers");
        assert!(got.contains(&(0, 1)), "she at 1: {got:?}");
        assert!(got.contains(&(1, 2)), "he at 2: {got:?}");
        assert!(got.contains(&(2, 2)), "hers at 2: {got:?}");
    }

    #[test]
    fn match_at_arbitrary_shift_not_window_aligned() {
        // the exact failure of 32-byte stride windows: payload shifted by
        // 37 bytes relative to the source still matches byte-exactly.
        let mut ac = AhoCorasick::new();
        ac.insert(b"TOKENPAYLOAD");
        ac.build();
        let mut text = vec![0u8; 37];
        text.extend_from_slice(b"prefix-envelope");
        text.extend_from_slice(b"TOKENPAYLOAD");
        assert_eq!(collect(&ac, &text), vec![(0, 52)]);
    }

    #[test]
    fn binary_values_with_nul_and_high_bytes() {
        let mut ac = AhoCorasick::new();
        ac.insert(&[0x00, 0xff, 0x10, 0x00]);
        ac.build();
        let text = vec![0x01u8, 0x00, 0xff, 0x10, 0x00, 0x02];
        assert_eq!(collect(&ac, &text), vec![(0, 1)]);
    }

    #[test]
    fn empty_and_no_patterns() {
        let mut ac = AhoCorasick::new();
        assert!(ac.is_empty());
        ac.insert(b"");
        ac.insert(b"x");
        ac.build();
        assert_eq!(ac.len(), 2);
        // empty pattern never reports, "x" does
        assert_eq!(collect(&ac, b"axx"), vec![(1, 1), (1, 2)]);
    }

    #[test]
    fn long_pattern_long_text_linear() {
        let mut ac = AhoCorasick::new();
        let pat: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        ac.insert(&pat);
        ac.build();
        let mut text = Vec::with_capacity(1 << 16);
        for i in 0..(1 << 16) {
            text.push((i % 199) as u8);
        }
        let off = 1000usize;
        text[off..off + pat.len()].copy_from_slice(&pat);
        let got = collect(&ac, &text);
        assert!(got.contains(&(0, off)), "found at {off}: {got:?}");
    }

    #[test]
    fn duplicate_patterns_both_report() {
        let mut ac = AhoCorasick::new();
        ac.insert(b"zz");
        ac.insert(b"zz");
        ac.build();
        assert_eq!(collect(&ac, b"zz"), vec![(0, 0), (1, 0)]);
    }

    #[test]
    fn out_link_chain_reports_deep_suffix_matches() {
        // "abcd", "cd", "d": at the final byte all three end - "cd" and
        // "d" are reachable only through the out_link chain of the "abcd"
        // terminal node (no merged output vectors).
        let mut ac = AhoCorasick::new();
        ac.insert(b"abcd");
        ac.insert(b"cd");
        ac.insert(b"d");
        ac.build();
        assert_eq!(collect(&ac, b"abcd"), vec![(0, 0), (1, 2), (2, 3)]);
    }
}
