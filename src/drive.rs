// Crawler interaction driver: behaves like a person completing a form, never
// like a bot clicking controls.
//
// WHY THIS SHAPE
//
// The product is antifraud telemetry. If the driver trips the risk engine
// instantly, we capture a captcha wall and nothing else - no token
// assembly, no pixel timing, no Picasso/DataDome internals. So the driver
// has two obligations that pull in opposite directions:
//
//   (a) be plausible enough that the challenge runs its FULL pipeline, and
//   (b) never perturb what it observes: no Runtime.evaluate (extra JS would
//       pollute the 0033 bytecode trace and the 0034 virtual clock), no
//       fingerprint spoofing, no synthetic fetches that would be
//       indistinguishable from the page's own requests in the net layer.
//
// Everything is therefore DOM-domain reads (getDocument / getBoxModel /
// scrollIntoViewIfNeeded) plus Input-domain events (dispatchMouse/KeyEvent)
// plus Page.reload. Those are browser-process operations; they do not
// execute page script.
//
// THE MODEL, not a click list. A person on a sign-up page:
//
//   ARRIVE -> READ (2-9s of gaze and micro-motion, zero interaction)
//          -> ORIENT (one DOM scan, locate the form)
//          -> FILL (click the first field ONCE, then Tab between fields;
//                   required first; type with bigram-paced cadence)
//          -> CONSENT (tick ToS/privacy boxes)
//          -> CHALLENGE (the widget is the payload; only now)
//          -> REVIEW (re-read before committing)
//          -> SUBMIT (hard-gated on the form being complete)
//          -> OBSERVE (navigation / challenge / validation error)
//          -> on error: repair ONLY the flagged fields, resubmit
//
// FOCUS IS TRACKED, not re-clicked. Tab already moves focus; clicking the
// field again produces focus->blur->focus, a sequence no human emits. The
// driver keeps a predicted focus index over the DOM-ordered focusable list
// and only clicks when Tab cannot reach the target.
//
// IDENTITY IS SEMANTIC. CDP NodeId is reassigned by every getDocument, and
// BackendNodeId changes when a SPA re-renders a field. Progress is keyed on
// name|id|type|form + ordinal, which survives both.

use crate::capture::Tb;
use crate::ctx::Ctx;
use crate::motor::{
    click, lognorm_ms, point_in, press_named, tremor, type_value, wheel, Pt, CDP_IN, VH, VW,
};
use chromiumoxide::cdp::browser_protocol::dom::{
    BackendNodeId, EnableParams as DomEnable, GetBoxModelParams, GetDocumentParams, Node,
    ScrollIntoViewIfNeededParams,
};
use chromiumoxide::cdp::browser_protocol::page::ReloadParams;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CDP: Duration = Duration::from_secs(4);
/// A failed CDP call means the tab is wedged, not that the crawl is over.
const DEGRADE: Duration = Duration::from_secs(6);

/// Minimum gap between full DOM scans. getDocument(depth=-1, pierce=true)
/// forces style recalc and layout across every frame; doing it per action
/// would (1) cost hundreds of roundtrips and (2) inject layout spikes into
/// the very timing telemetry we are here to record.
const SCAN_MIN: Duration = Duration::from_millis(1400);
/// Safety rescan when nothing has signalled a change.
const SCAN_MAX: Duration = Duration::from_secs(20);
/// How long to sit on a challenge we cannot reach before giving up on it.
/// A cross-origin iframe with no exposed control is unsolvable by input
/// events; the page still runs the challenge script while we wait, so that
/// telemetry is worth recording - but only for a while. The point of a run
/// is to collect DIFFERENT challenges, so after this we reload and move on.
const CHALLENGE_DWELL: Duration = Duration::from_secs(45);

/// Give up repairing a form after this many bounces and start over.
const MAX_SUBMIT_TRIES: u32 = 3;
/// How many times to retry an element whose box would not resolve before
/// giving up on it. A scroll that has not settled is the usual cause, so one
/// or two rescans fix it; a genuinely unresolvable element must not be
/// retried forever.
const MAX_FIELD_TRIES: u32 = 3;

/// W3C node types we care about.
const NODE_TEXT: i64 = 3;
/// Recursion bound: obfuscated markup can nest absurdly deep and a stack
/// overflow would kill the whole run, not just one scan.
const MAX_DEPTH: u32 = 512;

// ---------------------------------------------------------------------------
// element model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    TextInput,
    Password,
    Checkbox,
    Radio,
    Select,
    Submit,
    Button,
    Link,
    Widget,
}

#[derive(Clone)]
struct Field {
    backend: i64,
    /// semantic identity, stable across rescans AND across SPA re-renders
    sig: String,
    kind: Kind,
    typ: String,
    name: String,
    id: String,
    cls: String,
    placeholder: String,
    value: String,
    text: String,
    role: String,
    /// index into Walk::forms; usize::MAX = not inside a <form>
    form: usize,
    /// index into Walk::focusables (DOM order) for the Tab model
    tab_index: usize,
    checked: bool,
    required: bool,
    disabled: bool,
    /// aria-invalid / error class: a validation failure we must repair
    invalid: bool,
}

impl Field {
    fn hay(&self) -> String {
        let mut s = String::with_capacity(
            self.cls.len() + self.id.len() + self.text.len() + self.name.len() + self.role.len() + 24,
        );
        s.push_str(&self.cls);
        s.push(' ');
        s.push_str(&self.id);
        s.push(' ');
        s.push_str(&self.name);
        s.push(' ');
        s.push_str(&self.role);
        s.push(' ');
        s.push_str(&self.text);
        s.to_ascii_lowercase()
    }

    /// A captcha / consent-gate widget. Deliberately narrow and structural:
    /// matching "checkbox" or any random class substring made the old driver
    /// click newsletter boxes as if they were captchas, and click plain
    /// divs that happened to live in a container named *-challenge-*.
    fn is_widget(&self) -> bool {
        if self.kind == Kind::Widget {
            return true;
        }
        // only controls can be captcha toggles
        if !matches!(
            self.kind,
            Kind::Checkbox | Kind::Button | Kind::Submit | Kind::Link
        ) {
            return false;
        }
        let h = self.hay();
        WIDGET_HINTS.iter().any(|w| h.contains(w))
    }

    fn is_consent(&self) -> bool {
        if self.kind != Kind::Checkbox && self.kind != Kind::Radio {
            return false;
        }
        let h = self.hay();
        CONSENT_HINTS.iter().any(|w| h.contains(w))
    }

    fn is_textual(&self) -> bool {
        matches!(self.kind, Kind::TextInput | Kind::Password)
    }

    fn is_select(&self) -> bool {
        self.kind == Kind::Select
    }

    fn is_submit(&self) -> bool {
        self.kind == Kind::Submit
    }
}

const WIDGET_HINTS: &[&str] = &[
    "recaptcha",
    "g-recaptcha",
    "hcaptcha",
    "h-captcha",
    "cf-turnstile",
    "turnstile",
    "datadome",
    "px-captcha",
    "_pxcaptcha",
    "geetest",
    "funcaptcha",
    "arkose",
    "captcha",
];

const CONSENT_HINTS: &[&str] = &[
    "terms", "tos", "privacy", "policy", "agree", "consent", "accept",
    "i have read", "услов", "согла", "политик", "подтверж",
];

const SUBMIT_WORDS: &[&str] = &[
    "sign in", "signin", "sign up", "signup", "log in", "login", "log on",
    "continue", "submit", "next", "register", "create account", "get started",
    "verify", "send", "confirm", "войти", "регистрац", "продолжить", "далее",
    "отправить", "подтвердить", "создать",
];

/// input types that accept keyboard text. Everything else must not be typed
/// into.
const TEXT_TYPES: &[&str] = &[
    "text", "email", "tel", "password", "search", "url", "number", "",
];

/// Cross-origin challenge hosts. A reCAPTCHA/DataDome/Turnstile iframe is
/// cross-origin, so pierce=true returns the frame node but NOT its contents:
/// detecting the challenge by page text is blind exactly where the challenge
/// lives. The frame URL is still visible, so match on that.
const CHALLENGE_HOSTS: &[&str] = &[
    "recaptcha.net",
    "google.com/recaptcha",
    "hcaptcha.com",
    "challenges.cloudflare.com",
    "arkoselabs.com",
    "funcaptcha.com",
    "geetest.com",
    "perimeterx.net",
    "px-cdn.net",
    "datadome.co",
];

// ---------------------------------------------------------------------------
// DOM walk (local; one CDP call per scan)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Walk {
    fields: Vec<Field>,
    /// DOM-ordered signatures of everything Tab can land on
    focusables: Vec<String>,
    /// forms in document order; Field::form indexes this
    forms: Vec<i64>,
    /// visible page text, lowercased, for screen classification
    text: String,
    /// every frame/src URL seen, for cross-origin challenge detection
    urls: Vec<String>,
}

fn attr_get(a: &[String], name: &str) -> String {
    let mut i = 0;
    while i + 1 < a.len() {
        if a[i].eq_ignore_ascii_case(name) {
            return a[i + 1].clone();
        }
        i += 2;
    }
    String::new()
}

fn has_attr(a: &[String], name: &str) -> bool {
    a.iter().step_by(2).any(|k| k.eq_ignore_ascii_case(name))
}

fn classify(tag: &str, typ: &str, role: &str, text: &str) -> Option<Kind> {
    let tl = tag.to_ascii_lowercase();
    let ty = typ.to_ascii_lowercase();
    let rl = role.to_ascii_lowercase();
    match tl.as_str() {
        "input" => match ty.as_str() {
            "checkbox" => Some(Kind::Checkbox),
            "radio" => Some(Kind::Radio),
            "submit" | "image" => Some(Kind::Submit),
            "button" | "reset" => Some(Kind::Button),
            "hidden" | "file" | "range" | "color" => None,
            other => {
                if TEXT_TYPES.contains(&other) {
                    Some(Kind::TextInput)
                } else {
                    None
                }
            }
        },
        "textarea" => Some(Kind::TextInput),
        "select" => Some(Kind::Select),
        "button" => Some(if submit_worded(text) {
            Kind::Submit
        } else {
            Kind::Button
        }),
        "a" => Some(Kind::Link),
        _ => match rl.as_str() {
            "button" => Some(if submit_worded(text) {
                Kind::Submit
            } else {
                Kind::Button
            }),
            "checkbox" => Some(Kind::Checkbox),
            "radio" => Some(Kind::Radio),
            "textbox" | "combobox" => Some(if rl == "combobox" {
                Kind::Select
            } else {
                Kind::TextInput
            }),
            "link" => Some(Kind::Link),
            _ => None,
        },
    }
}

fn submit_worded(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    SUBMIT_WORDS.iter().any(|w| t.contains(w))
}

/// Can Tab land on this element? Mirrors the browser's sequential focus
/// navigation order closely enough to predict where Tab puts focus.
fn tabbable(tag: &str, attrs: &[String]) -> bool {
    let ty = attr_get(attrs, "type").to_ascii_lowercase();
    if tag == "input" && matches!(ty.as_str(), "hidden") {
        return false;
    }
    if has_attr(attrs, "disabled") {
        return false;
    }
    if let Some(ti) = attrs
        .iter()
        .zip(attrs.iter().skip(1))
        .find(|(k, _)| k.eq_ignore_ascii_case("tabindex"))
        .map(|(_, v)| v.as_str())
    {
        // negative tabindex removes it from sequential navigation
        if let Ok(n) = ti.trim().parse::<i32>() {
            return n >= 0;
        }
    }
    matches!(
        tag,
        "input" | "textarea" | "select" | "button" | "a" | "summary" | "label"
    ) || has_attr(attrs, "tabindex")
        || attr_get(attrs, "role") == "button"
}

struct WalkCtx<'a> {
    out: &'a mut Walk,
    form_stack: &'a mut Vec<i64>,
    /// ordinal counters per (tag,type) so a semantic signature stays stable
    /// when a SPA re-renders and reassigns every node id
    ordinals: std::collections::HashMap<String, u32>,
}

/// Elements whose subtree is NOT rendered content. Their text is source
/// code, and harvesting it poisons every downstream decision: a JS bundle
/// contains the literal words "invalid", "incorrect", "required", "welcome",
/// "dashboard", so a state machine reading page text sees an error screen on
/// every page, forever. Skipping the whole subtree also avoids recursing
/// through hundreds of kilobytes of minified code for nothing.
fn is_inert(tag: &str) -> bool {
    matches!(tag, "script" | "style" | "noscript")
}

fn walk(node: &Node, ctx: &mut WalkCtx, depth: u32) -> String {
    if depth > MAX_DEPTH {
        return String::new();
    }
    if node.node_type == NODE_TEXT {
        let v = node.node_value.trim();
        return if v.is_empty() {
            String::new()
        } else {
            let mut s = v.to_ascii_lowercase();
            s.push(' ');
            s
        };
    }

    let tag = node.local_name.to_ascii_lowercase();
    if is_inert(&tag) {
        return String::new();
    }
    let attrs: Vec<String> = node.attributes.clone().unwrap_or_default();

    // Frame URLs ONLY. `<script src=".../recaptcha/api.js">` loads the
    // challenge library on every page that uses reCAPTCHA - including v3,
    // where there is no visible widget at all - so treating script src as a
    // challenge frame means every such page is permanently "Captcha".
    // A real challenge lives in an IFRAME, and an iframe is the only element
    // whose src means "a separate document that may need clicking".
    if matches!(tag.as_str(), "iframe" | "frame" | "object" | "embed") {
        let v = attr_get(&attrs, "src");
        if v.starts_with("http") {
            ctx.out.urls.push(v);
        }
    }

    let is_form = tag == "form";
    if is_form {
        let bid = *node.backend_node_id.inner();
        ctx.out.forms.push(bid);
        ctx.form_stack.push(bid);
    }

    let typ = attr_get(&attrs, "type");
    let role = attr_get(&attrs, "role");
    let cls = attr_get(&attrs, "class");
    let aria = attr_get(&attrs, "aria-label");

    // Record the control BEFORE descending so the ordinal matches DOM order,
    // then descend exactly once and fill in the visible label afterwards:
    // `<button>Sign in</button>` has no aria-label, and without that text a
    // submit control is never recognised and the form is never submitted.
    let recorded: Option<usize> = if let Some(mut k) = classify(&tag, &typ, &role, &aria) {
        if k == Kind::TextInput && typ.eq_ignore_ascii_case("password") {
            k = Kind::Password;
        }
        let invalid = attr_get(&attrs, "aria-invalid").eq_ignore_ascii_case("true")
            || cls.to_ascii_lowercase().contains("error")
            || has_attr(&attrs, "data-invalid");
        let style = attr_get(&attrs, "style").to_ascii_lowercase();
        let hidden = has_attr(&attrs, "hidden")
            || style.contains("display:none")
            || style.contains("display: none")
            || style.contains("visibility:hidden")
            || style.contains("visibility: hidden");
        if hidden {
            None
        } else {
            let form = match ctx.form_stack.last() {
                Some(b) => ctx
                    .out
                    .forms
                    .iter()
                    .position(|f| f == b)
                    .unwrap_or(usize::MAX),
                None => usize::MAX,
            };
            // semantic signature: survives rescans AND SPA re-renders
            let ord_key = format!("{}|{}|{}", tag, typ.to_ascii_lowercase(), form);
            let ord = ctx.ordinals.entry(ord_key).or_insert(0);
            let ordinal = *ord;
            *ord += 1;
            let name = attr_get(&attrs, "name");
            let id = attr_get(&attrs, "id");
            let sig = if name.is_empty() && id.is_empty() {
                format!(
                    "{}:{}:{}:{}",
                    tag,
                    typ.to_ascii_lowercase(),
                    ordinal,
                    attr_get(&attrs, "placeholder")
                )
            } else {
                format!("{}:{}:{}", name, id, typ.to_ascii_lowercase())
            };
            ctx.out.fields.push(Field {
                backend: *node.backend_node_id.inner(),
                sig,
                kind: k,
                typ: typ.to_ascii_lowercase(),
                name,
                id,
                cls,
                placeholder: attr_get(&attrs, "placeholder"),
                value: attr_get(&attrs, "value"),
                text: aria,
                role,
                form,
                tab_index: usize::MAX,
                checked: has_attr(&attrs, "checked")
                    || attr_get(&attrs, "aria-checked").eq_ignore_ascii_case("true"),
                required: has_attr(&attrs, "required")
                    || attr_get(&attrs, "aria-required").eq_ignore_ascii_case("true"),
                disabled: has_attr(&attrs, "disabled")
                    || attr_get(&attrs, "aria-disabled").eq_ignore_ascii_case("true")
                    || has_attr(&attrs, "readonly"),
                invalid,
            });
            Some(ctx.out.fields.len() - 1)
        }
    } else {
        None
    };

    // sequential focus order
    if tabbable(&tag, &attrs) {
        let key = if let Some(idx) = recorded {
            ctx.out.fields[idx].sig.clone()
        } else {
            let ord_key = format!("nav|{}|{}", tag, ctx.out.focusables.len());
            let ord = ctx.ordinals.entry(ord_key).or_insert(0);
            let ordinal = *ord;
            *ord += 1;
            format!("nav:{}:{}:{}", tag, ctx.out.focusables.len(), ordinal)
        };
        ctx.out.focusables.push(key);
    }

    // single descent
    let mut text = String::new();
    if let Some(children) = &node.children {
        for c in children {
            text.push_str(&walk(c, ctx, depth + 1));
        }
    }
    if let Some(cd) = &node.content_document {
        text.push_str(&walk(cd, ctx, depth + 1));
    }
    if let Some(roots) = &node.shadow_roots {
        for r in roots {
            text.push_str(&walk(r, ctx, depth + 1));
        }
    }

    if let Some(idx) = recorded {
        if ctx.out.fields[idx].text.is_empty() && !text.trim().is_empty() {
            let t: String = text.trim().chars().take(64).collect();
            ctx.out.fields[idx].text = t;
            // a control whose label says "Continue" is a submit even when it
            // is an <input type=button> or <div role=button>
            if ctx.out.fields[idx].kind == Kind::Button
                && submit_worded(&ctx.out.fields[idx].text)
            {
                ctx.out.fields[idx].kind = Kind::Submit;
            }
        }
    }

    if is_form {
        ctx.form_stack.pop();
    }
    text
}

async fn scan(page: &chromiumoxide::Page) -> Option<Walk> {
    let _ = tokio::time::timeout(CDP_IN, page.execute(DomEnable::default())).await;
    // pierce=true: iframes and shadow roots included. The captcha widget is
    // usually shadow-hosted or in a frame.
    let doc = GetDocumentParams::builder().depth(-1).pierce(true).build();
    let root: Node = match tokio::time::timeout(CDP, page.execute(doc)).await {
        Ok(Ok(r)) => r.result.root,
        _ => return None,
    };
    let mut out = Walk {
        fields: Vec::new(),
        focusables: Vec::new(),
        forms: Vec::new(),
        text: String::new(),
        urls: Vec::new(),
    };
    let mut form_stack: Vec<i64> = Vec::new();
    let text = {
        // ordinals is MOVED into the ctx (the field owns it, not borrows it)
        let mut ctx = WalkCtx {
            out: &mut out,
            form_stack: &mut form_stack,
            ordinals: std::collections::HashMap::new(),
        };
        walk(&root, &mut ctx, 0)
        // ctx drops here, releasing the &mut out borrow
    };
    // char-safe cap: truncate() on a byte index panics inside a multi-byte
    // character, which any non-English page can produce.
    out.text = text.chars().take(1 << 15).collect();
    // resolve tab indices now that focusables is complete. Clone the list
    // first: iterating fields mutably while reading focusables from the same
    // struct is a double borrow.
    let focusables = out.focusables.clone();
    for f in out.fields.iter_mut() {
        f.tab_index = focusables
            .iter()
            .position(|s| s == &f.sig)
            .unwrap_or(usize::MAX);
    }
    out.urls.truncate(256);
    Some(out)
}

/// Fresh viewport geometry for one element, addressed by BackendNodeId.
/// NodeId is reassigned by every getDocument, so a cached NodeId goes stale
/// and the click lands nowhere.
async fn geometry(page: &chromiumoxide::Page, f: &Field) -> Option<(Pt, f64, f64)> {
    let sv = ScrollIntoViewIfNeededParams::builder()
        .backend_node_id(BackendNodeId::new(f.backend))
        .build();
    let _ = tokio::time::timeout(CDP_IN, page.execute(sv)).await;
    // let the scroll settle; a fixed 120ms is a compromise - too short on a
    // heavy page (box is pre-scroll), too long wastes crawl time.
    tokio::time::sleep(Duration::from_millis(130)).await;
    let p = GetBoxModelParams::builder()
        .backend_node_id(BackendNodeId::new(f.backend))
        .build();
    let r = tokio::time::timeout(CDP_IN, page.execute(p)).await.ok()?.ok()?;
    let q = r.result.model.content.inner();
    if q.len() < 8 {
        return None;
    }
    let xs = [q[0], q[2], q[4], q[6]];
    let ys = [q[1], q[3], q[5], q[7]];
    let w = xs.iter().cloned().fold(f64::MIN, f64::max)
        - xs.iter().cloned().fold(f64::MAX, f64::min);
    let h = ys.iter().cloned().fold(f64::MIN, f64::max)
        - ys.iter().cloned().fold(f64::MAX, f64::min);
    if !(w > 2.0) || !(h > 2.0) {
        return None;
    }
    let cx = (xs[0] + xs[1] + xs[2] + xs[3]) / 4.0;
    let cy = (ys[0] + ys[1] + ys[2] + ys[3]) / 4.0;
    // off-screen means the scroll did not take: do not click blind
    if !(cx > 0.0) || !(cy > 0.0) || cx > VW || cy > VH {
        return None;
    }
    Some((Pt::new(cx, cy), w, h))
}

// ---------------------------------------------------------------------------
// value synthesis: plausible, never a real identity
// ---------------------------------------------------------------------------

fn digits(rng: &mut SmallRng, n: usize) -> String {
    (0..n).map(|_| rng.gen_range(b'0'..=b'9') as char).collect()
}

fn word(rng: &mut SmallRng) -> &'static str {
    const W: &[&str] = &[
        "alex", "mira", "jonas", "lena", "tomas", "nora", "ivo", "sara",
        "pavel", "ruth", "kai", "elena", "marco", "yara", "dmitri", "ann",
        "sofia", "mateo", "ines", "lukas",
    ];
    W[rng.gen_range(0..W.len())]
}

/// example.com is on literal blocklists; use ordinary consumer mail domains.
fn mail_domain(rng: &mut SmallRng) -> &'static str {
    const D: &[&str] = &[
        "gmail.com", "outlook.com", "yahoo.com", "proton.me", "icloud.com",
        "hotmail.com", "gmx.com", "mail.com",
    ];
    D[rng.gen_range(0..D.len())]
}

fn fill_value(f: &Field, rng: &mut SmallRng, secret: &str) -> String {
    let mut k = String::with_capacity(96);
    k.push_str(&f.name);
    k.push(' ');
    k.push_str(&f.id);
    k.push(' ');
    k.push_str(&f.placeholder);
    k.push(' ');
    k.push_str(&f.typ);
    k.push(' ');
    k.push_str(&f.text);
    let k = k.to_ascii_lowercase();
    let n = rng.gen_range(100..9999u32);

    if k.contains("email") || k.contains("mail") || f.typ == "email" || k.contains("почт") {
        return format!("{}{}@{}", word(rng), digits(rng, 2), mail_domain(rng));
    }
    if f.kind == Kind::Password || k.contains("pass") || k.contains("парол") {
        // The ENTIRE value must be a pure function of `secret`, including the
        // symbol. A random special here made confirm-password (fixed "!7")
        // disagree 3 times out of 4, so every sign-up form failed validation
        // and the driver bounced in an error loop forever.
        return format!("{}!7", secret);
    }
    if k.contains("first") || k.contains("fname") || k.contains("given") || k.contains("имя") {
        let w = word(rng);
        return format!("{}{}", &w[..1].to_uppercase(), &w[1..]);
    }
    if k.contains("last") || k.contains("surname") || k.contains("family") || k.contains("lname")
        || k.contains("фамил")
    {
        const S: &[&str] = &[
            "Kovac", "Novak", "Bauer", "Lorenz", "Fischer", "Weber", "Horvat",
            "Meyer", "Vogel", "Kraus",
        ];
        return S[rng.gen_range(0..S.len())].to_string();
    }
    if k.contains("name") {
        let w = word(rng);
        return format!("{}{}", &w[..1].to_uppercase(), &w[1..]);
    }
    if k.contains("company") || k.contains("org") || k.contains("business") {
        return format!("{} Labs", word(rng).to_uppercase());
    }
    if k.contains("country") {
        return "Netherlands".to_string();
    }
    if k.contains("city") || k.contains("town") {
        const C: &[&str] = &["Amsterdam", "Rotterdam", "Utrecht", "Leiden", "Delft"];
        return C[rng.gen_range(0..C.len())].to_string();
    }
    if k.contains("zip") || k.contains("postal") || k.contains("индекс") {
        return format!("{}AB", digits(rng, 4));
    }
    if k.contains("address") || k.contains("street") || k.contains("адрес") {
        return format!("{} {}", word(rng).to_uppercase(), digits(rng, 3));
    }
    if f.typ == "number" || k.contains("age") || k.contains("code") || k.contains("year") {
        return if k.contains("year") {
            rng.gen_range(1980..2002u32).to_string()
        } else {
            rng.gen_range(18..80u32).to_string()
        };
    }
    if k.contains("url") || k.contains("website") || k.contains("site") {
        return format!("https://{}.dev", word(rng));
    }
    format!("{}{}", word(rng), n)
}

// ---------------------------------------------------------------------------
// screen model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Screen {
    Form,
    Captcha,
    Error,
    Success,
    Other,
}

/// Classify what is on screen. `submitted` matters: a validation error
/// before we submitted anything is impossible by definition, so without this
/// the driver reads stray "required"/"invalid" copy as an error screen and
/// bounces into a reload loop on a page it never even tried to submit.
fn screen_of(w: &Walk, submitted: bool) -> Screen {
    let t = &w.text;

    if (t.contains("welcome") && t.contains("dashboard"))
        || t.contains("account created")
        || t.contains("check your email")
        || t.contains("verify your email")
        || t.contains("registration complete")
        || t.contains("успешно")
        || t.contains("аккаунт создан")
    {
        return Screen::Success;
    }

    // Only a bounce from OUR submit counts as an error screen.
    if submitted {
        let invalid = w.fields.iter().any(|f| f.invalid);
        if invalid
            || t.contains("is required")
            || t.contains("please fill")
            || t.contains("incorrect")
            || t.contains("doesn't match")
            || t.contains("does not match")
            || t.contains("ошибка")
            || t.contains("заполните")
            || t.contains("неверно")
            || t.contains("не совпад")
        {
            return Screen::Error;
        }
    }

    // Is there a form we still have work to do on? This is what separates a
    // BLOCKING INTERSTITIAL (the whole page is the challenge, no form) from
    // an IN-FORM WIDGET (reCAPTCHA checkbox inside the sign-up form).
    //
    // Getting this backwards is the difference between a plausible session
    // and an instant block: clicking a captcha before filling anything is
    // the cheapest bot signature there is, and it makes the challenge fire
    // at maximum suspicion instead of as part of a normal submission.
    let fillable = active_form(w).is_some()
        && w.fields.iter().any(|f| {
            !f.disabled
                && (f.is_textual() || f.is_select() || f.kind == Kind::Checkbox)
        });

    if !fillable {
        let challenge_frame = w.urls.iter().any(|u| {
            let u = u.to_ascii_lowercase();
            CHALLENGE_HOSTS.iter().any(|h| u.contains(h))
        });
        let has_widget = w.fields.iter().any(|f| f.is_widget());
        if challenge_frame
            || has_widget
            || t.contains("verify you are human")
            || t.contains("i'm not a robot")
            || t.contains("im not a robot")
            || t.contains("are you a robot")
            || t.contains("confirm you are human")
            || t.contains("select all images")
            || t.contains("подтвердите что вы")
            || t.contains("выберите все")
        {
            return Screen::Captcha;
        }
    }

    if w.fields.iter().any(|f| f.is_textual()) || w.fields.iter().any(|f| f.is_submit()) {
        return Screen::Form;
    }
    Screen::Other
}

/// The form being driven: prefer one that has a submit control AND textual
/// fields. Choosing "most textual fields" alone picks a newsletter box on a
/// page whose real sign-up form is smaller.
fn active_form(w: &Walk) -> Option<usize> {
    let mut forms: Vec<usize> = w.fields.iter().map(|f| f.form).collect();
    forms.sort_unstable();
    forms.dedup();
    let mut best: Option<(usize, bool, usize)> = None; // (score, has_submit, idx)
    for form in forms {
        let texts = w
            .fields
            .iter()
            .filter(|f| f.form == form && f.is_textual() && !f.disabled)
            .count();
        if texts == 0 {
            continue;
        }
        let has_submit = w
            .fields
            .iter()
            .any(|f| f.form == form && !f.disabled && f.is_submit());
        // a form that can actually be submitted outranks a bigger one that
        // cannot; then prefer more fields
        let score = texts + if has_submit { 100 } else { 0 };
        if best.map(|(bs, _, _)| score > bs).unwrap_or(true) {
            best = Some((score, has_submit, form));
        }
    }
    match best {
        Some((_, _, form)) => Some(form),
        None => {
            if w.fields
                .iter()
                .any(|f| f.form == usize::MAX && f.is_textual() && !f.disabled)
            {
                Some(usize::MAX)
            } else {
                None
            }
        }
    }
}

/// HARD GATE. Returns the indices still blocking submission.
///
/// `acted` (semantic signatures) is the authority, NOT the DOM `value`
/// attribute: typing sets the property, and the attribute stays empty, so
/// reading it would report every filled field as empty.
///
/// Submitting an incomplete form only yields a validation error and the
/// antifraud challenge never fires - the crawl would collect nothing.
fn form_ready(w: &Walk, form: usize, acted: &HashSet<String>) -> Vec<usize> {
    let mut missing = Vec::new();
    for (i, f) in w.fields.iter().enumerate() {
        if f.form != form || f.disabled {
            continue;
        }
        let done = acted.contains(&f.sig);
        if f.is_textual() || f.is_select() {
            // A field the server rendered with a value is already valid:
            // waiting for the driver to type into it would block submit
            // forever. A select left on its "Select..." placeholder fails
            // validation exactly like an empty text field, so it gates too.
            if !done && f.value.trim().is_empty() {
                missing.push(i);
            }
        } else if (f.is_consent() || f.kind == Kind::Checkbox) && !done && !f.checked {
            missing.push(i);
        }
    }
    missing
}

// ---------------------------------------------------------------------------
// driver state
// ---------------------------------------------------------------------------

// Copy: holds only Instants, so `if let Phase::Read { until, start } = s.phase`
// copies out instead of borrowing s.phase, which would otherwise conflict
// with the &mut s.cursor uses inside the same block.
//
// `start` lives INSIDE the Read variant rather than as a TabState field: the
// content gate needs it, and putting it in the variant means forgetting to
// reset it on a re-read is a compile error instead of a silent bug where the
// ceiling is measured from the very first read of the session.
#[derive(Clone, Copy)]
enum Phase {
    /// Reading the page: gaze and micro-motion, zero interaction.
    /// Time-to-first-interaction is one of the heaviest behavioural signals.
    /// `until` is the minimum gaze, `start` is when this read began (the
    /// hard ceiling for waiting on content).
    Read { until: Instant, start: Instant },
    /// Working the form.
    Work,
    /// Just acted; letting the page react before looking again.
    Observe { until: Instant },
}

struct TabState {
    cursor: Pt,
    phase: Phase,
    scan: Option<Walk>,
    scan_at: Instant,
    acted: HashSet<String>,
    /// predicted focus: index into Walk::focusables
    focus: Option<usize>,
    submitted: bool,
    submit_tries: u32,
    last_url: String,
    last_reload: Instant,
    bad_until: Option<Instant>,
    /// one secret per tab so password and confirm-password agree
    secret: String,
    /// when we first got stuck on an unreachable challenge, or None. A
    /// cross-origin iframe with no exposed control cannot be solved, and
    /// sitting on it for the rest of the run burns the whole session on one
    /// screen instead of collecting DIFFERENT challenges.
    stuck_challenge: Option<Instant>,
    /// how many challenges this tab has given up on (reported per run)
    challenge_skips: u32,
    /// fields whose box could not be resolved, and how many times we tried.
    ///
    /// Marking such a field `acted` immediately is a lie: it stays empty,
    /// form_ready() then reports the form complete, we submit an incomplete
    /// form and bounce on validation forever. But never marking it either is
    /// an infinite loop on the same element. So: retry a bounded number of
    /// times (the scroll usually just needed a rescan to take), then give up.
    unreachable: HashMap<String, u32>,
}

fn env_secs(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

/// Hard cap on waiting for a page to produce content before working it
/// anyway. A page that never renders (hard failure, bot-wall with no DOM,
/// blank redirect) must not freeze the session forever.
const READ_GIVE_UP: Duration = Duration::from_secs(240);

/// Did the document actually produce something a person could act on?
///
/// This is the load signal. A fixed gaze budget cannot be one: under
/// interpreter-only tracing (--no-opt --no-sparkplug --no-maglev) JS runs
/// 10-50x slower, so a sign-up page that loads in 3s normally takes 30-150s
/// here, and a heavy anti-fraud page far longer. Starting to click before
/// the framework has rendered means scanning an empty tree, finding no
/// fields, and wandering the page blind while the challenge we came for has
/// not even begun to execute.
fn content_ready(w: &Walk) -> bool {
    if !w.fields.is_empty() {
        return true;
    }
    if w.urls.iter().any(|u| {
        let u = u.to_ascii_lowercase();
        CHALLENGE_HOSTS.iter().any(|h| u.contains(h))
    }) {
        return true;
    }
    // no controls yet, but the document has real rendered copy
    w.text.len() > 200
}

/// Move focus to a field the way a person does: if Tab from the current
/// focus lands exactly there, press Tab (no mouse travel at all); otherwise
/// reach and click. Returns the new cursor and whether focus is believed set.
async fn focus_field(
    page: &chromiumoxide::Page,
    st: &mut TabState,
    f: &Field,
    rng: &mut SmallRng,
) -> Result<bool, ()> {
    if let (Some(cur), ti) = (st.focus, f.tab_index) {
        if ti != usize::MAX {
            if cur == ti {
                // already focused: typing goes here, no event needed
                return Ok(true);
            }
            if cur + 1 == ti {
                // one Tab away - exactly what a human does
                tokio::time::sleep(Duration::from_millis(lognorm_ms(rng, 140.0, 0.4))).await;
                if press_named(page, "Tab", rng).await {
                    st.focus = Some(ti);
                    return Ok(true);
                }
            }
        }
    }
    let Some((c, w, h)) = geometry(page, f).await else {
        return Ok(false);
    };
    let p = point_in(c, w, h, rng);
    // gaze at the field before reaching for it
    tokio::time::sleep(Duration::from_millis(lognorm_ms(rng, 320.0, 0.45))).await;
    match click(page, st.cursor, p, w, rng).await {
        Ok(end) => {
            st.cursor = end;
            st.focus = if f.tab_index == usize::MAX {
                None
            } else {
                Some(f.tab_index)
            };
            Ok(true)
        }
        Err(()) => Err(()),
    }
}

/// How long one tab keeps the foreground before switching. A person finishes
/// a flow on one page, then moves on - they do not alternate hands between
/// four windows every few seconds.
fn session_budget(rng: &mut SmallRng) -> Duration {
    Duration::from_millis(rng.gen_range(45_000..120_000))
}

/// Drive the tabs. ONE tab is in the foreground at a time.
///
/// Two earlier shapes were both wrong:
///  * random tab per iteration + sleep inside the iteration: with N tabs
///    every inter-action delay got multiplied by N (a four-tab run typed one
///    field every 8-20 seconds) and all tabs shared one RNG, so their input
///    streams were statistically correlated;
///  * one concurrent task per tab: physically impossible. A browser has one
///    focused tab; background tabs report
///    document.visibilityState === 'hidden', get no rAF, and Input events
///    delivered to them arrive without focus. Checking visibilityState is
///    among the first things an antifraud script does, and four mice moving
///    at once is not a pattern a human can produce.
///
/// So: round-robin over tabs, bring the next one to the front, and give it a
/// continuous bounded session. State (progress, focus model, secrets) is kept
/// per tab and survives the switch, so returning to a tab resumes where it
/// left off instead of restarting the form.
pub async fn drive(ctx: Arc<Ctx>, tabs: Vec<Tb>) {
    if tabs.is_empty() {
        return;
    }
    let n = tabs.len();
    let mut rng = SmallRng::seed_from_u64(ctx.t0ms ^ 0x9E37_79B9_7F4A_7C15);

    let mut states: Vec<TabState> = Vec::with_capacity(n);
    let mut rngs: Vec<SmallRng> = Vec::with_capacity(n);
    for i in 0..n {
        // per-tab seed: independent streams, still reproducible
        let seed = ctx.t0ms.wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ (i as u64).wrapping_mul(0xD134_2543_F8FE_1A63);
        rngs.push(SmallRng::seed_from_u64(seed));
        // one secret per tab so password and confirm-password agree
        let mut secret = String::with_capacity(9);
        for _ in 0..9 {
            secret.push(rng.gen_range(b'a'..=b'z') as char);
        }
        states.push(TabState {
            cursor: Pt::new(rng.gen_range(180.0..1100.0), rng.gen_range(140.0..680.0)),
            // stagger so tabs do not all start reading at the same instant
            phase: Phase::Read {
                until: Instant::now()
                    + Duration::from_millis(2800 + (i as u64) * 650 + rng.gen_range(0..4200)),
                start: Instant::now(),
            },
            scan: None,
            scan_at: Instant::now() - SCAN_MAX,
            acted: HashSet::new(),
            focus: None,
            submitted: false,
            submit_tries: 0,
            last_url: String::new(),
            last_reload: Instant::now(),
            bad_until: None,
            secret,
            stuck_challenge: None,
            challenge_skips: 0,
            unreachable: HashMap::new(),
        });
    }

    let mut idx = 0usize;
    while !ctx.cn.stop.load(Ordering::Acquire)
        && !ctx.cn.dead.load(Ordering::Acquire)
        && Instant::now() < ctx.deadline
    {
        let i = idx % n;
        idx += 1;

        // Bring this tab to the foreground BEFORE touching it. Input sent to
        // a background tab is delivered without focus and the page sees
        // itself as hidden - that is both a detection surface and a reason
        // the challenge never runs.
        if n > 1 {
            let _ = tokio::time::timeout(CDP, tabs[i].page.bring_to_front()).await;
            // the switch itself costs a human a moment: gaze moves, pointer
            // settles. Also lets the page resume rAF before we probe the DOM.
            tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 900.0, 0.5))).await;
            // focus model is void after a tab switch: the browser does not
            // necessarily keep the same element focused, and geometry is
            // from a different tab's viewport state.
            states[i].focus = None;
            states[i].scan = None;
        }

        let session_end = (Instant::now() + session_budget(&mut rng)).min(ctx.deadline);
        // Take this tab's RNG out for the session and put it back after, so
        // each tab keeps its own independent stream across sessions.
        let taken = std::mem::replace(&mut rngs[i], SmallRng::seed_from_u64(0));
        let given = drive_tab(Session {
            ctx: &ctx,
            page: &tabs[i].page,
            s: &mut states[i],
            rng: taken,
            session_end,
        })
        .await;
        rngs[i] = given;
    }

    let skips: u32 = states.iter().map(|s| s.challenge_skips).sum();
    let submits: u32 = states.iter().filter(|s| s.submitted).count() as u32;
    eprintln!("[afeye] drive done: tabs={n} challenge_skips={skips} submitted_tabs={submits}");
}

/// One continuous foreground session. Grouped into a struct because the
/// alternative is six positional arguments, and the repo rule is explicit:
/// more than three arguments means a context struct, never a clippy allow.
///
/// `rng` is OWNED here, not borrowed: the session body calls `&mut rng` at
/// ~56 sites, and taking `&mut SmallRng` as a parameter would make every one
/// of those `&mut &mut SmallRng`. Destructuring below rebinds it to a local
/// so the body stays exactly as written.
struct Session<'a> {
    ctx: &'a Arc<Ctx>,
    page: &'a chromiumoxide::Page,
    s: &'a mut TabState,
    rng: SmallRng,
    session_end: Instant,
}

/// Run one bounded session on the foreground tab. State is borrowed in/out
/// so progress (filled fields, submit count, dwell timers) survives the
/// switch to another tab and the session resumes where it left off.
async fn drive_tab(sess: Session<'_>) -> SmallRng {
    let Session {
        ctx,
        page,
        s,
        mut rng,
        session_end,
    } = sess;
    let reload_every = Duration::from_secs(env_secs("AF_RELOAD_SECS", 0));
    loop {
        if ctx.cn.stop.load(Ordering::Acquire) || ctx.cn.dead.load(Ordering::Acquire) {
            break;
        }
        // hand the foreground back to the scheduler so another tab gets its
        // turn; this is what makes the run "one person, many pages" instead
        // of "many mice at once".
        if Instant::now() > session_end || Instant::now() > ctx.deadline {
            break;
        }
        if let Some(t) = s.bad_until {
            if Instant::now() < t {
                tokio::time::sleep(Duration::from_millis(150)).await;
                continue;
            }
            s.bad_until = None;
        }

        // ---------------- READ ----------------
        // Look at the page. Tremor, slow scroll, gaze. No clicks: a human
        // does not touch anything for the first seconds, and that gap is one
        // of the strongest bot signals there is.
        if let Phase::Read { until, start } = s.phase {
            if Instant::now() < until {
                tremor(page, &mut s.cursor, &mut rng).await;
                if rng.gen_bool(0.35) {
                    let notches = rng.gen_range(-3..3i32);
                    if notches != 0 {
                        wheel(page, s.cursor, notches, &mut rng).await;
                        s.scan = None;
                    }
                }
                tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 620.0, 0.5)))
                    .await;
                continue;
            }
            // Gaze budget is up. Do NOT start clicking on a guess: under the
            // interpreter-only trace the page may still be loading (30-150s
            // for a normal sign-up). Scan and require real content; keep
            // waiting - still just looking, which is exactly what a person
            // does on a slow page - until it appears or we give up.
            let ready = match scan(page).await {
                Some(w) => {
                    // decide first, then MOVE: cloning the whole Walk (fields,
                    // focusables, up to 32KB of page text) on every poll of a
                    // page that is still loading is pure waste - and this
                    // polls roughly every 900ms for 30-150s.
                    let r = content_ready(&w);
                    s.scan = Some(w);
                    s.scan_at = Instant::now();
                    r
                }
                None => false,
            };
            if ready || start.elapsed() > READ_GIVE_UP {
                s.phase = Phase::Work;
            } else {
                tremor(page, &mut s.cursor, &mut rng).await;
                tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 900.0, 0.45)))
                    .await;
                continue;
            }
        }

        // ---------------- OBSERVE ----------------
        // Just acted; give the page time to navigate / render the challenge /
        // run inline validation before looking again.
        if let Phase::Observe { until } = s.phase {
            if Instant::now() < until {
                tremor(page, &mut s.cursor, &mut rng).await;
                tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 800.0, 0.45)))
                    .await;
                continue;
            }
            s.phase = Phase::Work;
            s.scan = None;
        }

        // ---------------- rescan ----------------
        // getDocument(depth=-1, pierce=true) forces style recalc and layout
        // across every frame. Scanning after every action would inject
        // ~2 layout spikes per second into the very timing telemetry this
        // crawl exists to record.
        //
        // SCAN_MIN is a real throttle, not a no-op: when the tree was
        // invalidated but we scanned too recently, sleep out the remainder
        // instead of scanning again. Refusing to scan without also waiting
        // would leave the driver acting on a stale tree, which is worse.
        if s.scan.is_none() {
            let since = s.scan_at.elapsed();
            if since < SCAN_MIN {
                tokio::time::sleep(SCAN_MIN - since).await;
                continue;
            }
        }
        let need_scan = s.scan.is_none() || s.scan_at.elapsed() > SCAN_MAX;
        if need_scan {
            match scan(page).await {
                Some(w) => {
                    let url = tokio::time::timeout(Duration::from_secs(2), page.url())
                        .await
                        .ok()
                        .and_then(|r| r.ok())
                        .flatten()
                        .unwrap_or_default();
                    if url != s.last_url {
                        // navigated: new screen, so focus and progress reset.
                        // submit_tries resets too - a fresh form must not
                        // inherit the previous screen's failed attempts.
                        s.last_url = url;
                        s.acted.clear();
                        // a new page has new elements; stale retry counts would
                        // make the driver give up on them immediately
                        s.unreachable.clear();
                        s.focus = None;
                        s.submitted = false;
                        s.submit_tries = 0;
                    }
                    s.scan = Some(w);
                    s.scan_at = Instant::now();
                }
                None => {
                    s.bad_until = Some(Instant::now() + DEGRADE);
                    continue;
                }
            }
        }

        // Clone rather than borrow: holding `&Walk` out of `s.scan` across
        // the cursor/focus/acted mutations below is E0502. Semantic
        // signatures in `acted` survive the clone, so nothing is lost.
        let Some(w) = s.scan.clone() else {
            s.bad_until = Some(Instant::now() + DEGRADE);
            continue;
        };
        let screen = screen_of(&w, s.submitted);

        // ---------------- SUCCESS ----------------
        if screen == Screen::Success {
            tremor(page, &mut s.cursor, &mut rng).await;
            tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 3200.0, 0.55))).await;
            if reload_every.as_secs() > 0
                && s.last_reload.elapsed()
                    > reload_every + Duration::from_secs(rng.gen_range(0..40))
            {
                s.last_reload = Instant::now();
                s.scan = None;
                s.acted.clear();
                s.focus = None;
                s.submitted = false;
                let _ = tokio::time::timeout(CDP, page.execute(ReloadParams::default())).await;
                tokio::time::sleep(Duration::from_millis(rng.gen_range(1800..3600))).await;
                s.phase = Phase::Read {
                    until: Instant::now() + Duration::from_millis(rng.gen_range(2500..7500)),
                    start: Instant::now(),
                };
            }
            continue;
        }

        // ---------------- ERROR ----------------
        // A submit bounced on validation, or the antifraud rejected us. A
        // person repairs THE FLAGGED fields and submits again - not nothing
        // (infinite submit->error loop) and not everything (typing over valid
        // values is both wrong and a bot tell).
        if screen == Screen::Error {
            s.submit_tries = s.submit_tries.saturating_add(1);
            if s.submit_tries > MAX_SUBMIT_TRIES {
                // not converging: server-side rejection, a step we cannot
                // complete, or errors with no per-field markers. Hammering
                // identical submits is a bot signature and yields no new
                // telemetry, so reload and observe a fresh challenge.
                s.submit_tries = 0;
                s.submitted = false;
                s.acted.clear();
                s.focus = None;
                s.scan = None;
                let _ = tokio::time::timeout(CDP, page.execute(ReloadParams::default())).await;
                s.last_reload = Instant::now();
                tokio::time::sleep(Duration::from_millis(rng.gen_range(1800..3600))).await;
                s.phase = Phase::Read {
                    until: Instant::now() + Duration::from_millis(rng.gen_range(2500..7000)),
                    start: Instant::now(),
                };
                continue;
            }
            s.submitted = false;
            let mut released = 0usize;
            for f in w.fields.iter() {
                if f.disabled || !f.invalid {
                    continue;
                }
                s.acted.remove(&f.sig);
                released += 1;
            }
            if released == 0 {
                // generic error with no per-field marker: release the textual
                // fields of the active form so they get re-entered, rather
                // than spinning on a form_ready() that says "complete".
                if let Some(form) = active_form(&w) {
                    for f in w.fields.iter() {
                        if f.form == form && !f.disabled && (f.is_textual() || f.is_select()) {
                            s.acted.remove(&f.sig);
                        }
                    }
                }
            }
            s.scan = None;
            s.phase = Phase::Observe {
                until: Instant::now() + Duration::from_millis(lognorm_ms(&mut rng, 1400.0, 0.5)),
            };
            continue;
        }

        // ---------------- CAPTCHA ----------------
        // The widget IS the payload. It is worked when the page presents it,
        // and (crucially) not before the form is filled - clicking a captcha
        // as the very first action on a page is the cheapest bot signature
        // there is.
        if screen == Screen::Captcha {
            let wid = w.fields.iter().position(|f| f.is_widget());
            if let Some(wi) = wid {
                let f = w.fields[wi].clone();
                if !s.acted.contains(&f.sig) {
                    // Hesitate BEFORE measuring. A person looks at the
                    // challenge, decides, then reaches for it - and the widget
                    // animates/resizes while rendering, so sleeping after
                    // getBoxModel means clicking coordinates that are a
                    // second stale.
                    tokio::time::sleep(Duration::from_millis(lognorm_ms(
                        &mut rng, 1250.0, 0.42,
                    )))
                    .await;
                    if let Some((c, ww, hh)) = geometry(page, &f).await {
                        let p = point_in(c, ww, hh, &mut rng);
                        match click(page, s.cursor, p, ww, &mut rng).await {
                            Ok(end) => {
                                s.cursor = end;
                                s.acted.insert(f.sig.clone());
                                s.focus = None;
                            }
                            Err(()) => {
                                s.bad_until = Some(Instant::now() + DEGRADE);
                                continue;
                            }
                        }
                        s.scan = None;
                        s.phase = Phase::Observe {
                            until: Instant::now()
                                + Duration::from_millis(lognorm_ms(&mut rng, 4200.0, 0.45)),
                        };
                        continue;
                    }
                    // widget found but has no box yet: it is still rendering
                    s.phase = Phase::Observe {
                        until: Instant::now()
                            + Duration::from_millis(lognorm_ms(&mut rng, 1500.0, 0.5)),
                    };
                    s.scan = None;
                    continue;
                }
            }
            // A challenge frame we cannot reach: cross-origin iframe with no
            // control exposed to the DOM. Input events cannot solve it, but
            // the page keeps running the challenge script while we wait, so
            // that telemetry is worth recording - for a while. Sitting here
            // for the rest of the run would spend the whole session on one
            // screen, and the point is to collect DIFFERENT challenges.
            match s.stuck_challenge {
                None => {
                    s.stuck_challenge = Some(Instant::now());
                }
                Some(since) if since.elapsed() > CHALLENGE_DWELL => {
                    s.challenge_skips = s.challenge_skips.saturating_add(1);
                    s.stuck_challenge = None;
                    s.acted.clear();
                    s.focus = None;
                    s.submitted = false;
                    s.submit_tries = 0;
                    s.scan = None;
                    let _ =
                        tokio::time::timeout(CDP, page.execute(ReloadParams::default())).await;
                    s.last_reload = Instant::now();
                    tokio::time::sleep(Duration::from_millis(rng.gen_range(2000..4000))).await;
                    s.phase = Phase::Read {
                        until: Instant::now()
                            + Duration::from_millis(rng.gen_range(2500..7000)),
                        start: Instant::now(),
                    };
                    continue;
                }
                Some(_) => {}
            }
            tremor(page, &mut s.cursor, &mut rng).await;
            tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 2400.0, 0.5))).await;
            continue;
        }
        // no longer stuck: a solvable screen means the dwell timer resets
        s.stuck_challenge = None;

        // ---------------- FORM ----------------
        let Some(form) = active_form(&w) else {
            // nothing to fill: keep browsing so background telemetry flows
            if rng.gen_bool(0.55) {
                let notches = rng.gen_range(-5..-1i32);
                wheel(page, s.cursor, notches, &mut rng).await;
                s.scan = None;
                s.focus = None;
            } else {
                tremor(page, &mut s.cursor, &mut rng).await;
            }
            tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 1900.0, 0.5))).await;
            continue;
        };

        // The `submitted` latch must be releasable WITHOUT a navigation, or
        // multi-step SPA flows die: React/Vue wizards replace the form in
        // place, the URL never changes, so the url-diff reset never fires and
        // step 2's fields get filled forever but never submitted. Detect it
        // structurally instead - untouched fillable controls in the active
        // form mean a new step appeared.
        //
        // This sits BEFORE phase 1 on purpose. Checked at phase 5 it would
        // always be false, because phases 1-4 have just consumed every
        // untouched control.
        if s.submitted
            && w.fields.iter().any(|f| {
                f.form == form
                    && !f.disabled
                    && !s.acted.contains(&f.sig)
                    && (f.is_textual()
                        || f.is_select()
                        || f.kind == Kind::Checkbox
                        || f.is_widget())
            })
        {
            s.submitted = false;
            s.submit_tries = 0;
        }

        // 1. textual fields, required first. Filling optional ones while a
        //    required field is still empty is how a bot ends up submitting an
        //    invalid form.
        let next_text = w
            .fields
            .iter()
            .position(|f| {
                f.form == form
                    && f.is_textual()
                    && !f.disabled
                    && f.required
                    && !s.acted.contains(&f.sig)
            })
            .or_else(|| {
                w.fields.iter().position(|f| {
                    f.form == form
                        && f.is_textual()
                        && !f.disabled
                        && !s.acted.contains(&f.sig)
                })
            });
        if let Some(ti) = next_text {
            let f = w.fields[ti].clone();
            match focus_field(page, &mut *s, &f, &mut rng).await {
                Ok(true) => {}
                Ok(false) => {
                    // No box: the scroll has not settled, or the element is
                    // laid out outside the viewport. Do NOT mark it acted -
                    // that would leave it empty while form_ready() reports the
                    // form complete, and we would submit a hole and bounce on
                    // validation forever. Retry a bounded number of times.
                    let give_up = {
                        let n = s.unreachable.entry(f.sig.clone()).or_insert(0);
                        *n += 1;
                        *n >= MAX_FIELD_TRIES
                    };
                    if give_up {
                        s.acted.insert(f.sig.clone());
                    }
                    s.scan = None;
                    s.phase = Phase::Observe {
                        until: Instant::now() + Duration::from_millis(400),
                    };
                    continue;
                }
                Err(()) => {
                    s.bad_until = Some(Instant::now() + DEGRADE);
                    continue;
                }
            }
            // the beat between focusing a field and starting to type
            tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 280.0, 0.42))).await;
            let v = fill_value(&f, &mut rng, &s.secret);
            if !type_value(page, &v, &mut rng).await {
                s.bad_until = Some(Instant::now() + DEGRADE);
                continue;
            }
            s.acted.insert(f.sig.clone());
            // leaving a field: people Tab far more often than they reach for
            // the mouse, and Tab advances focus without any pointer travel.
            tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 300.0, 0.45))).await;
            if rng.gen_bool(0.78) {
                if press_named(page, "Tab", &mut rng).await {
                    s.focus = s.focus.map(|c| c + 1);
                }
            }
            // short observe: inline validation fires ~300-800ms after blur
            s.phase = Phase::Observe {
                until: Instant::now() + Duration::from_millis(lognorm_ms(&mut rng, 520.0, 0.6)),
            };
            continue;
        }

        // 2. selects. A country/language dropdown left on its "Select..."
        //    placeholder fails validation, so it gates submit too.
        let next_select = w.fields.iter().position(|f| {
            f.form == form && !f.disabled && f.is_select() && !s.acted.contains(&f.sig)
        });
        if let Some(si) = next_select {
            let f = w.fields[si].clone();
            match focus_field(page, &mut *s, &f, &mut rng).await {
                Ok(true) => {}
                Ok(false) => {
                    let give_up = {
                        let n = s.unreachable.entry(f.sig.clone()).or_insert(0);
                        *n += 1;
                        *n >= MAX_FIELD_TRIES
                    };
                    if give_up {
                        s.acted.insert(f.sig.clone());
                    }
                    s.scan = None;
                    s.phase = Phase::Observe {
                        until: Instant::now() + Duration::from_millis(400),
                    };
                    continue;
                }
                Err(()) => {
                    s.bad_until = Some(Instant::now() + DEGRADE);
                    continue;
                }
            }
            tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 340.0, 0.45))).await;
            // arrow through the options, then commit. Picking the very first
            // non-placeholder option every time is itself a pattern, so vary.
            let presses = rng.gen_range(1..6);
            for _ in 0..presses {
                press_named(page, "ArrowDown", &mut rng).await;
                tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 165.0, 0.5)))
                    .await;
            }
            tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 260.0, 0.45))).await;
            press_named(page, "Enter", &mut rng).await;
            s.acted.insert(f.sig.clone());
            s.phase = Phase::Observe {
                until: Instant::now() + Duration::from_millis(lognorm_ms(&mut rng, 620.0, 0.5)),
            };
            continue;
        }

        // 3. consent checkboxes / radios, in document order
        let next_consent = w.fields.iter().position(|f| {
            f.form == form
                && !f.disabled
                && (f.kind == Kind::Checkbox || f.kind == Kind::Radio)
                && !f.checked
                && !s.acted.contains(&f.sig)
        });
        if let Some(ci) = next_consent {
            let f = w.fields[ci].clone();
            // people read terms before ticking; skipping straight to the box
            // is another tell
            tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 1500.0, 0.5))).await;
            if let Some((c, ww, hh)) = geometry(page, &f).await {
                let p = point_in(c, ww, hh, &mut rng);
                match click(page, s.cursor, p, ww, &mut rng).await {
                    Ok(end) => {
                        s.cursor = end;
                        s.focus = if f.tab_index == usize::MAX {
                            None
                        } else {
                            Some(f.tab_index)
                        };
                    }
                    Err(()) => {
                        s.bad_until = Some(Instant::now() + DEGRADE);
                        s.acted.insert(f.sig.clone());
                        continue;
                    }
                }
            }
            s.acted.insert(f.sig.clone());
            s.scan = None;
            s.phase = Phase::Observe {
                until: Instant::now() + Duration::from_millis(lognorm_ms(&mut rng, 800.0, 0.5)),
            };
            continue;
        }

        // 4. a widget on this screen (often appears only once fields are full)
        let next_widget = w
            .fields
            .iter()
            .position(|f| f.is_widget() && !s.acted.contains(&f.sig));
        if let Some(wi) = next_widget {
            let f = w.fields[wi].clone();
            // look at the widget BEFORE measuring it: it animates and resizes
            // while rendering, so a pause after getBoxModel would leave us
            // clicking coordinates that are already stale.
            tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 1100.0, 0.45)))
                .await;
            if let Some((c, ww, hh)) = geometry(page, &f).await {
                let p = point_in(c, ww, hh, &mut rng);
                if let Ok(end) = click(page, s.cursor, p, ww, &mut rng).await {
                    s.cursor = end;
                }
                s.acted.insert(f.sig.clone());
                s.focus = None;
                s.scan = None;
                s.phase = Phase::Observe {
                    until: Instant::now() + Duration::from_millis(lognorm_ms(&mut rng, 4000.0, 0.5)),
                };
                continue;
            }
            s.acted.insert(f.sig.clone());
            continue;
        }

        // 5. SUBMIT - gated on the form actually being complete
        if !s.submitted {
            let missing = form_ready(&w, form, &s.acted);
            if !missing.is_empty() {
                // fill what is missing instead of submitting an incomplete
                // form (which only yields a validation error, no challenge)
                let mut progressed = false;
                for mi in missing.iter().take(6) {
                    let f = w.fields[*mi].clone();
                    if s.acted.contains(&f.sig) {
                        continue;
                    }
                    if focus_field(page, &mut *s, &f, &mut rng).await != Ok(true) {
                        // Same lie as phases 1-2 would be here: marking it
                        // acted leaves the field empty while form_ready()
                        // calls the form complete. Bound the retries instead.
                        let give_up = {
                            let n = s.unreachable.entry(f.sig.clone()).or_insert(0);
                            *n += 1;
                            *n >= MAX_FIELD_TRIES
                        };
                        if give_up {
                            s.acted.insert(f.sig.clone());
                        }
                        continue;
                    }
                    tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 300.0, 0.45)))
                        .await;
                    if f.is_textual() {
                        let v = fill_value(&f, &mut rng, &s.secret);
                        if type_value(page, &v, &mut rng).await {
                            progressed = true;
                        }
                    } else if f.is_select() {
                        let presses = rng.gen_range(1..5);
                        for _ in 0..presses {
                            press_named(page, "ArrowDown", &mut rng).await;
                            tokio::time::sleep(Duration::from_millis(
                                lognorm_ms(&mut rng, 150.0, 0.5),
                            ))
                            .await;
                        }
                        press_named(page, "Enter", &mut rng).await;
                        progressed = true;
                    } else {
                        // checkbox/radio: focus_field already clicked it
                        progressed = true;
                    }
                    s.acted.insert(f.sig.clone());
                }
                s.scan = None;
                s.phase = Phase::Observe {
                    until: Instant::now()
                        + Duration::from_millis(if progressed { 700 } else { 1600 }),
                };
                continue;
            }

            // review the form before committing: people re-read what they typed
            tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 2100.0, 0.45))).await;
            tremor(page, &mut s.cursor, &mut rng).await;

            let sub = w.fields.iter().position(|f| {
                f.form == form && !f.disabled && (f.is_submit() || f.kind == Kind::Button)
            });
            if let Some(si) = sub {
                let f = w.fields[si].clone();
                if let Some((c, ww, hh)) = geometry(page, &f).await {
                    let p = point_in(c, ww, hh, &mut rng);
                    match click(page, s.cursor, p, ww, &mut rng).await {
                        Ok(end) => {
                            s.cursor = end;
                            s.submitted = true;
                        }
                        Err(()) => {
                            s.bad_until = Some(Instant::now() + DEGRADE);
                            continue;
                        }
                    }
                }
            } else {
                // no submit control in the form: Enter from the focused field
                s.submitted = true;
                press_named(page, "Enter", &mut rng).await;
            }
            // submit navigates or renders the challenge: the cached tree and
            // the focus model are both dead
            s.scan = None;
            s.focus = None;
            s.phase = Phase::Observe {
                until: Instant::now() + Duration::from_millis(lognorm_ms(&mut rng, 5000.0, 0.45)),
            };
            continue;
        }

        // submitted and the screen has not changed: stay human and keep the
        // session alive so background telemetry keeps flowing
        if rng.gen_bool(0.55) {
            let notches = rng.gen_range(-4..-1i32);
            wheel(page, s.cursor, notches, &mut rng).await;
            s.scan = None;
            s.focus = None;
        } else {
            tremor(page, &mut s.cursor, &mut rng).await;
        }
        tokio::time::sleep(Duration::from_millis(lognorm_ms(&mut rng, 2600.0, 0.5))).await;
    }

    // hand the RNG back so this tab keeps its independent stream next session;
    // challenge_skips / submitted live in `s` (borrowed) and drive() sums them.
    rng
}
