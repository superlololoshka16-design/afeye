// Motor model: the physical layer of a human hand on a mouse + keyboard.
//
// Everything here exists because a real input device has properties that
// CDP will happily let you omit - and omitting them is what gets a crawler
// classified as a bot. Specifically:
//
//  * TIME-BASED SAMPLING. A 125Hz mouse emits a move event every ~8ms
//    REGARDLESS of how fast the hand travels. Sampling by distance (the
//    naive approach) inverts the physics: fast moves get sparse events,
//    slow moves get dense ones. Antifraud movement models read event
//    density directly, so density must be constant in time.
//  * SHIFT IS A KEY. For '@' the browser emits a discrete ShiftLeft
//    keyDown, THEN the 'A' keyDown with modifiers=8, THEN char, THEN the
//    two keyUps. Setting modifiers=8 alone produces an event where
//    e.shiftKey is true but e.getModifierState('Shift') is false -
//    internally contradictory, and detectable with one line of JS.
//  * DOMKeyLocation. Enter is 0, ShiftLeft 1, ShiftRight 2, numpad 3.
//    Defaulting to 0 for everything is another contradiction.
//  * FORCE. A mouse button press reports force=1, hover reports 0. CDP
//    defaults force to 0, so an unset press arrives as a touch with no
//    pressure.
//  * MICRO-TREMOR. A hand holding still is never still: 8-12Hz drift of
//    1-3px. A pointer that is perfectly frozen between actions and then
//    jumps is a machine.
//  * SUB-PIXEL POSITION. Device coordinates are integral, but the browser
//    tracks sub-pixel pointer position. Quantising to whole pixels is fine;
//    quantising the TRAJECTORY (computing on a grid) is not - so all math
//    stays f64 and only the wire value rounds.

use rand::rngs::SmallRng;
use rand::Rng;
use std::time::Duration;

use chromiumoxide::cdp::browser_protocol::input::*;

/// CDP input timeout. Generous: a page under heavy antifraud work can stall
/// the main thread, and a timeout here means "this tab is degraded", not
/// "give up on the crawl".
pub(super) const CDP_IN: Duration = Duration::from_millis(900);

/// Viewport the browser is launched with (browser.rs --window-size).
pub(super) const VW: f64 = 1280.0;
pub(super) const VH: f64 = 832.0;

/// Mouse sampling period in ms. 125Hz = 8ms. Real devices are 125/250/500Hz
/// and the OS coalesces, so 7-11ms of jitter around 8 is the honest shape.
const SAMPLE_MS: (u64, u64) = (7, 12);

/// Hand tremor amplitude in px while holding position.
const TREMOR_PX: f64 = 1.6;

#[derive(Clone, Copy, Debug)]
pub struct Pt {
    pub x: f64,
    pub y: f64,
}

impl Pt {
    pub fn new(x: f64, y: f64) -> Self {
        Pt { x, y }
    }
    fn dist(self, o: Pt) -> f64 {
        ((self.x - o.x).powi(2) + (self.y - o.y).powi(2)).sqrt()
    }
}

// ---------------------------------------------------------------------------
// timing primitives
// ---------------------------------------------------------------------------

/// Standard normal, Box-Muller. SmallRng has no gaussian and every honest
/// human interval is right-skewed, so this is the base of all delays.
pub fn gauss(rng: &mut SmallRng) -> f64 {
    let u1: f64 = rng.gen_range(1e-9f64..1.0);
    let u2: f64 = rng.gen();
    (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
}

/// Log-normal delay in ms: median `med`, log-sd `sigma`. Clamped so a tail
/// draw can never stall the crawl.
pub fn lognorm_ms(rng: &mut SmallRng, med: f64, sigma: f64) -> u64 {
    let v = (med.ln() + sigma * gauss(rng)).exp();
    v.clamp(6.0, 8000.0) as u64
}

/// Minimum-jerk position fraction. Human point-to-point reaches follow this
/// (Flash & Hogan 1985): slow start, fast middle, slow precise landing.
/// Constant velocity and symmetric bezier arcs are both machine shapes.
fn min_jerk(t: f64) -> f64 {
    let t = t.clamp(0.0, 1.0);
    10.0 * t * t * t - 15.0 * t * t * t * t + 6.0 * t * t * t * t * t
}

/// Fitts' law movement time in ms: MT = a + b * log2(2D/W + 1).
/// This is why a reach to a small distant target takes longer - the single
/// most replicated result in motor control, and exactly what a movement
/// model checks.
fn fitts_ms(dist: f64, width: f64, rng: &mut SmallRng) -> u64 {
    let w = width.max(8.0);
    let id = (2.0 * dist.max(1.0) / w + 1.0).log2();
    lognorm_ms(rng, 175.0 + 108.0 * id, 0.20)
}

/// Inter-key interval. Median ~112ms with a heavy right tail, faster for
/// common bigrams and for hand alternation, plus occasional hesitation.
pub fn keystroke_ms(rng: &mut SmallRng, prev: char, c: char) -> u64 {
    let common = matches!(
        (prev.to_ascii_lowercase(), c.to_ascii_lowercase()),
        ('t', 'h')
            | ('h', 'e')
            | ('e', 'r')
            | ('a', 'n')
            | ('o', 'n')
            | ('i', 'n')
            | ('n', 'd')
            | ('a', 'l')
            | ('e', 's')
            | ('i', 'o')
            | ('l', 'e')
            | ('s', 't')
            | ('e', 'n')
            | ('a', 't')
            | ('e', 'd')
            | ('o', 'r')
    );
    let mut med = if common { 84.0 } else { 122.0 };
    // alternating hands is faster than repeating one hand
    med *= if handed(prev) != handed(c) {
        0.91
    } else {
        1.13
    };
    // shift-combos (capitals, symbols) cost an extra beat
    if key_info(c).shift {
        med *= 1.18;
    }
    // hesitation: people pause mid-word to think
    if rng.gen_bool(0.06) {
        return lognorm_ms(rng, 480.0, 0.55);
    }
    lognorm_ms(rng, med, 0.33)
}

fn handed(c: char) -> u8 {
    match c.to_ascii_lowercase() {
        'q' | 'w' | 'e' | 'r' | 't' | 'a' | 's' | 'd' | 'f' | 'g' | 'z' | 'x' | 'c' | 'v'
        | 'b' | '1' | '2' | '3' | '4' | '5' | '`' | '@' | '#' | '$' | '%' => 0,
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// keyboard mapping
// ---------------------------------------------------------------------------

pub struct KeyInfo {
    /// physical key, e.g. KeyA / Digit2 / Semicolon
    pub code: &'static str,
    /// Windows virtual key code (== native for US layout)
    pub vk: i64,
    /// whether the shift modifier must be held
    pub shift: bool,
    /// DOMKeyLocation: 0 standard, 1 left, 2 right, 3 numpad
    pub location: i64,
}

pub fn key_info(c: char) -> KeyInfo {
    let lower = c.to_ascii_lowercase();
    if lower.is_ascii_lowercase() {
        return KeyInfo {
            code: match lower {
                'a' => "KeyA", 'b' => "KeyB", 'c' => "KeyC", 'd' => "KeyD",
                'e' => "KeyE", 'f' => "KeyF", 'g' => "KeyG", 'h' => "KeyH",
                'i' => "KeyI", 'j' => "KeyJ", 'k' => "KeyK", 'l' => "KeyL",
                'm' => "KeyM", 'n' => "KeyN", 'o' => "KeyO", 'p' => "KeyP",
                'q' => "KeyQ", 'r' => "KeyR", 's' => "KeyS", 't' => "KeyT",
                'u' => "KeyU", 'v' => "KeyV", 'w' => "KeyW", 'x' => "KeyX",
                'y' => "KeyY", _ => "KeyZ",
            },
            vk: lower as i64 - 'a' as i64 + 65,
            shift: c != lower,
            location: 0,
        };
    }
    if c.is_ascii_digit() {
        // shifted digits: ) ! @ # $ % ^ & * (
        let (d, shift) = match c {
            ')' => ('0', true), '!' => ('1', true), '@' => ('2', true),
            '#' => ('3', true), '$' => ('4', true), '%' => ('5', true),
            '^' => ('6', true), '&' => ('7', true), '*' => ('8', true),
            '(' => ('9', true), o => (o, false),
        };
        return KeyInfo {
            code: match d {
                '0' => "Digit0", '1' => "Digit1", '2' => "Digit2",
                '3' => "Digit3", '4' => "Digit4", '5' => "Digit5",
                '6' => "Digit6", '7' => "Digit7", '8' => "Digit8",
                _ => "Digit9",
            },
            vk: d as i64,
            shift,
            location: 0,
        };
    }
    let (code, vk, shift) = match c {
        ' ' => ("Space", 32, false),
        '.' => ("Period", 190, false),
        '>' => ("Period", 190, true),
        ',' => ("Comma", 188, false),
        '<' => ("Comma", 188, true),
        ';' => ("Semicolon", 186, false),
        ':' => ("Semicolon", 186, true),
        '\'' => ("Quote", 222, false),
        '"' => ("Quote", 222, true),
        '/' => ("Slash", 191, false),
        '?' => ("Slash", 191, true),
        '-' => ("Minus", 189, false),
        '_' => ("Minus", 189, true),
        '=' => ("Equal", 187, false),
        '+' => ("Equal", 187, true),
        '[' => ("BracketLeft", 219, false),
        '{' => ("BracketLeft", 219, true),
        ']' => ("BracketRight", 221, false),
        '}' => ("BracketRight", 221, true),
        '\\' => ("Backslash", 220, false),
        '|' => ("Backslash", 220, true),
        '`' => ("Backquote", 192, false),
        '~' => ("Backquote", 192, true),
        '\t' => ("Tab", 9, false),
        '\n' | '\r' => ("Enter", 13, false),
        _ => ("Space", 32, false),
    };
    KeyInfo {
        code,
        vk,
        shift,
        location: 0,
    }
}

/// Named (non-printable) keys: (key, code, vk, text, location).
pub fn named_key(name: &str) -> (&'static str, &'static str, i64, Option<&'static str>, i64) {
    match name {
        "Tab" => ("Tab", "Tab", 9, None, 0),
        "Enter" => ("Enter", "Enter", 13, Some("\r"), 0),
        "Backspace" => ("Backspace", "Backspace", 8, None, 0),
        "Escape" => ("Escape", "Escape", 27, None, 0),
        "ArrowDown" => ("ArrowDown", "ArrowDown", 40, None, 0),
        "ArrowUp" => ("ArrowUp", "ArrowUp", 38, None, 0),
        "ArrowLeft" => ("ArrowLeft", "ArrowLeft", 37, None, 0),
        "ArrowRight" => ("ArrowRight", "ArrowRight", 39, None, 0),
        "Home" => ("Home", "Home", 36, None, 0),
        "End" => ("End", "End", 35, None, 0),
        "ShiftLeft" => ("Shift", "ShiftLeft", 16, None, 1),
        "ShiftRight" => ("Shift", "ShiftRight", 16, None, 2),
        _ => ("Tab", "Tab", 9, None, 0),
    }
}

/// modifier bitmask per DOM spec
const MOD_SHIFT: i64 = 8;

/// Build a key event. `location` and `unmodified_text` are what make the
/// event internally consistent instead of a contradiction.
fn key_params(
    ty: DispatchKeyEventType,
    key: &str,
    code: &str,
    vk: i64,
    location: i64,
    text: Option<&str>,
    mods: i64,
    auto_repeat: bool,
) -> Result<DispatchKeyEventParams, String> {
    let mut b = DispatchKeyEventParams::builder()
        .r#type(ty)
        .key(key)
        .code(code)
        .windows_virtual_key_code(vk)
        .native_virtual_key_code(vk)
        .location(location)
        .modifiers(mods)
        .auto_repeat(auto_repeat)
        .is_keypad(false)
        .is_system_key(false);
    if let Some(t) = text {
        b = b.text(t).unmodified_text(t);
    }
    b.build()
}

/// One physical key press: [Shift down] keyDown char [Shift up].
/// The Shift events are discrete, exactly as a real keyboard driver emits
/// them, so getModifierState('Shift') agrees with e.shiftKey.
pub async fn press_char(
    page: &chromiumoxide::Page,
    c: char,
    rng: &mut SmallRng,
    auto_repeat: bool,
) -> bool {
    let ki = key_info(c);
    // stack buffer, zero allocation on the hot typing path
    let mut buf = [0u8; 4];
    let cs = c.encode_utf8(&mut buf);
    let mods = if ki.shift { MOD_SHIFT } else { 0 };

    if ki.shift {
        let (sk, sc, svk, _, sloc) = named_key(if rng.gen_bool(0.88) {
            "ShiftLeft"
        } else {
            "ShiftRight"
        });
        let down = key_params(
            DispatchKeyEventType::RawKeyDown,
            sk,
            sc,
            svk,
            sloc,
            None,
            MOD_SHIFT,
            false,
        );
        if let Ok(p) = down {
            if !matches!(
                tokio::time::timeout(CDP_IN, page.execute(p)).await,
                Ok(Ok(_))
            ) {
                return false;
            }
        }
        // shift is held slightly before the letter: 25-70ms
        tokio::time::sleep(Duration::from_millis(lognorm_ms(rng, 42.0, 0.35))).await;
    }

    // printable keys send keyDown (no text) then a separate char event; that
    // is how Chromium models it and what pages see in the wild.
    let down = key_params(
        DispatchKeyEventType::RawKeyDown,
        cs,
        ki.code,
        ki.vk,
        ki.location,
        None,
        mods,
        auto_repeat,
    );
    let ch = key_params(
        DispatchKeyEventType::Char,
        cs,
        ki.code,
        ki.vk,
        ki.location,
        Some(cs),
        mods,
        auto_repeat,
    );
    let up = key_params(
        DispatchKeyEventType::KeyUp,
        cs,
        ki.code,
        ki.vk,
        ki.location,
        None,
        mods,
        false,
    );
    let (down, ch, up) = match (down, ch, up) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return false,
    };
    if !matches!(
        tokio::time::timeout(CDP_IN, page.execute(down)).await,
        Ok(Ok(_))
    ) {
        return false;
    }
    let _ = tokio::time::timeout(CDP_IN, page.execute(ch)).await;
    // key hold time before release
    tokio::time::sleep(Duration::from_millis(lognorm_ms(rng, 66.0, 0.30))).await;
    if !matches!(
        tokio::time::timeout(CDP_IN, page.execute(up)).await,
        Ok(Ok(_))
    ) {
        return false;
    }

    if ki.shift {
        tokio::time::sleep(Duration::from_millis(lognorm_ms(rng, 28.0, 0.4))).await;
        let (sk, sc, svk, _, sloc) = named_key("ShiftLeft");
        if let Ok(p) = key_params(DispatchKeyEventType::KeyUp, sk, sc, svk, sloc, None, 0, false) {
            let _ = tokio::time::timeout(CDP_IN, page.execute(p)).await;
        }
    }
    true
}

/// A named key (Tab/Enter/arrows/Escape). No char event: these are not
/// printable.
pub async fn press_named(
    page: &chromiumoxide::Page,
    name: &str,
    rng: &mut SmallRng,
) -> bool {
    let (key, code, vk, text, location) = named_key(name);
    let ty = if text.is_some() {
        DispatchKeyEventType::KeyDown
    } else {
        DispatchKeyEventType::RawKeyDown
    };
    let down = key_params(ty, key, code, vk, location, text, 0, false);
    let up = key_params(DispatchKeyEventType::KeyUp, key, code, vk, location, None, 0, false);
    let (down, up) = match (down, up) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return false,
    };
    if !matches!(
        tokio::time::timeout(CDP_IN, page.execute(down)).await,
        Ok(Ok(_))
    ) {
        return false;
    }
    tokio::time::sleep(Duration::from_millis(lognorm_ms(rng, 62.0, 0.3))).await;
    matches!(
        tokio::time::timeout(CDP_IN, page.execute(up)).await,
        Ok(Ok(_))
    )
}

/// Type a whole value the way a person does: variable cadence driven by
/// bigram statistics, word-boundary pauses, and an occasional typo that is
/// noticed and corrected with Backspace.
pub async fn type_value(page: &chromiumoxide::Page, s: &str, rng: &mut SmallRng) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return true;
    }
    // a typo is only plausible in free text, not in a short numeric field
    let typo_at: Option<usize> = if chars.len() > 7 && rng.gen_bool(0.26) {
        Some(rng.gen_range(2..chars.len() - 1))
    } else {
        None
    };
    let mut prev = ' ';
    for (i, c) in chars.iter().enumerate() {
        if typo_at == Some(i) {
            // hit the neighbour key, notice, backspace, retry
            let wrong: char = if c.is_ascii_lowercase() {
                let b = *c as u8;
                let d = if rng.gen_bool(0.5) { 1i32 } else { -1 };
                ((b as i32 + d).clamp(b'a' as i32, b'z' as i32) as u8) as char
            } else if c.is_ascii_digit() {
                let d = if rng.gen_bool(0.5) { 1i32 } else { -1 };
                ((*c as i32 + d).clamp('0' as i32, '9' as i32) as u8) as char
            } else {
                'x'
            };
            if !press_char(page, wrong, rng, false).await {
                return false;
            }
            // the pause of noticing a mistake
            tokio::time::sleep(Duration::from_millis(lognorm_ms(rng, 340.0, 0.42))).await;
            if !press_named(page, "Backspace", rng).await {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(lognorm_ms(rng, 140.0, 0.4))).await;
        }
        if !press_char(page, *c, rng, false).await {
            return false;
        }
        // word boundaries and the structural parts of an email/phone get a
        // longer beat: that is where people chunk their input
        let chunk = *c == ' ' || *c == '@' || *c == '.' || *c == '-' || *c == '+';
        tokio::time::sleep(Duration::from_millis(if chunk {
            lognorm_ms(rng, 210.0, 0.42)
        } else {
            keystroke_ms(rng, prev, *c)
        }))
        .await;
        prev = *c;
    }
    true
}

// ---------------------------------------------------------------------------
// mouse
// ---------------------------------------------------------------------------

/// One mouse event carrying the full physical state a real device reports:
/// device type, pressed-button mask, force, and the pen axes a mouse always
/// reports as zero. Omitting these is what makes a synthesised event
/// distinguishable from a device event.
async fn mouse_evt(
    page: &chromiumoxide::Page,
    ty: DispatchMouseEventType,
    p: Pt,
    btn: Option<MouseButton>,
    buttons: i64,
    clicks: i64,
    force: f64,
    delta: Option<(f64, f64)>,
) -> bool {
    let mut b = DispatchMouseEventParams::builder()
        .x(p.x)
        .y(p.y)
        .r#type(ty)
        .pointer_type(DispatchMouseEventPointerType::Mouse)
        .modifiers(0)
        .buttons(buttons)
        // hover reports force 0, a press reports 1. CDP defaults to 0, so an
        // unset press arrives as a pointer with no pressure behind it.
        .force(force)
        .tilt_x(0)
        .tilt_y(0)
        .twist(0)
        // tangential pressure is a pen axis; a mouse always reports 0
        .tangential_pressure(0.0);
    if let Some(btn) = btn {
        b = b.button(btn);
    }
    if clicks > 0 {
        b = b.click_count(clicks);
    }
    if let Some((dx, dy)) = delta {
        b = b.delta_x(dx).delta_y(dy);
    }
    match b.build() {
        Ok(params) => {
            matches!(
                tokio::time::timeout(CDP_IN, page.execute(params)).await,
                Ok(Ok(_))
            )
        }
        Err(_) => false,
    }
}

async fn mouse_move(page: &chromiumoxide::Page, p: Pt, rng: &mut SmallRng) -> bool {
    // a device never reports the exact same coordinate twice in a row; add
    // sub-pixel jitter so the trace is not grid-quantised
    let j = Pt::new(
        p.x + rng.gen_range(-0.35..0.35),
        p.y + rng.gen_range(-0.35..0.35),
    );
    mouse_evt(
        page,
        DispatchMouseEventType::MouseMoved,
        j,
        None,
        0,
        0,
        0.0,
        None,
    )
    .await
}

/// Move along a minimum-jerk path sampled IN TIME (constant ~125Hz density),
/// with a lateral arc, endpoint noise, and an overshoot-and-correct tail on
/// long reaches. Duration obeys Fitts' law for the target size.
pub async fn move_to(
    page: &chromiumoxide::Page,
    from: Pt,
    to: Pt,
    target_w: f64,
    rng: &mut SmallRng,
) -> Result<Pt, ()> {
    let dist = from.dist(to);
    if dist < 2.0 {
        return if mouse_move(page, to, rng).await {
            Ok(to)
        } else {
            Err(())
        };
    }
    let total_ms = fitts_ms(dist, target_w, rng);
    // time-based sample count: constant density regardless of speed
    let step_ms = rng.gen_range(SAMPLE_MS.0 as f64..SAMPLE_MS.1 as f64);
    let steps = ((total_ms as f64) / step_ms).round().max(3.0) as usize;

    // ballistic aim: people overshoot on long/fast reaches, then correct.
    // The endpoint of the ballistic phase is biased past the target.
    let (aim, overshoot) = if dist > 130.0 && rng.gen_bool(0.68) {
        let over = (dist * rng.gen_range(0.02..0.09)).clamp(3.0, 26.0);
        let ux = (to.x - from.x) / dist;
        let uy = (to.y - from.y) / dist;
        // the arc bows to the side of the dominant hand
        let lateral = rng.gen_range(-1.0..1.0) * (dist * rng.gen_range(0.03..0.12)).min(40.0);
        (
            Pt::new(to.x + ux * over - uy * lateral, to.y + uy * over + ux * lateral),
            true,
        )
    } else {
        (to, false)
    };

    // ballistic phase: ~78% of the movement time, min-jerk profile
    let ball_steps = if overshoot {
        ((steps as f64) * 0.78).round().max(2.0) as usize
    } else {
        steps
    };
    let mut last = from;
    for s in 1..=ball_steps {
        let t = s as f64 / ball_steps as f64;
        let f = min_jerk(t);
        // hand tremor grows with speed (signal-dependent noise)
        let noise = TREMOR_PX * (1.0 - (2.0 * t - 1.0).abs());
        let p = Pt::new(
            from.x + (aim.x - from.x) * f + gauss(rng) * noise,
            from.y + (aim.y - from.y) * f + gauss(rng) * noise,
        );
        if !mouse_move(page, p, rng).await {
            return Err(());
        }
        last = p;
        tokio::time::sleep(Duration::from_millis(rng.gen_range(SAMPLE_MS.0..SAMPLE_MS.1))).await;
    }

    if overshoot {
        // corrective submovement: slower, shorter, precise, no tremor
        let c_ms = lognorm_ms(rng, (dist * 0.32).clamp(90.0, 420.0), 0.28);
        let c_steps = ((c_ms as f64) / step_ms).round().max(2.0) as usize;
        for s in 1..=c_steps {
            let t = s as f64 / c_steps as f64;
            let f = min_jerk(t);
            let p = Pt::new(last.x + (to.x - last.x) * f, last.y + (to.y - last.y) * f);
            if !mouse_move(page, p, rng).await {
                return Err(());
            }
            tokio::time::sleep(Duration::from_millis(rng.gen_range(SAMPLE_MS.0..SAMPLE_MS.1)))
                .await;
        }
    }
    Ok(to)
}

/// A click where a human lands: gaussian-biased to the centre, never the
/// exact geometric centre, and never outside the box.
pub fn point_in(c: Pt, w: f64, h: f64, rng: &mut SmallRng) -> Pt {
    let sx = (w * 0.20).clamp(1.0, 34.0);
    let sy = (h * 0.20).clamp(1.0, 14.0);
    let dx = (gauss(rng) * sx).clamp(-w * 0.34, w * 0.34);
    let dy = (gauss(rng) * sy).clamp(-h * 0.30, h * 0.30);
    Pt::new(
        (c.x + dx).clamp(1.0, VW - 1.0),
        (c.y + dy).clamp(1.0, VH - 1.0),
    )
}

/// Full click: approach, a settle pause (the moment of aim), press with
/// force=1 and buttons=1, a variable hold during which the hand drifts a
/// fraction of a pixel, then release with buttons=0.
pub async fn click(
    page: &chromiumoxide::Page,
    from: Pt,
    at: Pt,
    target_w: f64,
    rng: &mut SmallRng,
) -> Result<Pt, ()> {
    let mut hand = move_to(page, from, at, target_w, rng).await?;
    // aim/settle before committing
    tokio::time::sleep(Duration::from_millis(lognorm_ms(rng, 105.0, 0.36))).await;

    if !mouse_evt(
        page,
        DispatchMouseEventType::MousePressed,
        hand,
        Some(MouseButton::Left),
        1,
        1,
        1.0,
        None,
    )
    .await
    {
        return Err(());
    }
    // hold: 55-140ms, and the hand is not perfectly rigid during it. The
    // drift moves `hand` itself, because the RELEASE must come from where the
    // hand actually ended up. Recomputing a fresh random point from the
    // press position would teleport the pointer between the last move and
    // the release - physically impossible, and an obvious synthesised trace.
    let hold = lognorm_ms(rng, 76.0, 0.28);
    let drifts = (hold / 40).max(1);
    for _ in 0..drifts {
        tokio::time::sleep(Duration::from_millis((hold / drifts).max(8))).await;
        hand = Pt::new(
            (hand.x + gauss(rng) * 0.7).clamp(1.0, VW - 1.0),
            (hand.y + gauss(rng) * 0.7).clamp(1.0, VH - 1.0),
        );
        mouse_evt(
            page,
            DispatchMouseEventType::MouseMoved,
            hand,
            None,
            1,
            0,
            1.0,
            None,
        )
        .await;
    }
    // release: a finger shifts a fraction of a pixel off the press point
    let rel = Pt::new(
        (hand.x + gauss(rng) * 0.9).clamp(1.0, VW - 1.0),
        (hand.y + gauss(rng) * 0.9).clamp(1.0, VH - 1.0),
    );
    if !mouse_evt(
        page,
        DispatchMouseEventType::MouseReleased,
        rel,
        Some(MouseButton::Left),
        0,
        1,
        0.0,
        None,
    )
    .await
    {
        return Err(());
    }
    Ok(rel)
}

/// Idle micro-motion. A hand resting on a mouse is never still: 8-12Hz
/// drift of 1-3px. A pointer that is perfectly frozen between actions and
/// then jumps to a target is the single easiest bot tell in a movement trace.
pub async fn tremor(page: &chromiumoxide::Page, at: &mut Pt, rng: &mut SmallRng) {
    let n = rng.gen_range(2..5);
    for _ in 0..n {
        let p = Pt::new(
            (at.x + gauss(rng) * TREMOR_PX).clamp(1.0, VW - 1.0),
            (at.y + gauss(rng) * TREMOR_PX).clamp(1.0, VH - 1.0),
        );
        mouse_move(page, p, rng).await;
        *at = p;
        tokio::time::sleep(Duration::from_millis(rng.gen_range(70..140))).await;
    }
}

/// Wheel scroll as a series of notches. Real wheels are detented: a flick is
/// 3-9 discrete notches of ~100px with decaying spacing, not one big delta.
pub async fn wheel(page: &chromiumoxide::Page, at: Pt, notches: i32, rng: &mut SmallRng) -> bool {
    let sign = if notches < 0 { -1.0 } else { 1.0 };
    let n = notches.abs().clamp(1, 12);
    let mut amp = rng.gen_range(90.0..130.0);
    for _ in 0..n {
        let dy = sign * amp;
        if !mouse_evt(
            page,
            DispatchMouseEventType::MouseWheel,
            at,
            None,
            0,
            0,
            0.0,
            Some((0.0, dy)),
        )
        .await
        {
            return false;
        }
        // decay: the flick slows down
        amp *= rng.gen_range(0.62..0.88);
        tokio::time::sleep(Duration::from_millis(lognorm_ms(rng, 55.0, 0.5))).await;
    }
    true
}
