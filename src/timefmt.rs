pub struct Stamp {
    pub y: i64,
    pub mo: u32,
    pub d: u32,
    pub h: u32,
    pub mi: u32,
    pub s: u32,
}

pub fn stamp(ms: u64) -> Stamp {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, mo, d) = civil_from_days(days);
    Stamp {
        y,
        mo,
        d,
        h: (rem / 3600) as u32,
        mi: ((rem % 3600) / 60) as u32,
        s: (rem % 60) as u32,
    }
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn slot(ms: u64, span_min: u32) -> String {
    let a = stamp(ms);
    let end = ms + span_min as u64 * 60_000;
    let b = stamp(end);
    format!(
        "{:02}.{:02}.{:04}_{:02}.{:02}-{:02}.{:02}",
        a.mo, a.d, a.y, a.h, a.mi, b.h, b.mi
    )
}

pub fn run_id(ms: u64) -> String {
    let a = stamp(ms);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        a.y, a.mo, a.d, a.h, a.mi, a.s
    )
}

pub fn zip_stem(ms: u64) -> String {
    let a = stamp(ms);
    format!(
        "afeye-{:04}{:02}{:02}-{:02}{:02}{:02}",
        a.y, a.mo, a.d, a.h, a.mi, a.s
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch() {
        let z = stamp(0);
        assert_eq!((z.y, z.mo, z.d), (1970, 1, 1));
        assert_eq!((z.h, z.mi), (0, 0));
    }

    #[test]
    fn y2k() {
        let z = stamp(946_684_800_000);
        assert_eq!((z.y, z.mo, z.d), (2000, 1, 1));
    }

    #[test]
    fn leap() {
        let z = stamp(1_709_164_800_000);
        assert_eq!((z.y, z.mo, z.d), (2024, 2, 29));
    }

    #[test]
    fn midday() {
        let z = stamp(1_709_208_000_000);
        assert_eq!((z.h, z.mi, z.s), (12, 0, 0));
    }

    #[test]
    fn slot_fmt() {
        assert_eq!(slot(946_684_800_000, 30), "01.01.2000_00.00-00.30");
        assert_eq!(zip_stem(946_684_800_000), "afeye-20000101-000000");
    }
}
