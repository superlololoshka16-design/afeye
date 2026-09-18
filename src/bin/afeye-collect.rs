use std::path::PathBuf;

fn main() {
    let raw = std::env::var("AF_RAW_DIR")
        .unwrap_or_else(|_| afeye::collect::DEFAULT_RAW_DIR.to_owned());
    let out = std::env::var("AF_COLLECT_OUT").unwrap_or_else(|_| ".".into());
    let out = PathBuf::from(out).join("collect");
    afeye::collect::run_standalone(&PathBuf::from(raw), &out);
}
