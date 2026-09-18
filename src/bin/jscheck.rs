use std::fs;
use std::process::Command;

fn extract_src(inject_rs: &str) -> String {
    let start = inject_rs.find("r#\"").unwrap() + 3;
    let end = inject_rs[start..].find("\"#;").unwrap() + start;
    inject_rs[start..end].to_string()
}

fn main() {
    let path = format!("{}/src/inject.rs", env!("CARGO_MANIFEST_DIR"));
    let raw = fs::read_to_string(&path).expect("inject.rs");
    let src = extract_src(&raw);
    let js = src.replace("__B__", "_k42z").replace("__G__", "1");
    let tmp = std::env::temp_dir().join("afeye_inject_check.js");
    fs::write(&tmp, &js).unwrap();
    let out = Command::new("node").arg("--check").arg(&tmp).output().unwrap();
    if out.status.success() {
        println!("SYNTAX OK ({} bytes)", js.len());
    } else {
        println!("SYNTAX FAIL:\n{}", String::from_utf8_lossy(&out.stderr));
        std::process::exit(1);
    }
}
