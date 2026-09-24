use std::path::PathBuf;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/proof-collect/collect"));
    match afeye::bctrace::run(&dir) {
        Ok(st) => {
            println!(
                "instructions={} funcs={} live_blocks={} dead_blocks={} live_bytes={} dead_bytes={}",
                st.instructions, st.funcs, st.live_blocks, st.dead_blocks,
                st.live_bytes, st.dead_bytes
            );
            let rep: serde_json::Value = serde_json::from_slice(
                &std::fs::read(dir.join("filtered/bctrace.json"))
                    .expect("bctrace.json"),
            )
            .expect("parse");
            println!("--- api_calls ---");
            for e in rep["api_calls"].as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                println!("{} x{} {:?}", e["what"], e["times"], e["values"]);
            }
            println!("--- functions ---");
            for f in rep["functions"].as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                println!(
                    "{} line={} bc_len={} instrs={} exec={} live={} dead={} dead_ranges={}",
                    f["name"], f["line"], f["bc_len"], f["instructions"],
                    f["executions"], f["live_blocks"], f["dead_blocks"],
                    f["dead_ranges"]
                );
            }
        }
        Err(e) => {
            eprintln!("bctrace failed: {e}");
            std::process::exit(1);
        }
    }
}
