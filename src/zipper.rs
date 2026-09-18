use std::fs::File;
use std::io::copy;
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::CompressionMethod;

pub fn pack(stage: &Path, out: &Path) -> Result<u64, String> {
    if !stage.exists() {
        return Err("stage dir missing".into());
    }
    if let Some(d) = out.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let mut files: Vec<PathBuf> = Vec::new();
    collect(stage, &mut files)?;
    files.sort();
    let f = File::create(out).map_err(|e| e.to_string())?;
    let mut w = zip::ZipWriter::new(f);
    let opt = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(9))
        .unix_permissions(0o644)
        .large_file(true);
    for p in &files {
        let rel = p.strip_prefix(stage).map_err(|e| e.to_string())?;
        let name = rel.to_string_lossy().replace('\\', "/");
        if name.is_empty() {
            continue;
        }
        let meta = std::fs::metadata(p).map_err(|e| e.to_string())?;
        if meta.is_dir() {
            w.add_directory(name.clone(), opt.unix_permissions(0o755)).map_err(|e| e.to_string())?;
            continue;
        }
        w.start_file(name, opt).map_err(|e| e.to_string())?;
        let mut f2 = File::open(p).map_err(|e| e.to_string())?;
        copy(&mut f2, &mut w).map_err(|e| e.to_string())?;
    }
    w.finish().map_err(|e| e.to_string())?;
    let n = files.iter().filter(|p| p.is_file()).count() as u64;
    Ok(n)
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
    let mut items: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    items.sort();
    for p in items {
        if p.is_dir() {
            out.push(p.clone());
            collect(&p, out)?;
        } else {
            out.push(p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn zip_roundtrip() {
        let d = std::env::temp_dir().join("afeye-ziptest");
        let _ = std::fs::remove_dir_all(&d);
        let sub = d.join("sites").join("example.com").join("tunnels").join("1.2.3.4_51820").join("09.15.2026_10.30-11.00");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("timeline.jsonl"), "{\"k\":1,\"d\":{}}\n").unwrap();
        std::fs::create_dir_all(d.join("artifacts")).unwrap();
        std::fs::write(d.join("artifacts").join("aabb.js"), b"var x=1;").unwrap();
        let out = std::env::temp_dir().join("afeye-ziptest.zip");
        let n = pack(&d, &out).unwrap();
        assert_eq!(n, 2);
        let f = File::open(&out).unwrap();
        let mut z = zip::ZipArchive::new(f).unwrap();
        assert_eq!(
            z.by_name("artifacts/aabb.js").unwrap().compression(),
            zip::CompressionMethod::Deflated
        );
        let mut s = String::new();
        z.by_name("artifacts/aabb.js").unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "var x=1;");
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_file(&out);
    }
}
