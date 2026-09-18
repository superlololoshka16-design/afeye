use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use tokio::process::Command;

pub fn have_7z() -> bool {
    for b in ["7z", "7zz", "7za"] {
        if StdCommand::new(b)
            .arg("i")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

pub fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(src).map_err(|e| e.to_string())?;
    if meta.is_file() {
        if let Some(d) = dst.parent() {
            fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        if fs::hard_link(src, dst).is_ok() {
            return Ok(());
        }
        return fs::copy(src, dst).map(|_| ()).map_err(|e| e.to_string());
    }
    if meta.is_dir() {
        fs::create_dir_all(dst).map_err(|e| e.to_string())?;
        let rd = fs::read_dir(src).map_err(|e| e.to_string())?;
        for e in rd.flatten() {
            copy_tree(&e.path(), &dst.join(e.file_name()))?;
        }
        return Ok(());
    }
    Ok(())
}

pub async fn sz_pack(dir: &Path, out: &Path, volume_mb: u64) -> Result<Vec<PathBuf>, String> {
    if !dir.exists() {
        return Err("stage dir missing".into());
    }
    let out_abs = if out.is_absolute() {
        out.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|c| c.join(out))
            .unwrap_or_else(|_| out.to_path_buf())
    };
    for p in glob_volumes(&out_abs) {
        let _ = fs::remove_file(&p);
    }
    let _ = fs::remove_file(&out_abs);
    if let Some(d) = out_abs.parent() {
        fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let bin = pick_7z().ok_or("no 7z binary")?;
    let abs = fs::canonicalize(dir).map_err(|e| e.to_string())?;
    let mut cmd = Command::new("nice");
    cmd.args(["-n", "19"]);
    cmd.arg(bin);
    cmd.args(["a", "-t7z", "-m0=lzma2", "-mx=9", "-md=512m", "-mfb=273", "-ms=on", "-mmt=on"]);
    if volume_mb > 0 {
        cmd.arg(format!("-v{volume_mb}m"));
    }
    cmd.arg(&out_abs);
    cmd.arg(".");
    cmd.current_dir(&abs);
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());
    let outp = cmd.output().await.map_err(|e| e.to_string())?;
    if !outp.status.success() {
        return Err(format!(
            "7z rc={}: {}",
            outp.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&outp.stderr).chars().take(400).collect::<String>()
        ));
    }
    let vols = glob_volumes(&out_abs);
    if vols.is_empty() {
        return Err("7z produced no archive".into());
    }
    Ok(vols)
}

fn pick_7z() -> Option<&'static str> {
    ["7z", "7zz", "7za"].into_iter().find(|b| {
        StdCommand::new(b)
            .arg("i")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

fn glob_volumes(out: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if out.exists() {
        v.push(out.to_path_buf());
    }
    let stem = out.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
    if stem.is_empty() {
        return v;
    }
    if let Some(d) = out.parent() {
        let mut i = 1u32;
        while i < 4096 {
            let p = d.join(format!("{stem}.{i:03}"));
            if p.exists() {
                v.push(p);
            } else {
                break;
            }
            i += 1;
        }
    }
    v.sort();
    v
}

pub fn dir_bytes(p: &Path) -> u64 {
    let mut n = 0u64;
    if let Ok(rd) = fs::read_dir(p) {
        for e in rd.flatten() {
            let ep = e.path();
            if ep.is_dir() {
                n += dir_bytes(&ep);
            } else if let Ok(m) = fs::metadata(&ep) {
                n += m.len();
            }
        }
    }
    n
}

pub async fn curl_post_file(url: &str, fields: &[(&str, &str)], file_field: &str, path: &Path) -> Result<String, String> {
    let mut cmd = Command::new("curl");
    cmd.args(["-sS", "--max-time", "300", "-o", "-"]);
    cmd.arg(url);
    for (k, v) in fields {
        cmd.arg("-F").arg(format!("{k}={v}"));
    }
    cmd.arg("-F").arg(format!("{file_field}=@{}", path.display()));
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    let o = cmd.output().await.map_err(|e| e.to_string())?;
    let s = String::from_utf8_lossy(&o.stdout).to_string();
    if !o.status.success() {
        return Err(format!("curl rc={}", o.status.code().unwrap_or(-1)));
    }
    Ok(s)
}

pub async fn curl_get(url: &str, hdr: Option<&str>, max_secs: u64) -> Result<String, String> {
    let mut cmd = Command::new("curl");
    cmd.args(["-sSL", "--max-time", &max_secs.to_string(), "-o", "-"]);
    cmd.arg(url);
    if let Some(h) = hdr {
        cmd.arg("-H").arg(h);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    let o = cmd.output().await.map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!("curl rc={}", o.status.code().unwrap_or(-1)));
    }
    Ok(String::from_utf8_lossy(&o.stdout).to_string())
}

pub fn write_append(path: &Path, line: &str) -> io::Result<()> {
    use std::io::Write;
    if let Some(d) = path.parent() {
        fs::create_dir_all(d)?;
    }
    let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packs_and_volumes() {
        let d = std::env::temp_dir().join("afeye-arch-test");
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("sites/x")).unwrap();
        fs::write(d.join("sites/x/timeline.jsonl"), "abc\n".repeat(20000)).unwrap();
        let mut blob = Vec::with_capacity(3_000_000);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..3_000_000 {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            blob.push((x >> 24) as u8);
        }
        fs::write(d.join("sites/x/blob.bin"), blob).unwrap();
        let copy = std::env::temp_dir().join("afeye-arch-test-copy");
        let _ = fs::remove_dir_all(&copy);
        copy_tree(&d, &copy).unwrap();
        assert!(copy.join("sites/x/blob.bin").exists());
        assert_eq!(dir_bytes(&copy), dir_bytes(&d));
        if !have_7z() {
            let _ = fs::remove_dir_all(&d);
            let _ = fs::remove_dir_all(&copy);
            return;
        }
        let out = std::env::temp_dir().join("afeye-arch-test.7z");
        let vols = sz_pack(&copy, &out, 0).await.unwrap();
        assert_eq!(vols.len(), 1);
        assert!(out.exists());
        assert!(fs::metadata(&out).unwrap().len() > 1000);
        let _ = fs::remove_file(&out);
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&copy);
    }
}
