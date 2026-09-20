use crate::ctx::Tunnel;
use std::path::Path;
use tokio::process::Command;

pub fn parse_conf(i: u32, name: &str, raw: &str) -> Result<Tunnel, String> {
    let mut endpoint = String::new();
    let mut pubkey = String::new();
    let mut privkey = String::new();
    let mut addr: Vec<String> = Vec::new();
    let mut dns: Vec<String> = Vec::new();
    let mut section = "";
    for line in raw.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l.starts_with('[') && l.ends_with(']') {
            section = &l[1..l.len() - 1];
            continue;
        }
        let (k, v) = match l.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        match (section, k) {
            ("Interface", "PrivateKey") => privkey = v.to_owned(),
            ("Interface", "Address") => addr.extend(v.split(',').map(|s| s.trim().to_owned())),
            ("Interface", "DNS") => dns.extend(v.split(',').map(|s| s.trim().to_owned())),
            ("Peer", "Endpoint") => endpoint = v.to_owned(),
            ("Peer", "PublicKey") => pubkey = v.to_owned(),
            _ => {}
        }
    }
    if privkey.is_empty() || pubkey.is_empty() || endpoint.is_empty() {
        return Err(format!("conf {name}: missing key fields"));
    }
    let user = format!("fx{i}");
    Ok(Tunnel {
        i,
        name: name.to_owned(),
        user,
        ns: format!("afns{i}"),
        wg_if: format!("afwg{i}"),
        h_if: format!("afvh{i}"),
        n_if: format!("afvn{i}"),
        host_ip: format!("10.77.{i}.1"),
        ns_ip: format!("10.77.{i}.2"),
        port: 9400 + i as u16,
        endpoint,
        pubkey,
        privkey,
        addr,
        dns,
        egress: None,
    })
}

async fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let o = Command::new(cmd)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("{cmd}: {e}"))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        ))
    }
}

pub async fn setup(t: &Tunnel, work: &Path) -> Result<(), String> {
    let nsd = Path::new("/etc/netns").join(&t.ns);
    std::fs::create_dir_all(&nsd).map_err(|e| e.to_string())?;
    let mut res = String::new();
    for d in &t.dns {
        res.push_str("nameserver ");
        res.push_str(d);
        res.push('\n');
    }
    if res.is_empty() {
        res.push_str("nameserver 10.2.0.1\n");
    }
    std::fs::write(nsd.join("resolv.conf"), res).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(work).map_err(|e| e.to_string())?;
    let setconf = work.join(format!("{}.setconf", t.wg_if));
    let mut sc = String::new();
    sc.push_str("[Interface]\nPrivateKey = ");
    sc.push_str(&t.privkey);
    sc.push_str("\n\n[Peer]\nPublicKey = ");
    sc.push_str(&t.pubkey);
    sc.push_str("\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = ");
    sc.push_str(&t.endpoint);
    sc.push_str("\nPersistentKeepalive = 25\n");
    std::fs::write(&setconf, &sc).map_err(|e| e.to_string())?;
    {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        #[cfg(unix)]
        let _ = std::fs::set_permissions(&setconf, std::fs::Permissions::from_mode(0o600));
    }
    let scs = setconf.to_string_lossy().to_string();
    let args: Vec<String> = vec![
        "netns".into(),
        "add".into(),
        t.ns.clone(),
    ];
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run("ip", &refs).await?;
    let seq: Vec<Vec<String>> = vec![
        vec![
            "link".into(),
            "add".into(),
            t.h_if.clone(),
            "type".into(),
            "veth".into(),
            "peer".into(),
            "name".into(),
            t.n_if.clone(),
        ],
        vec![
            "addr".into(),
            "add".into(),
            format!("{}/24", t.host_ip),
            "dev".into(),
            t.h_if.clone(),
        ],
        vec!["link".into(), "set".into(), t.h_if.clone(), "up".into()],
        vec!["link".into(), "set".into(), t.n_if.clone(), "netns".into(), t.ns.clone()],
        vec![
            "netns".into(),
            "exec".into(),
            t.ns.clone(),
            "ip".into(),
            "link".into(),
            "set".into(),
            "lo".into(),
            "up".into(),
        ],
        vec![
            "netns".into(),
            "exec".into(),
            t.ns.clone(),
            "ip".into(),
            "addr".into(),
            "add".into(),
            format!("{}/24", t.ns_ip),
            "dev".into(),
            t.n_if.clone(),
        ],
        vec![
            "netns".into(),
            "exec".into(),
            t.ns.clone(),
            "ip".into(),
            "link".into(),
            "set".into(),
            t.n_if.clone(),
            "up".into(),
        ],
        vec!["link".into(), "add".into(), t.wg_if.clone(), "type".into(), "wireguard".into()],
    ];
    for step in seq {
        let refs: Vec<&str> = step.iter().map(|s| s.as_str()).collect();
        run("ip", &refs).await?;
    }
    run("wg", &["setconf", &t.wg_if, &scs]).await?;
    let _ = std::fs::remove_file(&setconf);
    let mut seq2: Vec<Vec<String>> = vec![
        vec!["link".into(), "set".into(), t.wg_if.clone(), "netns".into(), t.ns.clone()],
    ];
    for a in &t.addr {
        seq2.push(vec![
            "netns".into(),
            "exec".into(),
            t.ns.clone(),
            "ip".into(),
            "addr".into(),
            "add".into(),
            a.clone(),
            "dev".into(),
            t.wg_if.clone(),
        ]);
    }
    seq2.push(vec![
        "netns".into(),
        "exec".into(),
        t.ns.clone(),
        "ip".into(),
        "link".into(),
        "set".into(),
        "dev".into(),
        t.wg_if.clone(),
        "mtu".into(),
        "1420".into(),
        "up".into(),
    ]);
    seq2.push(vec![
        "netns".into(),
        "exec".into(),
        t.ns.clone(),
        "ip".into(),
        "route".into(),
        "add".into(),
        "default".into(),
        "dev".into(),
        t.wg_if.clone(),
    ]);
    let has_v6 = t.addr.iter().any(|a| a.contains(':'));
    if has_v6 {
        seq2.push(vec![
            "netns".into(),
            "exec".into(),
            t.ns.clone(),
            "ip".into(),
            "-6".into(),
            "route".into(),
            "add".into(),
            "default".into(),
            "dev".into(),
            t.wg_if.clone(),
        ]);
    }
    for step in seq2 {
        let refs: Vec<&str> = step.iter().map(|s| s.as_str()).collect();
        run("ip", &refs).await?;
    }
    Ok(())
}

pub async fn teardown(t: &Tunnel) {
    let _ = run("ip", &["netns", "del", &t.ns]).await;
    let _ = run("ip", &["link", "del", &t.h_if]).await;
    let pkill = format!("pkill -KILL -u {}", t.user);
    let _ = Command::new("bash").arg("-c").arg(&pkill).output().await;
}

pub async fn verify(t: &Tunnel) -> Result<String, String> {
    let o = Command::new("ip")
        .args(["netns", "exec", &t.ns, "runuser", "-u", &t.user, "--"])
        .arg("curl")
        .args(["-sS", "--max-time", "15", "https://www.cloudflare.com/cdn-cgi/trace"])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    let out = String::from_utf8_lossy(&o.stdout);
    for line in out.lines() {
        if let Some(ip) = line.strip_prefix("ip=") {
            if !ip.is_empty() {
                return Ok(ip.to_owned());
            }
        }
    }
    Err(format!(
        "egress check failed: {}",
        String::from_utf8_lossy(&o.stderr).trim()
    ))
}

pub async fn runner_ip() -> String {
    match Command::new("curl")
        .args(["-sS", "--max-time", "10", "https://www.cloudflare.com/cdn-cgi/trace"])
        .output()
        .await
    {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout);
            for line in out.lines() {
                if let Some(ip) = line.strip_prefix("ip=") {
                    return ip.to_owned();
                }
            }
            "unknown".into()
        }
        Err(_) => "unknown".into(),
    }
}

pub async fn prep_user_dirs(t: &Tunnel) -> Result<(), String> {
    for d in [format!("/tmp/afeye/p{}", t.i), format!("/tmp/afeye/h{}", t.i)] {
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).map_err(|e| format!("{d}: {e}"))?;
        let c = Command::new("chown")
            .arg(format!("{}:{}", t.user, t.user))
            .arg(&d)
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !c.status.success() {
            return Err(format!("chown {d} failed"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full() {
        let raw = "[Interface]\nPrivateKey = ABC=/\nAddress = 10.2.0.2/32, 2a07::2/128\nDNS = 10.2.0.1, 2a07::1\n\n[Peer]\nPublicKey = XYZ=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 138.199.7.234:51820\nPersistentKeepalive = 25\n";
        let t = parse_conf(3, "nl", raw).unwrap();
        assert_eq!(t.i, 3);
        assert_eq!(t.endpoint, "138.199.7.234:51820");
        assert_eq!(t.privkey, "ABC=/");
        assert_eq!(t.pubkey, "XYZ=");
        assert_eq!(t.addr, vec!["10.2.0.2/32", "2a07::2/128"]);
        assert_eq!(t.dns, vec!["10.2.0.1", "2a07::1"]);
        assert_eq!(t.ns, "afns3");
        assert_eq!(t.user, "fx3");
        assert_eq!(t.port, 9403);
    }

    #[test]
    fn parse_broken() {
        assert!(parse_conf(1, "x", "[Peer]\nPublicKey = A=\n").is_err());
    }
}
