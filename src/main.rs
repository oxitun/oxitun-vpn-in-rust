//! oxitun — minimal OpenVPN tunnel container.
//!
//! One process does everything gluetun does for this use case:
//!   1. installs a killswitch firewall (iptables) so traffic can only leave
//!      via tun0 or the VPN server itself,
//!   2. pins DNS to the tunnel resolver,
//!   3. spawns `openvpn` with the given profile,
//!   4. waits for tun0, then serves an HTTP CONNECT proxy,
//!   5. exits when openvpn dies → container restart policy takes over.

mod proxy;

use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn env_or(key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// First non-empty value among `keys`, erroring with all names listed.
fn first_env(keys: &[&str]) -> Result<String, String> {
    for key in keys {
        let v = env_or(key, "");
        if !v.is_empty() {
            return Ok(v);
        }
    }
    Err(format!("{} required", keys.join(" or ")))
}

/// `docker --env-file` keeps literal quotes; compose interpolation strips
/// them. Normalize both forms.
fn strip_quotes(s: &str) -> String {
    let t = s.trim();
    let t = t.strip_prefix('"').unwrap_or(t);
    let t = t.strip_prefix('\'').unwrap_or(t);
    let t = t.strip_suffix('"').unwrap_or(t);
    t.strip_suffix('\'').unwrap_or(t).to_string()
}

fn log(msg: &str) {
    eprintln!("[oxitun] {msg}");
}

fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{cmd} {} failed: {status}", args.join(" ")))
    }
}

/// Remote IPs declared in the .ovpn profile (needed for the killswitch
/// allowlist: the VPN connection itself must pass before tun0 exists).
fn remote_ips(profile: &Path) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(profile)
        .map_err(|e| format!("read {}: {e}", profile.display()))?;
    let mut ips = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some("remote") {
            if let Some(ip) = it.next() {
                if !ips.contains(&ip.to_string()) {
                    ips.push(ip.to_string());
                }
            }
        }
    }
    if ips.is_empty() {
        return Err(format!("no 'remote' directive in {}", profile.display()));
    }
    Ok(ips)
}

fn iptables_flush() -> Result<(), String> {
    // ip6tables has no usable nat/mangle in this context — filter only.
    for tbl in ["iptables", "ip6tables"] {
        run(tbl, &["-F"])?;
    }
    run("iptables", &["-t", "nat", "-F"])?;
    run("iptables", &["-t", "mangle", "-F"])?;
    Ok(())
}

fn iptables_policy() -> Result<(), String> {
    for tbl in ["iptables", "ip6tables"] {
        run(tbl, &["-P", "INPUT", "DROP"])?;
        run(tbl, &["-P", "FORWARD", "DROP"])?;
        run(tbl, &["-P", "OUTPUT", "DROP"])?;
    }
    Ok(())
}

fn iptables_rule(tbl: &str, args: &[&str]) -> Result<(), String> {
    run(tbl, args)
}

fn install_killswitch(profile: &Path, proxy_port: u16) -> Result<(), String> {
    let servers = remote_ips(profile)?;
    log(&format!("killswitch on — VPN servers: {}", servers.join(" ")));

    iptables_flush()?;
    iptables_policy()?;

    // INPUT: local, tunnel, established replies, proxy port on eth0.
    for tbl in ["iptables", "ip6tables"] {
        iptables_rule(tbl, &["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])?;
        iptables_rule(tbl, &["-A", "INPUT", "-i", "tun0", "-j", "ACCEPT"])?;
        iptables_rule(tbl, &[
            "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT",
        ])?;
    }
    iptables_rule("iptables", &[
        "-A", "INPUT", "-i", "eth0", "-p", "tcp", "--dport", &proxy_port.to_string(), "-j",
        "ACCEPT",
    ])?;

    // OUTPUT: local, tunnel, established, VPN servers (any port, IPv4 only).
    for tbl in ["iptables", "ip6tables"] {
        iptables_rule(tbl, &["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;
        iptables_rule(tbl, &["-A", "OUTPUT", "-o", "tun0", "-j", "ACCEPT"])?;
        iptables_rule(tbl, &[
            "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT",
        ])?;
    }
    for ip in &servers {
        iptables_rule("iptables", &["-A", "OUTPUT", "-d", ip, "-j", "ACCEPT"])?;
    }
    Ok(())
}

fn write_resolv_conf(dns: &str) -> Result<(), String> {
    fs::write("/etc/resolv.conf", format!("nameserver {dns}\n"))
        .map_err(|e| format!("/etc/resolv.conf: {e}"))
}

fn write_auth_file(user: &str, pass: &str) -> Result<String, String> {
    let path = "/run/oxitun-auth.txt";
    fs::write(path, format!("{user}\n{pass}\n")).map_err(|e| format!("{path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(path.to_string())
}

fn tun0_exists() -> bool {
    Path::new("/sys/class/net/tun0").exists()
}

fn main() {
    if let Err(e) = run_inner() {
        eprintln!("[oxitun] FATAL: {e}");
        std::process::exit(1);
    }
}

fn run_inner() -> Result<i32, String> {
    // VPN_PROFILE > default. Credentials are the provider-agnostic
    // VPN_USER / VPN_PASS.
    let profile = env_or("VPN_PROFILE", "/etc/openvpn/client.ovpn");
    let profile_path = Path::new(&profile);
    let proxy_port: u16 = env_or("PROXY_PORT", "8888")
        .parse()
        .map_err(|_| "PROXY_PORT must be a valid port".to_string())?;
    let vpn_dns = env_or("VPN_DNS", "10.2.0.1");
    let killswitch = !matches!(env_or("KILLSWITCH", "on").to_lowercase().as_str(), "off" | "0" | "false" | "no");

    let user = strip_quotes(&first_env(&["VPN_USER"])?);
    let pass = strip_quotes(&first_env(&["VPN_PASS"])?);
    if user.is_empty() || pass.is_empty() {
        return Err("VPN_USER/VPN_PASS empty after unquoting".into());
    }

    if killswitch {
        install_killswitch(profile_path, proxy_port)?;
    } else {
        log("killswitch disabled (KILLSWITCH=off)");
    }
    write_resolv_conf(&vpn_dns)?;
    let auth_file = write_auth_file(&user, &pass)?;

    log(&format!("starting openvpn ({profile})"));
    let mut child = Command::new("openvpn")
        .arg("--config")
        .arg(profile_path)
        .arg("--auth-user-pass")
        .arg(&auth_file)
        .arg("--connect-retry")
        .arg("5")
        // Move to the next `remote` after a few failed rounds instead of
        // retrying a dead server forever (free-tier flakiness).
        .arg("--connect-retry-max")
        .arg("3")
        .arg("--connect-timeout")
        .arg("10")
        // TLS handshake stall guard: a TCP connection that opens but never
        // answers the push must not hang the tunnel indefinitely.
        .arg("--hand-window")
        .arg("20")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn openvpn: {e}"))?;

    // Wait for tun0 (90s), bailing early if openvpn already died.
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if tun0_exists() {
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("openvpn exited before tun0: {status}"));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err("tun0 did not come up in 90s".into());
        }
        thread::sleep(Duration::from_millis(500));
    }
    log("tun0 up — tunnel established");

    // CONNECT proxy on its own thread; main supervises openvpn.
    thread::spawn(move || {
        if let Err(e) = proxy::serve(proxy_port) {
            eprintln!("[oxitun] proxy fatal: {e}");
            std::process::exit(1);
        }
    });
    // Give the listener a moment to bind before reporting healthy.
    thread::sleep(Duration::from_millis(300));
    log(&format!("proxy listening on :{proxy_port}"));

    let status = child.wait().map_err(|e| format!("wait openvpn: {e}"))?;
    log(&format!("openvpn exited ({status}) — container will restart"));
    Ok(status.code().unwrap_or(1))
}
