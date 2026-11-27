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
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const AUTH_FILE: &str = "/run/oxitun-auth.txt";
const TUN_WAIT: Duration = Duration::from_secs(90);

fn env_or(key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Primeiro valor não vazio entre `keys`; erro listando todos os nomes.
fn first_env(keys: &[&str]) -> Result<String, String> {
    for key in keys {
        let v = env_or(key, "");
        if !v.is_empty() {
            return Ok(v);
        }
    }
    Err(format!("{} required", keys.join(" or ")))
}

/// `docker --env-file` mantém aspas literais; a interpolação do compose as remove.
fn strip_quotes(s: &str) -> String {
    let t = s.trim();
    let t = t.strip_prefix('"').unwrap_or(t);
    let t = t.strip_prefix('\'').unwrap_or(t);
    let t = t.strip_suffix('"').unwrap_or(t);
    t.strip_suffix('\'').unwrap_or(t).to_string()
}

/// Killswitch ligado por padrão; desliga apenas com valores explícitos.
fn killswitch_enabled(raw: &str) -> bool {
    !matches!(
        raw.trim().to_lowercase().as_str(),
        "off" | "0" | "false" | "no" | "n" | "disabled"
    )
}

/// Registra mensagem em stderr com timestamp (segundos UNIX).
fn log(msg: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!("[oxitun {ts}] {msg}");
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

/// Aplica o mesmo comando a iptables (IPv4) e ip6tables (IPv6).
fn both(args: &[&str]) -> Result<(), String> {
    for tbl in ["iptables", "ip6tables"] {
        run(tbl, args)?;
    }
    Ok(())
}

/// IPs remotos do .ovpn. Necessários na allowlist porque a conexão VPN
/// precisa passar antes de tun0 existir.
fn remote_ips(profile: &Path) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(profile)
        .map_err(|e| format!("read {}: {e}", profile.display()))?;
    let mut ips: Vec<String> = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some("remote") {
            if let Some(ip) = it.next() {
                if !ips.iter().any(|x| x == ip) {
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

/// Política DROP antes do flush: a janela ACCEPT durante a limpeza é fechada.
fn apply_base_policy() -> Result<(), String> {
    both(&["-P", "INPUT", "DROP"])?;
    both(&["-P", "FORWARD", "DROP"])?;
    both(&["-P", "OUTPUT", "DROP"])?;
    both(&["-F"])?;
    run("iptables", &["-t", "nat", "-F"])?;
    run("iptables", &["-t", "mangle", "-F"])?;
    Ok(())
}

fn install_killswitch(profile: &Path, proxy_port: u16) -> Result<(), String> {
    let servers = remote_ips(profile)?;
    log(&format!("killswitch on — VPN servers: {}", servers.join(" ")));
    apply_base_policy()?;

    let port = proxy_port.to_string();

    // INPUT: loopback, túnel, respostas estabelecidas, proxy na eth0.
    both(&["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])?;
    both(&["-A", "INPUT", "-i", "tun0", "-j", "ACCEPT"])?;
    both(&["-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;
    run("iptables", &[
        "-A", "INPUT", "-i", "eth0", "-p", "tcp", "--dport", port.as_str(), "-j", "ACCEPT",
    ])?;
    run("iptables", &[
        "-A", "INPUT", "-i", "eth0", "-p", "udp", "--dport", port.as_str(), "-j", "ACCEPT",
    ])?;

    // OUTPUT: loopback, túnel, respostas estabelecidas, servidores VPN (IPv4).
    both(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;
    both(&["-A", "OUTPUT", "-o", "tun0", "-j", "ACCEPT"])?;
    both(&["-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;
    for ip in &servers {
        run("iptables", &["-A", "OUTPUT", "-d", ip.as_str(), "-j", "ACCEPT"])?;
    }
    Ok(())
}

/// Escreve o resolver do túnel. Falha não é fatal: com o killswitch ativo,
/// o DNS do host fica bloqueado, então a resolução falha fechada.
fn write_resolv_conf(dns: &str) {
    if let Err(e) = fs::write("/etc/resolv.conf", format!("nameserver {dns}\n")) {
        log(&format!("aviso: /etc/resolv.conf não gravado ({e}); DNS só via túnel se o runtime permitir"));
    }
}

/// Grava credenciais com modo 0600 já na criação, sem janela de permissão ampla.
fn write_auth_file(user: &str, pass: &str) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(AUTH_FILE)
        .map_err(|e| format!("{AUTH_FILE}: {e}"))?;
    f.write_all(format!("{user}\n{pass}\n").as_bytes())
        .map_err(|e| format!("{AUTH_FILE}: {e}"))
}

/// Aguarda tun0 até `TUN_WAIT`, abortando se o openvpn já tiver morrido.
fn wait_for_tun0(child: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + TUN_WAIT;
    loop {
        if proxy::tun0_up() {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("openvpn exited before tun0: {status}"));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err(format!("tun0 did not come up in {}s", TUN_WAIT.as_secs()));
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn main() {
    match run_inner() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("[oxitun] FATAL: {e}");
            std::process::exit(1);
        }
    }
}

fn run_inner() -> Result<i32, String> {
    let profile = env_or("VPN_PROFILE", "/etc/openvpn/client.ovpn");
    let profile_path = Path::new(&profile);
    let proxy_port: u16 = env_or("PROXY_PORT", "8888")
        .parse()
        .map_err(|_| "PROXY_PORT must be a valid port".to_string())?;
    let vpn_dns = env_or("VPN_DNS", "10.2.0.1");
    let killswitch = killswitch_enabled(&env_or("KILLSWITCH", "on"));

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
    write_resolv_conf(&vpn_dns);
    write_auth_file(&user, &pass)?;

    log(&format!("starting openvpn ({profile})"));
    let mut child = Command::new("openvpn")
        .arg("--config")
        .arg(profile_path)
        .arg("--auth-user-pass")
        .arg(AUTH_FILE)
        .arg("--connect-retry")
        .arg("5")
        // Após algumas rodadas falhas, passa para o próximo `remote`
        // em vez de insistir em um servidor morto (free tier instável).
        .arg("--connect-retry-max")
        .arg("3")
        .arg("--connect-timeout")
        .arg("10")
        // Janela de handshake TLS (padrão 60 s): falha rápida se o servidor
        // não responder ao push, sem travar o túnel indefinidamente.
        .arg("--hand-window")
        .arg("20")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn openvpn: {e}"))?;

    wait_for_tun0(&mut child)?;
    log("tun0 up — tunnel established");

    // Proxy CONNECT em thread própria; a main supervisiona o openvpn.
    thread::spawn(move || {
        if let Err(e) = proxy::serve(proxy_port) {
            eprintln!("[oxitun] proxy fatal: {e}");
            std::process::exit(1);
        }
    });
    thread::sleep(Duration::from_millis(300));
    log(&format!("proxy listening on :{proxy_port}"));

    let status = child.wait().map_err(|e| format!("wait openvpn: {e}"))?;
    log(&format!("openvpn exited ({status}) — container will restart"));
    Ok(status.code().unwrap_or(1))
}
