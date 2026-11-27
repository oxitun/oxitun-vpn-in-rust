//! Proxy de saída na porta única `PROXY_PORT`:
//!   - HTTP CONNECT (TCP) e GET /healthz,
//!   - SOCKS5 CONNECT (TCP),
//!   - SOCKS5 UDP ASSOCIATE (UDP), relay na mesma porta, protocolo UDP.
//!
//! Despacho pelo primeiro byte: 0x05 = SOCKS5, demais = HTTP.

use std::collections::HashMap;
use std::env;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 64;
const MAX_UDP_ASSOC: usize = 64;
const UDP_BUF: usize = 65_535;
const UDP_POLL: Duration = Duration::from_secs(1);

const SOCKS_VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// Verdadeiro quando tun0 existe. Também usado por `main.rs`.
pub fn tun0_up() -> bool {
    Path::new("/sys/class/net/tun0").exists()
}

/// Guarda de conexão TCP: incrementa ao adquirir, decrementa ao soltar.
struct ConnGuard;

impl ConnGuard {
    fn acquire() -> Option<Self> {
        if ACTIVE.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            ACTIVE.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(ConnGuard)
        }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Associação UDP: um socket de saída por cliente e o endereço UDP do cliente.
struct Assoc {
    tcp_peer: IpAddr,
    client: Option<SocketAddr>,
    upstream: Arc<UdpSocket>,
}

/// Estado compartilhado do relay UDP e do registro de associações.
struct Relay {
    sock: UdpSocket,
    port: u16,
    assocs: Mutex<HashMap<u64, Assoc>>,
    next_id: AtomicU64,
}

impl Relay {
    /// Registra associação; `None` se o limite foi atingido.
    fn register(&self, tcp_peer: IpAddr, upstream: Arc<UdpSocket>) -> Option<u64> {
        let mut m = self.assocs.lock().ok()?;
        if m.len() >= MAX_UDP_ASSOC {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        m.insert(id, Assoc { tcp_peer, client: None, upstream });
        Some(id)
    }

    fn unregister(&self, id: u64) {
        if let Ok(mut m) = self.assocs.lock() {
            m.remove(&id);
        }
    }

    fn exists(&self, id: u64) -> bool {
        self.assocs.lock().map(|m| m.contains_key(&id)).unwrap_or(false)
    }

    fn client_of(&self, id: u64) -> Option<SocketAddr> {
        self.assocs.lock().ok().and_then(|m| m.get(&id).and_then(|a| a.client))
    }
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
}

/// Lê até `\r\n\r\n` com prazo total de `HEADER_TIMEOUT`.
fn read_headers(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now() + HEADER_TIMEOUT;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() >= MAX_HEADER_BYTES {
            return Err(Error::new(ErrorKind::InvalidData, "headers too large"));
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| Error::new(ErrorKind::TimedOut, "header deadline"))?;
        stream.set_read_timeout(Some(remaining))?;
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "eof before headers complete"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Extrai host e porta de `host:port` (formato do CONNECT HTTP).
fn parse_connect(target: &str) -> Result<(String, u16), &'static str> {
    let (host, port) = target.rsplit_once(':').ok_or("bad authority")?;
    if host.is_empty() {
        return Err("bad authority");
    }
    let port = port.parse::<u16>().map_err(|_| "bad port")?;
    Ok((host.to_string(), port))
}

/// Monta `host:port`, colocando IPv6 entre colchetes.
fn join_target(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Resolve e conecta ao upstream TCP. Erro retorna (status HTTP, mensagem).
fn open_upstream(host: &str, port: u16) -> Result<TcpStream, (&'static str, &'static str)> {
    let mut addrs = join_target(host, port)
        .to_socket_addrs()
        .map_err(|_| ("502 Bad Gateway", "dns failure"))?;
    let target = addrs.next().ok_or(("502 Bad Gateway", "no address"))?;
    let stream = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT)
        .map_err(|_| ("502 Bad Gateway", "connect failed"))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Pipe bidirecional TCP. O primeiro lado a terminar encerra os dois.
fn pipe(client: TcpStream, upstream: TcpStream) {
    let (Ok(mut client_r), Ok(mut upstream_w)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let t = thread::spawn(move || {
        let _ = std::io::copy(&mut client_r, &mut upstream_w);
        let _ = upstream_w.shutdown(Shutdown::Both);
    });

    let mut upstream_r = upstream;
    let mut client_w = client;
    let _ = std::io::copy(&mut upstream_r, &mut client_w);
    let _ = client_w.shutdown(Shutdown::Both);
    let _ = t.join();
}

// ── SOCKS5 ─────────────────────────────────────────────────────

fn unspecified() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 0))
}

/// Lê endereço SOCKS (ATYP já consumido). Retorna (host, porta).
fn read_socks_addr<R: Read>(r: &mut R, atyp: u8) -> std::io::Result<(String, u16)> {
    let host = match atyp {
        ATYP_V4 => {
            let mut a = [0u8; 4];
            r.read_exact(&mut a)?;
            Ipv4Addr::from(a).to_string()
        }
        ATYP_V6 => {
            let mut a = [0u8; 16];
            r.read_exact(&mut a)?;
            Ipv6Addr::from(a).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len)?;
            let mut d = vec![0u8; len[0] as usize];
            r.read_exact(&mut d)?;
            String::from_utf8(d).map_err(|_| Error::new(ErrorKind::InvalidData, "domain utf8"))?
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, "bad atyp")),
    };
    let mut p = [0u8; 2];
    r.read_exact(&mut p)?;
    Ok((host, u16::from_be_bytes(p)))
}

/// Codifica endereço no formato SOCKS (ATYP + endereço + porta).
fn encode_socks_addr(a: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    match a.ip() {
        IpAddr::V4(ip) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&a.port().to_be_bytes());
    out
}

/// Resposta SOCKS: VER REP RSV + BND.ADDR/BND.PORT.
fn socks_reply(client: &mut TcpStream, rep: u8, bnd: SocketAddr) {
    let mut out = vec![SOCKS_VER, rep, 0x00];
    out.extend(encode_socks_addr(bnd));
    let _ = client.write_all(&out);
}

/// Handshake SOCKS5 e despacho por comando.
fn handle_socks(mut client: TcpStream, relay: Arc<Relay>) {
    let mut hdr = [0u8; 2];
    if client.read_exact(&mut hdr).is_err() || hdr[0] != SOCKS_VER {
        return;
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    if client.read_exact(&mut methods).is_err() {
        return;
    }
    if !methods.contains(&0x00) {
        let _ = client.write_all(&[SOCKS_VER, 0xFF]);
        return;
    }
    if client.write_all(&[SOCKS_VER, 0x00]).is_err() {
        return;
    }

    let mut req = [0u8; 4];
    if client.read_exact(&mut req).is_err() || req[0] != SOCKS_VER {
        return;
    }
    let cmd = req[1];
    let Ok((host, port)) = read_socks_addr(&mut client, req[3]) else {
        socks_reply(&mut client, 0x08, unspecified());
        return;
    };

    match cmd {
        CMD_CONNECT => socks_connect(client, &host, port),
        CMD_UDP_ASSOCIATE => socks_udp_associate(client, relay),
        _ => socks_reply(&mut client, 0x07, unspecified()),
    }
}

fn socks_connect(mut client: TcpStream, host: &str, port: u16) {
    let upstream = match open_upstream(host, port) {
        Ok(s) => s,
        Err(_) => {
            socks_reply(&mut client, 0x04, unspecified());
            return;
        }
    };
    socks_reply(&mut client, 0x00, unspecified());
    let _ = client.set_read_timeout(None);
    pipe(client, upstream);
}

/// UDP ASSOCIATE: a associação vive enquanto o controle TCP estiver aberto.
fn socks_udp_associate(mut client: TcpStream, relay: Arc<Relay>) {
    let (Ok(peer), Ok(local)) = (client.peer_addr(), client.local_addr()) else {
        return;
    };
    let upstream = match UdpSocket::bind(("0.0.0.0", 0)) {
        Ok(s) => Arc::new(s),
        Err(_) => {
            socks_reply(&mut client, 0x01, unspecified());
            return;
        }
    };
    let _ = upstream.set_read_timeout(Some(UDP_POLL));

    let Some(id) = relay.register(peer.ip(), Arc::clone(&upstream)) else {
        socks_reply(&mut client, 0x02, unspecified());
        return;
    };

    socks_reply(&mut client, 0x00, SocketAddr::new(local.ip(), relay.port));

    let r = Arc::clone(&relay);
    thread::spawn(move || upstream_pump(r, id, upstream));

    // Mantém a associação viva até o cliente fechar o controle TCP.
    let _ = client.set_read_timeout(None);
    let mut sink = [0u8; 256];
    while matches!(client.read(&mut sink), Ok(n) if n > 0) {}
    relay.unregister(id);
}

/// Extrai destino de um datagrama SOCKS UDP: RSV RSV FRAG ATYP DST.ADDR DST.PORT DATA.
/// Retorna (`host:port`, deslocamento do payload). FRAG != 0 não é suportado.
fn parse_udp_header(pkt: &[u8]) -> Option<(String, usize)> {
    if pkt.len() < 4 || pkt[2] != 0 {
        return None;
    }
    let atyp = pkt[3];
    let mut cur = &pkt[4..];
    let (host, port) = read_socks_addr(&mut cur, atyp).ok()?;
    let off = pkt.len() - cur.len();
    Some((join_target(&host, port), off))
}

/// Encaminha datagramas do cliente ao upstream. Aprende o endereço UDP do
/// cliente no primeiro datagrama vindo do IP que abriu o controle TCP.
fn route_client_datagram(relay: &Relay, from: SocketAddr, pkt: &[u8]) -> Option<(Arc<UdpSocket>, String, usize)> {
    let mut m = relay.assocs.lock().ok()?;
    let id = match m.iter().find(|(_, a)| a.client == Some(from)).map(|(id, _)| *id) {
        Some(id) => id,
        None => {
            let id = m
                .iter()
                .find(|(_, a)| a.client.is_none() && a.tcp_peer == from.ip())
                .map(|(id, _)| *id)?;
            m.get_mut(&id)?.client = Some(from);
            id
        }
    };
    let upstream = Arc::clone(&m.get(&id)?.upstream);
    drop(m);
    let (dst, off) = parse_udp_header(pkt)?;
    Some((upstream, dst, off))
}

/// Loop do relay: lê o socket UDP compartilhado e envia ao upstream da associação.
fn udp_loop(relay: Arc<Relay>) {
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let Ok((n, from)) = relay.sock.recv_from(&mut buf) else {
            continue;
        };
        if let Some((upstream, dst, off)) = route_client_datagram(&relay, from, &buf[..n]) {
            let _ = upstream.send_to(&buf[off..n], dst.as_str());
        }
    }
}

/// Recebe respostas do upstream de uma associação e devolve ao cliente com cabeçalho SOCKS.
fn upstream_pump(relay: Arc<Relay>, id: u64, upstream: Arc<UdpSocket>) {
    let mut buf = vec![0u8; UDP_BUF];
    while relay.exists(id) {
        // Timeout de polling: reavalia a existência da associação.
        if let Ok((n, src)) = upstream.recv_from(&mut buf) {
            if let Some(client) = relay.client_of(id) {
                let mut out = vec![0u8, 0, 0];
                out.extend(encode_socks_addr(src));
                out.extend_from_slice(&buf[..n]);
                let _ = relay.sock.send_to(&out, client);
            }
        }
    }
}

// ── Entrada ────────────────────────────────────────────────────

fn handle_client(mut client: TcpStream, relay: Arc<Relay>) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(HEADER_TIMEOUT));
    let mut first = [0u8; 1];
    if !matches!(client.peek(&mut first), Ok(1)) {
        return;
    }
    if first[0] == SOCKS_VER {
        return handle_socks(client, relay);
    }

    let Ok(headers) = read_headers(&mut client) else {
        return;
    };
    let Ok(head) = std::str::from_utf8(&headers) else {
        return;
    };
    let mut parts = head.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return;
    };

    // GET /healthz: liveness para HEALTHCHECK do Docker; 503 com tun0 fora.
    if method == "GET" && target == "/healthz" {
        if tun0_up() {
            respond(&mut client, "200 OK", "ok");
        } else {
            respond(&mut client, "503 Service Unavailable", "tun0 down");
        }
        return;
    }

    if method != "CONNECT" {
        respond(&mut client, "405 Method Not Allowed", "CONNECT only");
        return;
    }

    let (host, port) = match parse_connect(target) {
        Ok(v) => v,
        Err(msg) => {
            respond(&mut client, "400 Bad Request", msg);
            return;
        }
    };
    let upstream = match open_upstream(&host, port) {
        Ok(s) => s,
        Err((status, msg)) => {
            respond(&mut client, status, msg);
            return;
        }
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }

    // Remove o timeout de cabeçalho antes do pipe; senão conexões ociosas caem.
    let _ = client.set_read_timeout(None);
    pipe(client, upstream);
}

/// Escuta TCP e UDP em `port` (mesmo número, protocolos distintos).
/// `UDP_ADVERTISE_PORT` sobrescreve a porta anunciada no BND de UDP
/// ASSOCIATE — necessária quando o Docker publica a porta em outra
/// (ex.: 127.0.0.1:18011:8888/udp → anunciar 18011).
pub fn serve(port: u16) -> std::io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    let sock = UdpSocket::bind(("0.0.0.0", port))?;
    let advertise = env::var("UDP_ADVERTISE_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(port);
    let relay = Arc::new(Relay {
        sock,
        port: advertise,
        assocs: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
    });

    let r = Arc::clone(&relay);
    thread::spawn(move || udp_loop(r));

    eprintln!("[oxitun] proxy listening on :{port} (TCP: HTTP CONNECT + SOCKS5; UDP: SOCKS5 UDP ASSOCIATE)");
    for stream in listener.incoming() {
        let mut s = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[oxitun] accept error: {e}");
                continue;
            }
        };
        match ConnGuard::acquire() {
            Some(guard) => {
                let r = Arc::clone(&relay);
                thread::spawn(move || {
                    handle_client(s, r);
                    drop(guard);
                });
            }
            None => respond(&mut s, "503 Service Unavailable", "too many connections"),
        }
    }
    Ok(())
}
