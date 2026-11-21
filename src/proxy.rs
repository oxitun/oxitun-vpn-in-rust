//! Minimal HTTP CONNECT proxy + /healthz endpoint.
//!
//! Workers only need `CONNECT host:443` for HTTPS tunneling; plain-HTTP
//! forward proxying is intentionally not implemented.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::thread;
use std::time::Duration;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(15);

fn tun0_up() -> bool {
    Path::new("/sys/class/net/tun0").exists()
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
}

/// Read until the header terminator `\r\n\r\n` (bounded). Returns raw bytes.
fn read_headers(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(HEADER_TIMEOUT))?;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() >= MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof before headers complete",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn handle_client(mut client: TcpStream) {
    let _ = client.set_nodelay(true);
    let headers = match read_headers(&mut client) {
        Ok(h) => h,
        Err(_) => return,
    };
    let Ok(head) = std::str::from_utf8(&headers) else {
        return;
    };
    let mut parts = head.split_whitespace();
    let (method, target) = match (parts.next(), parts.next()) {
        (Some(m), Some(t)) => (m, t),
        _ => return,
    };

    // GET /healthz — liveness for Docker HEALTHCHECK; 503 while tun0 is down.
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

    // CONNECT authority: host:port (IPv6 literals unsupported — not needed).
    let Some((host, port)) = target.rsplit_once(':') else {
        respond(&mut client, "400 Bad Request", "bad authority");
        return;
    };
    let Ok(port) = port.parse::<u16>() else {
        respond(&mut client, "400 Bad Request", "bad port");
        return;
    };
    let addr = format!("{host}:{port}");
    let Ok(mut upstream_addrs) = addr.to_socket_addrs() else {
        respond(&mut client, "502 Bad Gateway", "dns failure");
        return;
    };
    let Some(upstream_addr) = upstream_addrs.next() else {
        respond(&mut client, "502 Bad Gateway", "no address");
        return;
    };
    let Ok(upstream) = TcpStream::connect(upstream_addr) else {
        respond(&mut client, "502 Bad Gateway", "connect failed");
        return;
    };
    let _ = upstream.set_nodelay(true);

    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }

    // Bidirectional pipe: client<->upstream. First finisher shuts both down.
    let client2 = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let upstream2 = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };
    let t = thread::spawn(move || {
        let mut r = client2;
        let mut w = upstream2;
        let _ = std::io::copy(&mut r, &mut w);
        let _ = w.shutdown(Shutdown::Both);
    });
    let mut r = upstream;
    let mut w = client;
    let _ = std::io::copy(&mut r, &mut w);
    let _ = w.shutdown(Shutdown::Both);
    let _ = t.join();
}

/// Bind `0.0.0.0:port` and serve forever (one thread per connection).
pub fn serve(port: u16) -> std::io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    eprintln!("[oxitun] CONNECT proxy listening on :{port}");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                thread::spawn(move || handle_client(s));
            }
            Err(e) => eprintln!("[oxitun] accept error: {e}"),
        }
    }
    Ok(())
}
