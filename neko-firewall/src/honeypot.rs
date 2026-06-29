//! HTTP honeypot / watermark responder.
//!
//! Listens on one or more ports that should never receive legitimate traffic.
//! Every connection is therefore a signal: it is logged, optionally forwarded
//! to a user-defined notification command, and answered with a decoy HTTP page
//! that embeds an encrypted "watermark" token describing the visitor.
//!
//! The token is `NEKO1.<base64url(nonce || ChaCha20-Poly1305(secret, info))>`,
//! so only the holder of the configured secret can decode who triggered it
//! (`nf honeypot decode <token>`), while a scanner / mapping platform only sees
//! opaque noise.

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::HoneypotConfig;

const TOKEN_PREFIX: &str = "NEKO1.";
const READ_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_REQUEST: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VisitorInfo {
    ip: String,
    port: u16,
    ts: u64,
    method: String,
    path: String,
    host: String,
    ua: String,
}

#[derive(Serialize)]
struct HitRecord<'a> {
    #[serde(flatten)]
    visitor: &'a VisitorInfo,
    token: &'a str,
    dst_port: u16,
}

/// Spawn a listener task per configured port. Returns immediately; the tasks
/// run until the process exits.
pub fn serve(cfg: HoneypotConfig) {
    let key = derive_key(&cfg.secret);
    for &port in &cfg.ports {
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = listen(port, cfg, key).await {
                log::error!("[honeypot] listener on :{} stopped: {}", port, e);
            }
        });
    }
}

async fn listen(port: u16, cfg: HoneypotConfig, key: [u8; 32]) -> Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("failed to bind honeypot port {}", port))?;
    log::info!("[honeypot] listening on 0.0.0.0:{}", port);
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, peer, port, &cfg, &key).await {
                        log::debug!("[honeypot] connection from {} error: {}", peer, e);
                    }
                });
            }
            Err(e) => {
                log::warn!("[honeypot] accept on :{} failed: {}", port, e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    dst_port: u16,
    cfg: &HoneypotConfig,
    key: &[u8; 32],
) -> Result<()> {
    // Read whatever the client sends first (may be nothing: a bare port scan).
    let mut buf = vec![0u8; MAX_REQUEST];
    let n = match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    let (method, path, host, ua) = parse_request(&buf[..n]);

    let visitor = VisitorInfo {
        ip: peer.ip().to_string(),
        port: peer.port(),
        ts: now_secs(),
        method,
        path,
        host,
        ua,
    };

    let token = encode_token(key, &visitor)?;
    record_hit(cfg, &visitor, &token, dst_port).await;

    let body = build_body(&token);
    let server = cfg.server_header.as_deref().unwrap_or("nginx");
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Server: {server}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         X-Neko-Tag: {token}\r\n\
         Connection: close\r\n\r\n{body}",
        server = server,
        len = body.len(),
        token = token,
        body = body,
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
    Ok(())
}

fn build_body(token: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"neko-tag\" content=\"{t}\">\
         <title>It works</title></head>\
         <body><h1>It works!</h1>\
         <p>This site is under maintenance.</p>\
         <!-- {t} --></body></html>",
        t = token
    )
}

/// Best-effort parse of the request line and a couple of headers. Returns
/// (method, path, host, user-agent), each truncated to a bounded length.
fn parse_request(buf: &[u8]) -> (String, String, String, String) {
    let text = String::from_utf8_lossy(buf);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = trunc(parts.next().unwrap_or(""), 16);
    let path = trunc(parts.next().unwrap_or(""), 256);

    let mut host = String::new();
    let mut ua = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "host" => host = trunc(value.trim(), 128),
                "user-agent" => ua = trunc(value.trim(), 256),
                _ => {}
            }
        }
    }
    (method, path, host, ua)
}

fn trunc(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn record_hit(cfg: &HoneypotConfig, visitor: &VisitorInfo, token: &str, dst_port: u16) {
    log::warn!(
        "[honeypot] HIT :{} from {}:{} {} {} ua={:?} token={}",
        dst_port,
        visitor.ip,
        visitor.port,
        visitor.method,
        visitor.path,
        visitor.ua,
        token
    );

    let record = HitRecord {
        visitor,
        token,
        dst_port,
    };
    let json = serde_json::to_string(&record).unwrap_or_default();

    if let Err(e) = append_log(&cfg.log_path, &json).await {
        log::warn!("[honeypot] failed to write log {}: {}", cfg.log_path, e);
    }

    if let Some(cmd) = cfg.notify_command.as_deref() {
        fire_notify(cmd, visitor, token, dst_port, &json).await;
    }
}

async fn append_log(path: &str, line: &str) -> Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .with_context(|| format!("open {}", path))?;
    file.write_all(line.as_bytes()).await?;
    file.write_all(b"\n").await?;
    Ok(())
}

/// Run the user-defined notification command via `sh -c`, exposing the visitor
/// fields as environment variables and the full JSON record on stdin. Fully
/// detached: failures never affect the response.
async fn fire_notify(cmd: &str, visitor: &VisitorInfo, token: &str, dst_port: u16, json: &str) {
    let mut command = tokio::process::Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .env("NEKO_HP_IP", &visitor.ip)
        .env("NEKO_HP_PORT", visitor.port.to_string())
        .env("NEKO_HP_DST_PORT", dst_port.to_string())
        .env("NEKO_HP_TS", visitor.ts.to_string())
        .env("NEKO_HP_METHOD", &visitor.method)
        .env("NEKO_HP_PATH", &visitor.path)
        .env("NEKO_HP_HOST", &visitor.host)
        .env("NEKO_HP_UA", &visitor.ua)
        .env("NEKO_HP_TOKEN", token)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    match command.spawn() {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(json.as_bytes()).await;
            }
            // Reap the child so it doesn't become a zombie.
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
        }
        Err(e) => log::warn!("[honeypot] notify command failed to start: {}", e),
    }
}

// ---- watermark crypto -----------------------------------------------------

fn derive_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"neko-honeypot-v1");
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

fn encode_token(key: &[u8; 32], visitor: &VisitorInfo) -> Result<String> {
    let plaintext = serde_json::to_vec(visitor).context("serialize visitor")?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| anyhow!("rng: {}", e))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|_| anyhow!("encrypt failed"))?;
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(format!("{}{}", TOKEN_PREFIX, b64url_encode(&blob)))
}

/// Decode a watermark token back to its JSON visitor record using the secret.
pub fn decode_token(secret: &str, token: &str) -> Result<String> {
    let key = derive_key(secret);
    let body = token
        .trim()
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| anyhow!("not a NEKO1 token"))?;
    let blob = b64url_decode(body)?;
    if blob.len() < 12 + 16 {
        bail!("token too short");
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| anyhow!("decrypt failed (wrong secret or corrupt token)"))?;
    let visitor: VisitorInfo = serde_json::from_slice(&plaintext).context("parse visitor")?;
    serde_json::to_string_pretty(&visitor).context("format visitor")
}

/// Generate a fresh random secret (32 bytes, base64url-encoded).
pub fn generate_secret() -> String {
    let mut raw = [0u8; 32];
    // getrandom only fails on platforms without an RNG; fall back is not needed
    // on Linux, but keep it non-panicking.
    if getrandom::getrandom(&mut raw).is_err() {
        let t = now_secs().to_ne_bytes();
        for (i, b) in raw.iter_mut().enumerate() {
            *b = t[i % t.len()] ^ (i as u8);
        }
    }
    b64url_encode(&raw)
}

// ---- base64url (no padding) ----------------------------------------------

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[(n >> 18) as usize & 0x3f] as char);
        out.push(B64URL[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[n as usize & 0x3f] as char);
        }
    }
    out
}

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    let val = |c: u8| -> Result<u32> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => bail!("invalid base64url character"),
        }
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for &c in chunk {
            n = (n << 6) | val(c)?;
        }
        // Left-align the accumulated bits for short final chunks.
        n <<= 6 * (4 - chunk.len());
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_roundtrip() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let enc = b64url_encode(&data);
            let dec = b64url_decode(&enc).expect("decode");
            assert_eq!(dec, data, "len {}", len);
        }
    }

    #[test]
    fn token_roundtrip() {
        let key = derive_key("hunter2");
        let visitor = VisitorInfo {
            ip: "203.0.113.7".into(),
            port: 54321,
            ts: 1_700_000_000,
            method: "GET".into(),
            path: "/admin".into(),
            host: "example.com".into(),
            ua: "masscan/1.3".into(),
        };
        let token = encode_token(&key, &visitor).expect("encode");
        assert!(token.starts_with(TOKEN_PREFIX));
        let json = decode_token("hunter2", &token).expect("decode");
        assert!(json.contains("203.0.113.7"));
        assert!(json.contains("masscan/1.3"));
        // Wrong secret must fail.
        assert!(decode_token("wrong", &token).is_err());
    }

    #[tokio::test]
    async fn live_request_roundtrip() {
        let log_path = std::env::temp_dir().join("neko-hp-test.jsonl");
        let cfg = HoneypotConfig {
            enabled: true,
            ports: vec![39517],
            secret: "smoke-secret".into(),
            log_path: log_path.to_string_lossy().into_owned(),
            notify_command: None,
            server_header: None,
        };
        serve(cfg);

        // Wait for the listener to bind, then send a request.
        let mut stream = None;
        for _ in 0..50 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", 39517)).await {
                stream = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut s = stream.expect("connect to honeypot");
        s.write_all(b"GET /secret-path HTTP/1.1\r\nHost: victim.example\r\nUser-Agent: zgrab/0.x\r\n\r\n")
            .await
            .unwrap();

        let mut resp = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            match tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                Ok(Ok(n)) => resp.extend_from_slice(&buf[..n]),
            }
        }
        let text = String::from_utf8_lossy(&resp);
        let token_line = text
            .lines()
            .find(|l| l.starts_with("X-Neko-Tag:"))
            .expect("X-Neko-Tag header present");
        let token = token_line.trim_start_matches("X-Neko-Tag:").trim();

        let json = decode_token("smoke-secret", token).expect("decode live token");
        assert!(json.contains("/secret-path"), "json: {}", json);
        assert!(json.contains("zgrab/0.x"), "json: {}", json);
        assert!(json.contains("127.0.0.1"), "json: {}", json);
    }
}
