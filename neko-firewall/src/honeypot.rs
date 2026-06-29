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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};

use crate::config::HoneypotConfig;

const TOKEN_PREFIX: &str = "NEKO1.";
const READ_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_REQUEST: usize = 4096;

/// Byte-exact copy of nginx's default `index.html` (docs/html/index.html),
/// LF line endings, so the decoy is indistinguishable from a stock install.
const NGINX_PAGE: &str = "\
<!DOCTYPE html>\n\
<html>\n\
<head>\n\
<title>Welcome to nginx!</title>\n\
<style>\n\
html { color-scheme: light dark; }\n\
body { width: 35em; margin: 0 auto;\n\
font-family: Tahoma, Verdana, Arial, sans-serif; }\n\
</style>\n\
</head>\n\
<body>\n\
<h1>Welcome to nginx!</h1>\n\
<p>If you see this page, nginx is successfully installed and working.\n\
Further configuration is required for the web server, reverse proxy, \n\
API gateway, load balancer, content cache, or other features.</p>\n\
\n\
<p>For online documentation and support please refer to\n\
<a href=\"https://nginx.org/\">nginx.org</a>.<br/>\n\
To engage with the community please visit\n\
<a href=\"https://community.nginx.org/\">community.nginx.org</a>.<br/>\n\
For enterprise grade support, professional services, additional \n\
security features and capabilities please refer to\n\
<a href=\"https://f5.com/nginx\">f5.com/nginx</a>.</p>\n\
\n\
<p><em>Thank you for using nginx.</em></p>\n\
</body>\n\
</html>\n";

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
    node: &'a str,
    #[serde(flatten)]
    visitor: &'a VisitorInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a str>,
    dst_port: u16,
}

/// Internal event sent from a connection handler to the notification aggregator.
struct HitEvent {
    visitor: VisitorInfo,
    token: Option<String>,
    dst_port: u16,
}

/// Spawn a listener task per configured port. Returns immediately; the tasks
/// run until the process exits.
pub fn serve(cfg: HoneypotConfig) {
    let key = derive_key(&cfg.secret);
    let node = Arc::new(node_name(&cfg));
    let limiter = Arc::new(Semaphore::new(cfg.max_connections.max(1)));

    // All notifications flow through one aggregator that debounces per source
    // IP and collapses floods into periodic summaries, so a DDoS to the
    // honeypot port can't fan out into a notification storm.
    let (tx, rx) = mpsc::channel::<HitEvent>(1024);
    {
        let cfg = cfg.clone();
        let node = node.clone();
        tokio::spawn(async move { aggregator(rx, cfg, node).await });
    }

    log::info!("[honeypot] node={} max_conns={}", node, cfg.max_connections);
    for &port in &cfg.ports {
        let cfg = cfg.clone();
        let node = node.clone();
        let limiter = limiter.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = listen(port, cfg, key, node, limiter, tx).await {
                log::error!("[honeypot] listener on :{} stopped: {}", port, e);
            }
        });
    }
}

async fn listen(
    port: u16,
    cfg: HoneypotConfig,
    key: [u8; 32],
    node: Arc<String>,
    limiter: Arc<Semaphore>,
    tx: mpsc::Sender<HitEvent>,
) -> Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("failed to bind honeypot port {}", port))?;
    log::info!("[honeypot] listening on 0.0.0.0:{}", port);
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // Flood guard: if every handler slot is busy, drop the
                // connection now instead of spawning unbounded work.
                let Ok(permit) = limiter.clone().try_acquire_owned() else {
                    continue;
                };
                let cfg = cfg.clone();
                let node = node.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle(stream, peer, port, &cfg, &key, &node, &tx).await {
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

#[allow(clippy::too_many_arguments)]
async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    dst_port: u16,
    cfg: &HoneypotConfig,
    key: &[u8; 32],
    node: &str,
    tx: &mpsc::Sender<HitEvent>,
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

    // The watermark token is only computed/embedded when explicitly enabled.
    // By default the honeypot stays a byte-identical nginx page (every hit is
    // still captured via the log + notification), so it can't be fingerprinted
    // as a honeypot by the tag itself.
    let token = if cfg.watermark {
        Some(encode_token(key, &visitor)?)
    } else {
        None
    };

    // Always log every hit at full fidelity; the aggregator decides whether to
    // notify (so a flood floods the log, not your phone).
    log_hit(cfg, node, &visitor, token.as_deref(), dst_port).await;
    let _ = tx.try_send(HitEvent {
        visitor: visitor.clone(),
        token: token.clone(),
        dst_port,
    });

    let body = build_body(token.as_deref());
    let server = cfg.server_header.as_deref().unwrap_or("nginx");
    let tag_header = match token.as_deref() {
        Some(t) => format!("X-Neko-Tag: {}\r\n", t),
        None => String::new(),
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Server: {server}\r\n\
         Date: {date}\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         {tag}\r\n{body}",
        server = server,
        date = http_date(now_secs()),
        len = body.len(),
        tag = tag_header,
        body = body,
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
    Ok(())
}

fn build_body(token: Option<&str>) -> String {
    match token {
        // Watermark mode: append the token as a trailing comment so a mapping
        // platform indexes it, while the visible page is still vanilla nginx.
        Some(t) => format!("{}<!-- {} -->\n", NGINX_PAGE, t),
        None => NGINX_PAGE.to_string(),
    }
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

/// Format a Unix timestamp as an RFC 7231 HTTP-date (always GMT), so the decoy
/// carries a normal `Date:` header like a real server.
fn http_date(secs: u64) -> String {
    const DOW: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (secs / 86400) as i64;
    let sod = secs % 86400;
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    // 1970-01-01 was a Thursday.
    let dow = (((days % 7 + 7) % 7) + 4) % 7;
    // civil_from_days (Howard Hinnant).
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DOW[dow as usize],
        d,
        MON[(m - 1) as usize],
        year,
        hh,
        mm,
        ss
    )
}

/// Append a full-fidelity record for every hit (never debounced).
async fn log_hit(
    cfg: &HoneypotConfig,
    node: &str,
    visitor: &VisitorInfo,
    token: Option<&str>,
    dst_port: u16,
) {
    log::warn!(
        "[honeypot] HIT [{}] :{} from {}:{} {} {} ua={:?}",
        node,
        dst_port,
        visitor.ip,
        visitor.port,
        visitor.method,
        visitor.path,
        visitor.ua,
    );

    let record = HitRecord {
        node,
        visitor,
        token,
        dst_port,
    };
    let json = serde_json::to_string(&record).unwrap_or_default();
    if let Err(e) = append_log(&cfg.log_path, &json).await {
        log::warn!("[honeypot] failed to write log {}: {}", cfg.log_path, e);
    }
}

/// Resolve this node's name: explicit config, else the system hostname.
fn node_name(cfg: &HoneypotConfig) -> String {
    if let Some(n) = &cfg.node_name {
        if !n.is_empty() {
            return n.clone();
        }
    }
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Decides whether an individual notification should be sent. Pure state +
/// explicit `now`, so the anti-storm logic is unit-testable without timers.
struct NotifyGate {
    dedup: Duration,
    max_per_min: u32,
    last_notified: HashMap<String, Instant>,
    win_notified: u32,
}

impl NotifyGate {
    fn new(dedup: Duration, max_per_min: u32) -> Self {
        Self {
            dedup,
            max_per_min,
            last_notified: HashMap::new(),
            win_notified: 0,
        }
    }

    /// True iff `ip` should get an individual notification now: not seen within
    /// the dedup window, and the per-minute budget isn't exhausted.
    fn admit(&mut self, ip: &str, now: Instant) -> bool {
        let deduped = self
            .last_notified
            .get(ip)
            .map(|t| now.duration_since(*t) < self.dedup)
            .unwrap_or(false);
        if deduped || self.win_notified >= self.max_per_min {
            return false;
        }
        self.last_notified.insert(ip.to_string(), now);
        self.win_notified += 1;
        true
    }

    /// Roll the per-minute window: reset the budget, prune stale dedup entries.
    fn roll_window(&mut self, now: Instant) {
        self.win_notified = 0;
        let dedup = self.dedup;
        self.last_notified
            .retain(|_, t| now.duration_since(*t) < dedup);
    }
}

/// Notification aggregator: debounce per source IP + per-minute rate cap, with
/// the overflow folded into a single summary so floods never spam.
async fn aggregator(mut rx: mpsc::Receiver<HitEvent>, cfg: HoneypotConfig, node: Arc<String>) {
    let mut gate = NotifyGate::new(
        Duration::from_secs(cfg.notify_dedup_secs.max(1)),
        cfg.notify_max_per_min,
    );
    let mut win_total: u64 = 0;
    let mut win_notified: u64 = 0;
    let mut win_ips: HashMap<String, u64> = HashMap::new();

    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                let Some(ev) = maybe else { break; };
                if cfg.notify_command.is_none() {
                    continue;
                }
                win_total += 1;
                let count = {
                    let c = win_ips.entry(ev.visitor.ip.clone()).or_insert(0);
                    *c += 1;
                    *c
                };
                if gate.admit(&ev.visitor.ip, Instant::now()) {
                    win_notified += 1;
                    notify_hit(&cfg, node.as_str(), &ev, count).await;
                }
            }
            _ = tick.tick() => {
                let folded = win_total.saturating_sub(win_notified);
                if folded > 0 {
                    notify_summary(&cfg, node.as_str(), win_total, win_notified, &win_ips).await;
                }
                win_total = 0;
                win_notified = 0;
                win_ips.clear();
                gate.roll_window(Instant::now());
            }
        }
    }
}

async fn notify_hit(cfg: &HoneypotConfig, node: &str, ev: &HitEvent, count: u64) {
    let Some(cmd) = cfg.notify_command.as_deref() else {
        return;
    };
    let v = &ev.visitor;
    let time = http_date(v.ts);
    let method = if v.method.is_empty() { "-" } else { v.method.as_str() };
    let path = if v.path.is_empty() { "-" } else { v.path.as_str() };
    let repeat = if count > 1 {
        format!(" ({}x in window)", count)
    } else {
        String::new()
    };
    let text = format!(
        "🚨 [{node}] honeypot tcp/{dp} hit\nfrom {ip}:{sp}{repeat}\n{method} {path}  Host: {host}\nUA: {ua}\n{time}",
        node = node,
        dp = ev.dst_port,
        ip = v.ip,
        sp = v.port,
        repeat = repeat,
        method = method,
        path = path,
        host = if v.host.is_empty() { "-" } else { v.host.as_str() },
        ua = if v.ua.is_empty() { "-" } else { v.ua.as_str() },
        time = time,
    );
    let fields = vec![
        ("NEKO_HP_KIND", "hit".to_string()),
        ("NEKO_HP_NODE", node.to_string()),
        ("NEKO_HP_IP", v.ip.clone()),
        ("NEKO_HP_PORT", v.port.to_string()),
        ("NEKO_HP_DST_PORT", ev.dst_port.to_string()),
        ("NEKO_HP_TS", v.ts.to_string()),
        ("NEKO_HP_TIME", time.clone()),
        ("NEKO_HP_METHOD", v.method.clone()),
        ("NEKO_HP_PATH", v.path.clone()),
        ("NEKO_HP_HOST", v.host.clone()),
        ("NEKO_HP_UA", v.ua.clone()),
        ("NEKO_HP_COUNT", count.to_string()),
        ("NEKO_HP_TOKEN", ev.token.clone().unwrap_or_default()),
    ];
    let json = serde_json::json!({
        "kind": "hit", "node": node, "count": count,
        "ip": v.ip, "port": v.port, "dst_port": ev.dst_port,
        "ts": v.ts, "time": time, "method": v.method, "path": v.path,
        "host": v.host, "ua": v.ua, "token": ev.token,
    })
    .to_string();
    send_notification(cmd, &fields, &text, &json).await;
}

async fn notify_summary(
    cfg: &HoneypotConfig,
    node: &str,
    total: u64,
    notified: u64,
    win_ips: &HashMap<String, u64>,
) {
    let Some(cmd) = cfg.notify_command.as_deref() else {
        return;
    };
    let unique = win_ips.len();
    let folded = total.saturating_sub(notified);
    let mut top: Vec<(&String, &u64)> = win_ips.iter().collect();
    top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let top_str = top
        .iter()
        .take(5)
        .map(|(ip, c)| format!("{}×{}", ip, c))
        .collect::<Vec<_>>()
        .join(", ");
    let text = format!(
        "⚠️ [{node}] honeypot flood: {total} hits / {unique} IPs in 60s\n{notified} notified, {folded} folded\ntop: {top}",
        node = node,
        total = total,
        unique = unique,
        notified = notified,
        folded = folded,
        top = top_str,
    );
    let fields = vec![
        ("NEKO_HP_KIND", "flood".to_string()),
        ("NEKO_HP_NODE", node.to_string()),
        ("NEKO_HP_TOTAL", total.to_string()),
        ("NEKO_HP_UNIQUE", unique.to_string()),
        ("NEKO_HP_NOTIFIED", notified.to_string()),
        ("NEKO_HP_FOLDED", folded.to_string()),
        ("NEKO_HP_WINDOW", "60".to_string()),
        ("NEKO_HP_TOP", top_str.clone()),
    ];
    let json = serde_json::json!({
        "kind": "flood", "node": node, "total": total, "unique": unique,
        "notified": notified, "folded": folded, "window_secs": 60, "top": top_str,
    })
    .to_string();
    send_notification(cmd, &fields, &text, &json).await;
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

/// Run the user-defined notification command via `sh -c`, exposing the given
/// `NEKO_HP_*` fields plus a prebuilt `NEKO_HP_TEXT` message as environment
/// variables and the full JSON record on stdin. Fully detached: failures never
/// affect the response.
async fn send_notification(cmd: &str, fields: &[(&str, String)], text: &str, json: &str) {
    let mut command = tokio::process::Command::new("sh");
    command.arg("-c").arg(cmd);
    for (k, v) in fields {
        command.env(k, v);
    }
    command
        .env("NEKO_HP_TEXT", text)
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
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
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
    fn notify_gate_debounces_and_rate_limits() {
        let base = Instant::now();
        let mut gate = NotifyGate::new(Duration::from_secs(300), 3);

        // First hit from an IP is admitted; repeats within the window are not.
        assert!(gate.admit("1.1.1.1", base));
        assert!(!gate.admit("1.1.1.1", base + Duration::from_secs(10)));
        assert!(!gate.admit("1.1.1.1", base + Duration::from_secs(299)));
        // After the dedup window, the same IP is admitted again.
        assert!(gate.admit("1.1.1.1", base + Duration::from_secs(301)));

        // Per-minute budget (3) caps distinct IPs; the 4th is folded.
        let mut gate = NotifyGate::new(Duration::from_secs(300), 3);
        assert!(gate.admit("a", base));
        assert!(gate.admit("b", base));
        assert!(gate.admit("c", base));
        assert!(!gate.admit("d", base)); // budget exhausted -> folded into summary
        // Rolling the window restores the budget.
        gate.roll_window(base + Duration::from_secs(60));
        assert!(gate.admit("d", base + Duration::from_secs(60)));
    }

    #[test]
    fn nginx_page_matches_upstream_size() {
        // nginx's current default index.html is 896 bytes; guard byte fidelity.
        assert_eq!(NGINX_PAGE.len(), 896);
        let _ = std::fs::write(
            std::env::temp_dir().join("neko-nginx-page.html"),
            NGINX_PAGE,
        );
    }

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
            watermark: true,
            node_name: Some("test-node".into()),
            notify_dedup_secs: 300,
            notify_max_per_min: 10,
            max_connections: 16,
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

    #[tokio::test]
    async fn stealth_mode_serves_plain_nginx() {
        let log_path = std::env::temp_dir().join("neko-hp-stealth.jsonl");
        let cfg = HoneypotConfig {
            enabled: true,
            ports: vec![39518],
            secret: String::new(),
            log_path: log_path.to_string_lossy().into_owned(),
            notify_command: None,
            server_header: None,
            watermark: false,
            node_name: Some("test-node".into()),
            notify_dedup_secs: 300,
            notify_max_per_min: 10,
            max_connections: 16,
        };
        serve(cfg);

        let mut stream = None;
        for _ in 0..50 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", 39518)).await {
                stream = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut s = stream.expect("connect to honeypot");
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();

        let mut resp = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            match tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                Ok(Ok(n)) => resp.extend_from_slice(&buf[..n]),
            }
        }
        let text = String::from_utf8_lossy(&resp);
        // No watermark leakage, and the body is byte-identical to nginx's page.
        assert!(!text.contains("X-Neko-Tag"), "resp: {}", text);
        assert!(!text.contains("NEKO1."), "resp: {}", text);
        let body = text.split("\r\n\r\n").nth(1).expect("has body");
        assert_eq!(body, NGINX_PAGE);
    }
}
