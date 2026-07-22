use crate::config::Paths;
use crate::parsers::Parts;
use crate::state::AppState;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Duration as StdDuration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub(super) fn temp_paths(tmp: &TempDir) -> Paths {
    let data = tmp.path();
    Paths {
        config: data.join("klaxond.toml"),
        default_config: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("klaxond.default.toml"),
        render_config: data.join("render-config.json"),
        ntfy_topics: data.join("ntfy-topics.json"),
        dedup_config: data.join("dedup-config.json"),
        dedup_pending_dir: data.join("dedup_pending"),
        auth_config: data.join("auth-config.json"),
        auth_session_key: data.join("auth-session.key"),
        backup_dir: data.join("backups"),
        static_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"),
        beszel_db: data.join("missing-beszel.db"),
        history_db: data.join("klaxond.db"),
    }
}

pub(in crate::delivery) fn test_state() -> (TempDir, AppState) {
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(temp_paths(&tmp)).unwrap();
    (tmp, state)
}

pub(in crate::delivery) fn sample_parts() -> Parts {
    Parts {
        title: "Test alert".into(),
        body: "alert body".into(),
        tags: vec!["warning".into()],
        actions: vec![[
            "view".into(),
            "Open".into(),
            "http://example.test/runbook".into(),
        ]],
        priority: "urgent".into(),
        alertname: "TestAlert".into(),
        skip_snooze: false,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
    }
}

pub(super) fn http_response(content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

pub(super) async fn spawn_http_once(response: Vec<u8>) -> (String, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&stream).await;
        let _ = tx.send(String::from_utf8_lossy(&request).to_string());
        write_all(&stream, &response).await;
    });
    (format!("http://{addr}"), rx)
}

pub(super) fn spawn_smtp_once() -> (String, u16, std::sync::mpsc::Receiver<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let transcript = handle_smtp_client(stream);
        let _ = tx.send(transcript);
    });
    ("127.0.0.1".into(), addr.port(), rx)
}

pub(super) fn smtp_transcript_timeout() -> StdDuration {
    StdDuration::from_secs(2)
}

async fn read_http_request(stream: &tokio::net::TcpStream) -> Vec<u8> {
    let mut buf = vec![0_u8; 4096];
    let mut read = 0;
    loop {
        if read == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
        stream.readable().await.unwrap();
        match stream.try_read(&mut buf[read..]) {
            Ok(0) => break,
            Ok(n) => {
                read += n;
                if request_complete(&buf[..read]) {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => panic!("read fake HTTP request: {err}"),
        }
    }
    buf.truncate(read);
    buf
}

async fn write_all(stream: &tokio::net::TcpStream, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        stream.writable().await.unwrap();
        match stream.try_write(bytes) {
            Ok(0) => panic!("fake HTTP socket closed while writing"),
            Ok(n) => bytes = &bytes[n..],
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => panic!("write fake HTTP response: {err}"),
        }
    }
}

fn request_complete(buf: &[u8]) -> bool {
    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]);
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            let len = value.trim().parse::<usize>().unwrap_or(0);
            return buf.len().saturating_sub(header_end) >= len;
        }
    }
    true
}

fn handle_smtp_client(mut stream: std::net::TcpStream) -> String {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut transcript = String::new();
    smtp_reply(&mut stream, "220 localhost ESMTP");
    let mut in_data = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        transcript.push_str(&line);
        let command = line.trim_end_matches(['\r', '\n']);
        if in_data {
            if command == "." {
                smtp_reply(&mut stream, "250 queued");
                in_data = false;
            }
            continue;
        }
        let upper = command.to_ascii_uppercase();
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            smtp_reply(&mut stream, "250-localhost");
            smtp_reply(&mut stream, "250-AUTH PLAIN LOGIN");
            smtp_reply(&mut stream, "250 OK");
        } else if upper == "AUTH LOGIN" {
            smtp_reply(&mut stream, "334 VXNlcm5hbWU6");
            read_smtp_line(&mut reader, &mut transcript);
            smtp_reply(&mut stream, "334 UGFzc3dvcmQ6");
            read_smtp_line(&mut reader, &mut transcript);
            smtp_reply(&mut stream, "235 authenticated");
        } else if upper == "AUTH PLAIN" {
            smtp_reply(&mut stream, "334 ");
            read_smtp_line(&mut reader, &mut transcript);
            smtp_reply(&mut stream, "235 authenticated");
        } else if upper.starts_with("AUTH PLAIN ") {
            smtp_reply(&mut stream, "235 authenticated");
        } else if upper.starts_with("MAIL FROM") || upper.starts_with("RCPT TO") {
            smtp_reply(&mut stream, "250 OK");
        } else if upper == "DATA" {
            smtp_reply(&mut stream, "354 end with dot");
            in_data = true;
        } else if upper == "QUIT" {
            smtp_reply(&mut stream, "221 bye");
            break;
        } else {
            smtp_reply(&mut stream, "250 OK");
        }
    }
    transcript
}

fn read_smtp_line(reader: &mut BufReader<std::net::TcpStream>, transcript: &mut String) {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    transcript.push_str(&line);
}

fn smtp_reply(stream: &mut std::net::TcpStream, line: &str) {
    stream.write_all(line.as_bytes()).unwrap();
    stream.write_all(b"\r\n").unwrap();
    stream.flush().unwrap();
}
