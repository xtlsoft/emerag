//! End-to-end tests against in-process TcpListener servers.
//!
//! No external network access is used: every server binds 127.0.0.1:0 and is
//! driven by a thread in this test binary.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use emerag_http::{Client, ProxyConfig, Request, TlsOptions, Url};

fn client() -> Client {
    let mut c = Client::new();
    c.connect_timeout = Duration::from_secs(2);
    c.read_timeout = Duration::from_secs(2);
    c.max_redirects = 5;
    c
}

fn url(s: &str) -> Url {
    match Url::parse(s) {
        Ok(u) => u,
        Err(e) => panic!("bad test URL {s}: {e}"),
    }
}

fn serve<F>(handler: F) -> (u16, JoinHandle<()>)
where
    F: FnOnce(TcpStream) + Send + 'static,
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    let handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            handler(stream);
        }
    });
    (port, handle)
}

fn serve_conns<F>(count: usize, mut handler: F) -> (u16, JoinHandle<()>)
where
    F: FnMut(usize, TcpStream) + Send + 'static,
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    let handle = thread::spawn(move || {
        for i in 0..count {
            if let Ok((stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                handler(i, stream);
            }
        }
    });
    (port, handle)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read one complete request (head plus declared body) from the server side.
fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(head_end) = find(&buf, b"\r\n\r\n").map(|i| i + 4) {
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if buf.len() >= head_end + length {
                return buf;
            }
        }
        match stream.read(&mut tmp) {
            Ok(0) => return buf,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return buf,
        }
    }
}

fn head_text(request: &[u8]) -> String {
    match find(request, b"\r\n\r\n") {
        Some(i) => String::from_utf8_lossy(&request[..i + 4]).to_string(),
        None => String::from_utf8_lossy(request).to_string(),
    }
}

fn request_body(request: &[u8]) -> Vec<u8> {
    match find(request, b"\r\n\r\n") {
        Some(i) => request[i + 4..].to_vec(),
        None => Vec::new(),
    }
}

fn head_has(head: &str, needle: &str) -> bool {
    head.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

#[test]
fn simple_get_with_content_length() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let (port, handle) = serve(move |mut s| {
        let req = read_request(&mut s);
        let _ = tx.send(req);
        let _ = s.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\ncontent-type: text/plain\r\nX-Multi: a\r\nX-Multi: b\r\n\r\nhello",
        );
    });
    let mut resp = client()
        .send(Request::get(url(&format!(
            "http://127.0.0.1:{port}/hello?x=1"
        ))))
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.reason, "OK");
    assert_eq!(resp.header("CONTENT-LENGTH"), Some("5"));
    assert_eq!(resp.header("Content-Type"), Some("text/plain"));
    assert_eq!(resp.header_all("x-multi"), vec!["a", "b"]);
    assert_eq!(resp.url.path_and_query(), "/hello?x=1");
    assert_eq!(resp.read_to_end_limited(100).unwrap(), b"hello");
    assert_eq!(resp.read_to_end_limited(100).unwrap(), b"");

    let req = rx.recv().unwrap();
    let head = head_text(&req);
    assert!(head.starts_with("GET /hello?x=1 HTTP/1.1\r\n"), "{head}");
    assert!(
        head.contains(&format!("Host: 127.0.0.1:{port}\r\n")),
        "{head}"
    );
    assert!(head_has(&head, "Connection: close"), "{head}");
    assert!(head_has(&head, "User-Agent: emerag/"), "{head}");
    assert!(head_has(&head, "Content-Length: 0"), "{head}");
    handle.join().unwrap();
}

#[test]
fn caller_host_wins_and_content_length_is_computed() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let (port, handle) = serve(move |mut s| {
        let req = read_request(&mut s);
        let _ = tx.send(req);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    });
    let mut req = Request::new("POST", url(&format!("http://127.0.0.1:{port}/p")))
        .header("Host", "virtual.example")
        .header("Content-Length", "999")
        .header("X-Trace", "abc");
    req.body = b"payload".to_vec();
    let resp = client().send(req).unwrap();
    assert_eq!(resp.status, 200);

    let head = head_text(&rx.recv().unwrap());
    assert!(head.contains("Host: virtual.example\r\n"), "{head}");
    assert!(head.contains("Content-Length: 7\r\n"), "{head}");
    assert!(!head.contains("999"), "{head}");
    assert_eq!(
        head.to_ascii_lowercase().matches("content-length:").count(),
        1
    );
    assert!(head.contains("X-Trace: abc\r\n"), "{head}");
    handle.join().unwrap();
}

#[test]
fn chunked_body_with_extensions_and_trailers() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;foo=bar\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n",
        );
    });
    let mut resp = client()
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/"))))
        .unwrap();
    assert_eq!(resp.read_to_end_limited(1000).unwrap(), b"hello world");
    handle.join().unwrap();
}

#[test]
fn chunked_updates_are_split_across_reads() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        let _ = s.flush();
        let _ = s.write_all(b"a\r\n0123456789");
        let _ = s.flush();
        thread::sleep(Duration::from_millis(20));
        let _ = s.write_all(b"\r\n0\r\n\r\n");
    });
    let mut resp = client()
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/"))))
        .unwrap();
    assert_eq!(resp.read_to_end_limited(1000).unwrap(), b"0123456789");
    handle.join().unwrap();
}

#[test]
fn read_to_close_when_no_length_is_given() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\nstreamed until close");
    });
    let mut resp = client()
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/"))))
        .unwrap();
    assert_eq!(
        resp.read_to_end_limited(1000).unwrap(),
        b"streamed until close"
    );
    handle.join().unwrap();
}

#[test]
fn hundred_continue_then_final_response() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok",
        );
    });
    let mut resp = client()
        .send(Request::new(
            "POST",
            url(&format!("http://127.0.0.1:{port}/")),
        ))
        .unwrap();
    assert_eq!(resp.status, 201);
    assert_eq!(resp.reason, "Created");
    assert_eq!(resp.read_to_end_limited(10).unwrap(), b"ok");
    handle.join().unwrap();
}

#[test]
fn no_body_statuses() {
    let (port, handle) = serve_conns(2, |i, mut s| {
        let _ = read_request(&mut s);
        if i == 0 {
            let _ = s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n");
        } else {
            let _ = s.write_all(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n");
        }
    });
    let mut a = client()
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/a"))))
        .unwrap();
    assert_eq!(a.status, 204);
    assert_eq!(a.read_to_end_limited(10).unwrap(), b"");
    let mut b = client()
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/b"))))
        .unwrap();
    assert_eq!(b.status, 304);
    assert_eq!(b.read_to_end_limited(10).unwrap(), b"");
    handle.join().unwrap();
}

#[test]
fn redirect_303_turns_post_into_get() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let (port_b, handle_b) = serve(move |mut s| {
        let req = read_request(&mut s);
        let _ = tx.send(req);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    });
    let location = format!("http://127.0.0.1:{port_b}/final");
    let (port_a, handle_a) = serve(move |mut s| {
        let _ = read_request(&mut s);
        let response =
            format!("HTTP/1.1 303 See Other\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
        let _ = s.write_all(response.as_bytes());
    });
    let c = client();
    let req = Request::post(
        url(&format!("http://127.0.0.1:{port_a}/start")),
        b"a=1".to_vec(),
        "application/x-www-form-urlencoded",
    );
    let resp = c.send_follow(req).unwrap();
    assert_eq!(resp.status, 200);
    let req_b = rx.recv().unwrap();
    let head = head_text(&req_b);
    assert!(head.starts_with("GET /final HTTP/1.1\r\n"), "{head}");
    assert!(!head_has(&head, "content-type"), "{head}");
    assert_eq!(request_body(&req_b), b"");
    assert!(head_has(&head, "Content-Length: 0"), "{head}");
    handle_a.join().unwrap();
    handle_b.join().unwrap();
}

#[test]
fn redirect_307_preserves_method_and_body() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let (port_b, handle_b) = serve(move |mut s| {
        let req = read_request(&mut s);
        let _ = tx.send(req);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    });
    let location = format!("http://127.0.0.1:{port_b}/final");
    let (port_a, handle_a) = serve(move |mut s| {
        let _ = read_request(&mut s);
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
        );
        let _ = s.write_all(response.as_bytes());
    });
    let mut req = Request::new("POST", url(&format!("http://127.0.0.1:{port_a}/start")));
    req.body = b"abc".to_vec();
    let resp = client().send_follow(req).unwrap();
    assert_eq!(resp.status, 200);
    let req_b = rx.recv().unwrap();
    let head = head_text(&req_b);
    assert!(head.starts_with("POST /final HTTP/1.1\r\n"), "{head}");
    assert_eq!(request_body(&req_b), b"abc");
    handle_a.join().unwrap();
    handle_b.join().unwrap();
}

#[test]
fn authorization_is_kept_on_same_origin_redirect() {
    let (port, handle) = serve_conns(2, |i, mut s| {
        let req = read_request(&mut s);
        let head = head_text(&req);
        if i == 0 {
            assert!(head.contains("Authorization: Bearer secret"), "{head}");
            let _ =
                s.write_all(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n");
        } else {
            assert!(head.starts_with("GET /next HTTP/1.1\r\n"), "{head}");
            assert!(
                head.contains("Authorization: Bearer secret"),
                "auth lost: {head}"
            );
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    let req = Request::get(url(&format!("http://127.0.0.1:{port}/start"))).bearer("secret");
    let resp = client().send_follow(req).unwrap();
    assert_eq!(resp.status, 200);
    handle.join().unwrap();
}

#[test]
fn authorization_is_stripped_on_cross_origin_redirect() {
    let (port_b, handle_b) = serve(|mut s| {
        let req = read_request(&mut s);
        let head = head_text(&req);
        assert!(
            !head_has(&head, "authorization"),
            "authorization leaked: {head}"
        );
        assert!(!head_has(&head, "cookie"), "cookie leaked: {head}");
        assert!(
            !head.contains("virtual.example"),
            "stale Host leaked: {head}"
        );
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    });
    let location = format!("http://127.0.0.1:{port_b}/final");
    let (port_a, handle_a) = serve(move |mut s| {
        let _ = read_request(&mut s);
        let response =
            format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
        let _ = s.write_all(response.as_bytes());
    });
    let req = Request::get(url(&format!("http://127.0.0.1:{port_a}/start")))
        .bearer("secret")
        .header("Cookie", "session=1")
        .header("Host", "virtual.example");
    let resp = client().send_follow(req).unwrap();
    assert_eq!(resp.status, 200);
    handle_a.join().unwrap();
    handle_b.join().unwrap();
}

#[test]
fn redirect_loop_is_detected() {
    let (port, handle) = serve_conns(2, |_i, mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\n\r\n");
    });
    let err = client()
        .send_follow(Request::get(url(&format!("http://127.0.0.1:{port}/start"))))
        .unwrap_err();
    assert!(err.to_string().contains("redirect loop"), "{err}");
    handle.join().unwrap();
}

#[test]
fn redirect_limit_is_enforced() {
    let (port, handle) = serve_conns(3, |i, mut s| {
        let _ = read_request(&mut s);
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: /hop?i={}\r\nContent-Length: 0\r\n\r\n",
            i + 1
        );
        let _ = s.write_all(response.as_bytes());
    });
    let mut c = client();
    c.max_redirects = 2;
    let err = c
        .send_follow(Request::get(url(&format!(
            "http://127.0.0.1:{port}/hop?i=0"
        ))))
        .unwrap_err();
    assert!(err.to_string().contains("too many redirects"), "{err}");
    handle.join().unwrap();
}

#[test]
fn body_limit_is_enforced() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789");
    });
    let mut resp = client()
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/"))))
        .unwrap();
    let err = resp.read_to_end_limited(5).unwrap_err();
    assert!(err.to_string().contains("exceeds"), "{err}");
    handle.join().unwrap();
}

#[test]
fn malformed_status_line_is_rejected() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 2OO OK\r\n\r\n");
    });
    assert!(client()
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/"))))
        .is_err());
    handle.join().unwrap();
}

#[test]
fn malformed_header_is_rejected() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nNoColonHere\r\n\r\n");
    });
    assert!(client()
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/"))))
        .is_err());
    handle.join().unwrap();
}

#[test]
fn invalid_content_length_is_rejected() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5x\r\n\r\nhello");
    });
    assert!(client()
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/"))))
        .is_err());
    handle.join().unwrap();
}

#[test]
fn header_read_timeout_is_reported_and_bounded() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        thread::sleep(Duration::from_millis(400));
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    });
    let mut c = client();
    c.read_timeout = Duration::from_millis(100);
    let started = Instant::now();
    let err = c
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/"))))
        .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took too long: {err}"
    );
    handle.join().unwrap();
}

#[test]
fn body_read_timeout_is_retryable() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345");
        let _ = s.flush();
        thread::sleep(Duration::from_millis(250));
        let _ = s.write_all(b"67890");
    });
    let mut c = client();
    c.read_timeout = Duration::from_millis(100);
    let mut resp = c
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/"))))
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 16];
    while got.len() < 5 {
        match resp.read_some(&mut buf) {
            Ok(0) => panic!("body ended early: {:?}", got),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => panic!("unexpected error before first chunk: {e}"),
        }
    }
    let err = resp.read_some(&mut buf).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "unexpected error kind: {:?}",
        err.kind()
    );
    thread::sleep(Duration::from_millis(250));
    loop {
        match resp.read_some(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => panic!("retry after timeout failed: {e}"),
        }
    }
    assert_eq!(got, b"1234567890");
    handle.join().unwrap();
}

#[test]
fn cancellation_aborts_a_body_read() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcd");
        let _ = s.flush();
        thread::sleep(Duration::from_millis(300));
        let _ = s.write_all(b"efghij");
    });
    let c = client();
    let mut resp = c
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/"))))
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 16];
    while got.len() < 4 {
        let n = resp.read_some(&mut buf).unwrap();
        assert!(n > 0, "body ended early");
        got.extend_from_slice(&buf[..n]);
    }
    c.cancel.cancel();
    let err = resp.read_some(&mut buf).unwrap_err();
    assert!(err.to_string().contains("cancelled"), "{err}");
    handle.join().unwrap();
}

#[test]
fn error_body_is_captured_without_duplication() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 14\r\nContent-Type: text/plain\r\n\r\nnot found here",
        );
    });
    let mut resp = client()
        .send(Request::get(url(&format!(
            "http://127.0.0.1:{port}/missing"
        ))))
        .unwrap();
    assert_eq!(resp.status, 404);
    assert_eq!(resp.early_body, b"not found here");
    assert_eq!(resp.read_to_end_limited(1000).unwrap(), b"not found here");
    handle.join().unwrap();
}

#[test]
fn resolve_override_connects_without_using_dns() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\npinned");
    });
    let mut c = client();
    c.resolve
        .parse_entry(&format!("pinned.example:{port}:127.0.0.1"))
        .unwrap();
    c.resolve
        .add("added.example", port, "127.0.0.1".parse().unwrap());
    assert_eq!(
        c.resolve.lookup("added.example", port),
        Some("127.0.0.1".parse().unwrap())
    );
    c.no_dns = true;
    let resp = c
        .send(Request::get(url(&format!("http://pinned.example:{port}/"))))
        .unwrap();
    assert_eq!(resp.status, 200);
    handle.join().unwrap();
}

#[test]
fn no_dns_without_override_mentions_the_flags() {
    let mut c = client();
    c.no_dns = true;
    let err = c
        .send(Request::get(url("http://no-such-host.invalid/")))
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("--resolve"), "{text}");
    assert!(text.contains("--ip"), "{text}");
}

#[test]
fn connect_failure_mentions_the_flags() {
    let mut c = client();
    c.connect_timeout = Duration::from_millis(200);
    let err = c
        .send(Request::get(url("http://127.0.0.1:1/")))
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("--resolve"), "{text}");
    assert!(text.contains("--ip"), "{text}");
}

#[test]
fn forward_proxy_sends_absolute_form_and_basic_auth() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let (port, handle) = serve(move |mut s| {
        let req = read_request(&mut s);
        let _ = tx.send(req);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nproxy");
    });
    let mut c = client();
    c.proxy = Some(ProxyConfig {
        http: Some(format!("http://user:pass@127.0.0.1:{port}")),
        ..Default::default()
    });
    let mut resp = c
        .send(Request::get(url("http://example.invalid/x?q=1")))
        .unwrap();
    assert_eq!(resp.read_to_end_limited(100).unwrap(), b"proxy");

    let req = rx.recv().unwrap();
    let head = head_text(&req);
    assert!(
        head.starts_with("GET http://example.invalid/x?q=1 HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(head.contains("Host: example.invalid\r\n"), "{head}");
    assert!(
        head.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"),
        "{head}"
    );
    handle.join().unwrap();
}

#[test]
fn no_proxy_bypasses_the_configured_proxy() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ndirect");
    });
    let mut c = client();
    c.proxy = Some(ProxyConfig {
        http: Some("http://127.0.0.1:1".to_string()),
        no_proxy: vec!["127.0.0.1".to_string()],
        ..Default::default()
    });
    let mut resp = c
        .send(Request::get(url(&format!("http://127.0.0.1:{port}/"))))
        .unwrap();
    assert_eq!(resp.read_to_end_limited(100).unwrap(), b"direct");
    handle.join().unwrap();
}

#[test]
fn sse_iterator_streams_events() {
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n");
        let _ = s.flush();
        let _ = s.write_all(b"event: delta\ndata: hel");
        let _ = s.flush();
        thread::sleep(Duration::from_millis(20));
        let _ = s.write_all(b"lo\n\ndata: world\n\n");
    });
    let resp = client()
        .send(Request::get(url(&format!(
            "http://127.0.0.1:{port}/events"
        ))))
        .unwrap();
    let events: Vec<_> = resp
        .sse_events()
        .collect::<emerag_http::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event, "delta");
    assert_eq!(events[0].data, "hello");
    assert_eq!(events[1].event, "message");
    assert_eq!(events[1].data, "world");
    handle.join().unwrap();
}

#[test]
#[ignore = "awaits emerag-tls"]
fn https_request_over_tls() {
    // Kept as the integration point for emerag-tls: once TlsStream::connect is
    // implemented this test exercises the full https path (SNI, ALPN, CA
    // verification) against an in-process TLS server.
    let (port, handle) = serve(|mut s| {
        let _ = read_request(&mut s);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    });
    let mut c = client();
    c.tls = TlsOptions::new();
    let resp = c
        .send(Request::get(url(&format!("https://127.0.0.1:{port}/"))))
        .unwrap();
    assert_eq!(resp.status, 200);
    handle.join().unwrap();
}
