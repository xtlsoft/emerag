//! Interoperability tests against openssl s_server, a Python TLS server and
//! (when explicitly requested with --ignored) real public HTTPS endpoints.
//!
//! Every test skips with a printed note when its tool is unavailable, so an
//! offline machine without OpenSSL still gets a green unit test suite.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use emerag_tls::{TlsConfig, TlsStream, TlsVersion, VerifyMode};

// ------------------------------------------------------------------ helpers

fn have_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn have_python() -> bool {
    Command::new("python3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn scratch_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = base.join(format!("emerag-tls-{}-{}-{}", std::process::id(), n, tag));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn openssl(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run openssl");
    if !out.status.success() {
        panic!(
            "openssl {:?} failed: {}\n{}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.stdout
}

struct Certs {
    dir: PathBuf,
    ca_pem: Vec<u8>,
    leaf_cert: PathBuf,
    leaf_key: PathBuf,
}

impl Drop for Certs {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn make_certs(tag: &str, key_kind: &str) -> Certs {
    let dir = scratch_dir(tag);
    openssl(
        &dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "2",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-subj",
            "/CN=Emerag Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    );

    if key_kind == "ec" || key_kind == "ec384" {
        let curve = if key_kind == "ec384" {
            "P-384"
        } else {
            "P-256"
        };
        openssl(
            &dir,
            &[
                "req",
                "-newkey",
                "ec",
                "-pkeyopt",
                &format!("ec_paramgen_curve:{curve}"),
                "-sha256",
                "-nodes",
                "-keyout",
                "leaf.key",
                "-out",
                "leaf.csr",
                "-subj",
                "/CN=localhost",
            ],
        );
    } else {
        openssl(
            &dir,
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-keyout",
                "leaf.key",
                "-out",
                "leaf.csr",
                "-subj",
                "/CN=localhost",
            ],
        );
    }

    let key_usage = if key_kind.starts_with("ec") {
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
    } else {
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
    };
    fs::write(dir.join("leaf.ext"), key_usage).expect("write extension file");
    openssl(
        &dir,
        &[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "leaf.pem",
            "-days",
            "2",
            "-sha256",
            "-extfile",
            "leaf.ext",
        ],
    );

    let ca_pem = fs::read(dir.join("ca.pem")).expect("read CA");
    Certs {
        dir: dir.clone(),
        ca_pem,
        leaf_cert: dir.join("leaf.pem"),
        leaf_key: dir.join("leaf.key"),
    }
}

fn make_wrong_ca(dir: &Path) -> Vec<u8> {
    openssl(
        dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "2",
            "-nodes",
            "-keyout",
            "wrong.key",
            "-out",
            "wrong.pem",
            "-subj",
            "/CN=Wrong Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
    );
    fs::read(dir.join("wrong.pem")).expect("read wrong CA")
}

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let addr = format!("127.0.0.1:{port}");
    while Instant::now() < deadline {
        if let Ok(stream) = TcpStream::connect_timeout(
            &addr.parse().expect("socket addr"),
            Duration::from_millis(200),
        ) {
            drop(stream);
            return true;
        }
        thread::sleep(Duration::from_millis(40));
    }
    false
}

struct Server {
    child: Child,
    port: u16,
    _certs: Certs,
    log: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_server(certs: Certs, extra: &[&str]) -> Server {
    let port = free_port();
    let log = certs.dir.join("s_server.log");
    let log_file = fs::File::create(&log).expect("create server log");
    let mut cmd = Command::new("openssl");
    cmd.arg("s_server")
        .arg("-accept")
        .arg(port.to_string())
        .arg("-www")
        .arg("-cert")
        .arg(&certs.leaf_cert)
        .arg("-key")
        .arg(&certs.leaf_key)
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log_file));
    let child = cmd.spawn().expect("spawn openssl s_server");
    let server = Server {
        child,
        port,
        _certs: certs,
        log,
    };
    if !wait_for_port(port, Duration::from_secs(8)) {
        let log = fs::read_to_string(&server.log).unwrap_or_default();
        panic!("openssl s_server did not start on port {port}:\n{log}");
    }
    server
}

fn connect(port: u16, cfg: &TlsConfig) -> Result<TlsStream, String> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("tcp: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("timeout: {e}"))?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("timeout: {e}"))?;
    TlsStream::connect(tcp, cfg).map_err(|e| e.to_string())
}

fn connect_ok(port: u16, cfg: &TlsConfig) -> TlsStream {
    match connect(port, cfg) {
        Ok(s) => s,
        Err(e) => panic!("TLS handshake failed: {e}"),
    }
}

fn connect_err(port: u16, cfg: &TlsConfig) -> String {
    match connect(port, cfg) {
        Ok(_) => panic!("TLS handshake unexpectedly succeeded"),
        Err(e) => e,
    }
}

fn read_response(stream: &mut TlsStream) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > 262_144 {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                break;
            }
            Err(e) => panic!("read failed: {e}"),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn http_get(port: u16, cfg: &TlsConfig) -> (TlsStream, String) {
    let mut stream = connect_ok(port, cfg);
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write request");
    stream.flush().expect("flush request");
    let body = read_response(&mut stream);
    (stream, body)
}

fn local_cfg(ca_pem: Vec<u8>) -> TlsConfig {
    let mut cfg = TlsConfig::new("localhost");
    cfg.ca_pem = Some(ca_pem);
    cfg
}

// ------------------------------------------------------- TLS 1.3 interop

#[test]
fn openssl_tls13_default_ciphers() {
    if !have_openssl() {
        eprintln!("skipping openssl TLS 1.3 test: openssl not found");
        return;
    }
    let certs = make_certs("tls13-default", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(certs, &["-tls1_3", "-alpn", "http/1.1"]);
    let (stream, body) = http_get(server.port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls13);
    assert_eq!(stream.alpn(), Some("http/1.1"));
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
    assert!(stream.peer_spki_sha256().is_some());
}

#[test]
fn openssl_tls13_all_cipher_suites() {
    if !have_openssl() {
        eprintln!("skipping openssl TLS 1.3 suite tests: openssl not found");
        return;
    }
    for suite in [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ] {
        let certs = make_certs(&format!("tls13-{}", suite.to_ascii_lowercase()), "rsa");
        let ca = certs.ca_pem.clone();
        let server = spawn_server(certs, &["-tls1_3", "-ciphersuites", suite]);
        let (stream, body) = http_get(server.port, &local_cfg(ca));
        assert_eq!(stream.version(), TlsVersion::Tls13, "suite {suite}");
        assert!(
            body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
            "suite {suite}: {body:?}"
        );
    }
}

#[test]
fn openssl_tls13_ecdsa_certificate() {
    if !have_openssl() {
        eprintln!("skipping openssl ECDSA TLS 1.3 test: openssl not found");
        return;
    }
    let certs = make_certs("tls13-ecdsa", "ec");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(certs, &["-tls1_3"]);
    let (stream, body) = http_get(server.port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls13);
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
}

#[test]
fn openssl_tls13_p256_key_share() {
    if !have_openssl() {
        eprintln!("skipping openssl P-256 TLS 1.3 test: openssl not found");
        return;
    }
    let certs = make_certs("tls13-p256", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(certs, &["-tls1_3", "-groups", "P-256"]);
    let (stream, body) = http_get(server.port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls13);
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
}

#[test]
fn openssl_tls13_p384_ecdsa_certificate() {
    if !have_openssl() {
        eprintln!("skipping openssl P-384 TLS 1.3 test: openssl not found");
        return;
    }
    let certs = make_certs("tls13-ecdsa384", "ec384");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(certs, &["-tls1_3"]);
    let (stream, body) = http_get(server.port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls13);
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
}

// ------------------------------------------------------- TLS 1.2 interop

#[test]
fn openssl_tls12_ecdhe_rsa_aes128_gcm() {
    if !have_openssl() {
        eprintln!("skipping openssl TLS 1.2 test: openssl not found");
        return;
    }
    let certs = make_certs("tls12-aes128", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(
        certs,
        &[
            "-tls1_2",
            "-cipher",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "-alpn",
            "http/1.1",
        ],
    );
    let (stream, body) = http_get(server.port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls12);
    assert_eq!(stream.alpn(), Some("http/1.1"));
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
}

#[test]
fn openssl_tls12_ecdhe_rsa_aes256_gcm_sha384() {
    if !have_openssl() {
        eprintln!("skipping openssl TLS 1.2 SHA384 test: openssl not found");
        return;
    }
    let certs = make_certs("tls12-aes256", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(
        certs,
        &["-tls1_2", "-cipher", "ECDHE-RSA-AES256-GCM-SHA384"],
    );
    let (stream, body) = http_get(server.port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls12);
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
}

#[test]
fn openssl_tls12_ecdhe_rsa_chacha20() {
    if !have_openssl() {
        eprintln!("skipping openssl TLS 1.2 ChaCha test: openssl not found");
        return;
    }
    let certs = make_certs("tls12-chacha", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(
        certs,
        &["-tls1_2", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305"],
    );
    let (stream, body) = http_get(server.port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls12);
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
}

#[test]
fn openssl_tls12_ecdsa_certificate() {
    if !have_openssl() {
        eprintln!("skipping openssl ECDSA TLS 1.2 test: openssl not found");
        return;
    }
    let certs = make_certs("tls12-ecdsa", "ec");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(
        certs,
        &["-tls1_2", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256"],
    );
    let (stream, body) = http_get(server.port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls12);
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
}

#[test]
fn openssl_tls13_ip_literal_without_sni() {
    if !have_openssl() {
        eprintln!("skipping IP-literal test: openssl not found");
        return;
    }
    let certs = make_certs("ip-literal", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(certs, &["-tls1_3"]);
    // SNI must be omitted for an IP literal, and the SAN IP entry must match.
    let mut cfg = TlsConfig::new("127.0.0.1");
    cfg.ca_pem = Some(ca);
    let (stream, body) = http_get(server.port, &cfg);
    assert_eq!(stream.version(), TlsVersion::Tls13);
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
}

#[test]
fn openssl_tls12_no_session_ticket() {
    if !have_openssl() {
        eprintln!("skipping no-ticket TLS 1.2 test: openssl not found");
        return;
    }
    let certs = make_certs("tls12-no-ticket", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(
        certs,
        &[
            "-tls1_2",
            "-no_ticket",
            "-cipher",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ],
    );
    let (stream, body) = http_get(server.port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls12);
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
}

#[test]
fn openssl_tls12_p256_key_share() {
    if !have_openssl() {
        eprintln!("skipping openssl P-256 TLS 1.2 test: openssl not found");
        return;
    }
    let certs = make_certs("tls12-p256", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(
        certs,
        &[
            "-tls1_2",
            "-groups",
            "P-256",
            "-cipher",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ],
    );
    let (stream, body) = http_get(server.port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls12);
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
}

#[test]
fn openssl_tls12_rsa_pkcs1_signature() {
    if !have_openssl() {
        eprintln!("skipping openssl PKCS#1 TLS 1.2 test: openssl not found");
        return;
    }
    let certs = make_certs("tls12-pkcs1", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(
        certs,
        &[
            "-tls1_2",
            "-cipher",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "-sigalgs",
            "rsa_pkcs1_sha256",
        ],
    );
    let (stream, body) = http_get(server.port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls12);
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
}

#[test]
fn min_version_tls13_rejects_a_tls12_server() {
    if !have_openssl() {
        eprintln!("skipping min_version test: openssl not found");
        return;
    }
    let certs = make_certs("min-version", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(
        certs,
        &["-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"],
    );
    let mut cfg = local_cfg(ca);
    cfg.min_version = TlsVersion::Tls13;
    let err = connect_err(server.port, &cfg);
    assert!(
        err.starts_with("tls: handshake:"),
        "expected a handshake failure, got: {err}"
    );
}

// ----------------------------------------------------------- verification

#[test]
fn hostname_mismatch_is_rejected() {
    if !have_openssl() {
        eprintln!("skipping hostname mismatch test: openssl not found");
        return;
    }
    let certs = make_certs("hostname-mismatch", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(certs, &["-tls1_3"]);
    let mut cfg = TlsConfig::new("wrong.example.com");
    cfg.ca_pem = Some(ca);
    let err = connect_err(server.port, &cfg);
    assert!(
        err.contains("hostname mismatch"),
        "expected hostname mismatch, got: {err}"
    );
}

#[test]
fn wrong_ca_is_rejected_and_insecure_skips_verification() {
    if !have_openssl() {
        eprintln!("skipping wrong-CA test: openssl not found");
        return;
    }
    let certs = make_certs("wrong-ca", "rsa");
    let wrong = make_wrong_ca(&certs.dir);
    let server = spawn_server(certs, &["-tls1_3"]);

    let mut cfg = TlsConfig::new("localhost");
    cfg.ca_pem = Some(wrong.clone());
    let err = connect_err(server.port, &cfg);
    assert!(
        err.starts_with("tls: verify:"),
        "expected a verification error, got: {err}"
    );

    let mut insecure = TlsConfig::new("localhost");
    insecure.ca_pem = Some(wrong);
    insecure.verify = VerifyMode::Insecure;
    let (stream, body) = http_get(server.port, &insecure);
    assert_eq!(stream.version(), TlsVersion::Tls13);
    assert!(
        body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );
    assert!(stream.peer_spki_sha256().is_some());
}

#[test]
fn pinned_spki_matches_and_mismatches() {
    if !have_openssl() {
        eprintln!("skipping SPKI pin test: openssl not found");
        return;
    }
    let certs = make_certs("pin", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(certs, &["-tls1_3"]);

    let mut insecure = TlsConfig::new("localhost");
    insecure.verify = VerifyMode::Insecure;
    let (stream, _) = http_get(server.port, &insecure);
    let pin = stream.peer_spki_sha256().expect("SPKI pin");
    // s_server handles one connection at a time; release it before reconnecting.
    drop(stream);

    let mut cfg = local_cfg(ca);
    cfg.pinned_spki = Some(pin);
    let (stream, body) = http_get(server.port, &cfg);
    assert!(body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200"));
    drop(stream);

    let mut bad = cfg;
    bad.pinned_spki = Some([0xA5u8; 32]);
    let err = connect_err(server.port, &bad);
    assert!(
        err.contains("SPKI pin mismatch"),
        "expected SPKI pin mismatch, got: {err}"
    );
}

// ------------------------------------------------------ negative / scripted

#[test]
fn tampered_server_handshake_record_fails_cleanly() {
    if !have_openssl() {
        eprintln!("skipping tamper test: openssl not found");
        return;
    }
    let certs = make_certs("tamper", "rsa");
    let ca = certs.ca_pem.clone();
    let server = spawn_server(certs, &["-tls1_3"]);
    let proxy_port = spawn_tamper_proxy(server.port);
    let cfg = local_cfg(ca);
    let err = connect_err(proxy_port, &cfg);
    assert!(
        err.starts_with("tls: handshake:"),
        "expected a handshake-stage error, got: {err}"
    );
    assert!(
        err.contains("bad record MAC") || err.contains("decryption failed"),
        "expected an authentication failure, got: {err}"
    );
}

fn spawn_tamper_proxy(upstream_port: u16) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("proxy listen");
    let port = listener.local_addr().expect("proxy addr").port();
    thread::spawn(move || {
        let Ok((client, _)) = listener.accept() else {
            return;
        };
        let Ok(server) = TcpStream::connect(("127.0.0.1", upstream_port)) else {
            return;
        };
        let client_read = client.try_clone().expect("clone client");
        let server_read = server.try_clone().expect("clone server");
        let handle = thread::spawn(move || {
            let mut from = server_read;
            let mut to = client;
            forward_tampered(&mut from, &mut to);
            let _ = to.shutdown(Shutdown::Both);
        });
        let mut from = client_read;
        let mut to = server;
        let _ = std::io::copy(&mut from, &mut to);
        let _ = to.shutdown(Shutdown::Write);
        let _ = handle.join();
    });
    port
}

fn forward_tampered(from: &mut TcpStream, to: &mut TcpStream) {
    let mut buf = [0u8; 16384];
    let mut pending: Vec<u8> = Vec::new();
    let mut flipped = false;
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => pending.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
        loop {
            if pending.len() < 5 {
                break;
            }
            let len = u16::from_be_bytes([pending[3], pending[4]]) as usize;
            if len > 18432 {
                return;
            }
            if pending.len() < 5 + len {
                break;
            }
            let mut record: Vec<u8> = pending.drain(..5 + len).collect();
            if !flipped && record[0] == 23 && len > 32 {
                let at = 5 + len / 2;
                record[at] ^= 0x01;
                flipped = true;
            }
            if to.write_all(&record).is_err() {
                return;
            }
        }
    }
}

#[test]
fn plaintext_alert_error_names_the_alert() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let _ = read_one_record(&mut sock);
        // fatal(2) handshake_failure(40)
        let _ = sock.write_all(&[21, 3, 3, 0, 2, 2, 40]);
        let _ = sock.flush();
    });
    let cfg = TlsConfig::new("localhost");
    let err = connect_err(port, &cfg);
    assert_eq!(err, "tls: handshake: server alert handshake_failure (40)");
    let _ = handle.join();
}

#[test]
fn tls12_server_without_extended_master_secret_is_rejected() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let _ = read_one_record(&mut sock);
        // TLS 1.2 ServerHello with no extensions (thus no extended_master_secret).
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11u8; 32]);
        body.push(0); // empty session id
        body.extend_from_slice(&[0xc0, 0x2f]); // ECDHE_RSA_AES128_GCM_SHA256
        body.push(0); // null compression
        let mut msg = vec![2, 0, 0, body.len() as u8];
        msg.extend_from_slice(&body);
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        record.extend_from_slice(&msg);
        let _ = sock.write_all(&record);
        let _ = sock.flush();
        thread::sleep(Duration::from_millis(100));
    });
    let cfg = TlsConfig::new("localhost");
    let err = connect_err(port, &cfg);
    assert!(
        err.contains("extended master secret"),
        "expected an EMS error, got: {err}"
    );
    let _ = handle.join();
}

fn read_one_record(sock: &mut TcpStream) -> std::io::Result<()> {
    let mut header = [0u8; 5];
    sock.read_exact(&mut header)?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    sock.read_exact(&mut payload)?;
    Ok(())
}

// ---------------------------------------------------------- Python server

#[test]
fn python_ssl_server_http() {
    if !have_python() {
        eprintln!("skipping Python TLS test: python3 not found");
        return;
    }
    if !have_openssl() {
        eprintln!("skipping Python TLS test: openssl needed to make certificates");
        return;
    }
    let certs = make_certs("python", "rsa");
    let ca = certs.ca_pem.clone();
    let port = free_port();
    let script = r#"
import socket, ssl, sys
port = int(sys.argv[1]); cert = sys.argv[2]; key = sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
ctx.set_alpn_protocols(["http/1.1"])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(1)
print("READY", flush=True)
c, _ = s.accept()
try:
    t = ctx.wrap_socket(c, server_side=True)
    t.recv(8192)
    t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    t.close()
except Exception as e:
    pass
s.close()
"#;
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(port.to_string())
        .arg(&certs.leaf_cert)
        .arg(&certs.leaf_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn python3");
    let stdout = child.stdout.take().expect("python stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("python ready line");
    assert!(
        line.contains("READY"),
        "python server did not start: {line}"
    );

    let (stream, body) = http_get(port, &local_cfg(ca));
    assert_eq!(stream.version(), TlsVersion::Tls13);
    assert_eq!(stream.alpn(), Some("http/1.1"));
    assert!(
        body.starts_with("HTTP/1.1 200"),
        "unexpected response: {body:?}"
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn python_large_bidirectional_records() {
    if !have_python() || !have_openssl() {
        eprintln!("skipping Python large-I/O test: python3/openssl not found");
        return;
    }
    let certs = make_certs("python-large", "rsa");
    let ca = certs.ca_pem.clone();
    let port = free_port();
    let script = r#"
import socket, ssl, sys
port = int(sys.argv[1]); cert = sys.argv[2]; key = sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(1)
print("READY", flush=True)
c, _ = s.accept()
t = ctx.wrap_socket(c, server_side=True)
got = 0
while got < 40000:
    chunk = t.recv(65536)
    if not chunk:
        break
    got += len(chunk)
if got != 40000:
    sys.exit(2)
t.sendall(b"B" * 40000)
t.close()
s.close()
"#;
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(port.to_string())
        .arg(&certs.leaf_cert)
        .arg(&certs.leaf_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn python3");
    let stdout = child.stdout.take().expect("python stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("python ready line");
    assert!(
        line.contains("READY"),
        "python server did not start: {line}"
    );

    let mut stream = connect_ok(port, &local_cfg(ca));
    let request = vec![b'A'; 40_000];
    stream.write_all(&request).expect("write large request");
    stream.flush().expect("flush large request");

    let mut got = Vec::new();
    let mut buf = [0u8; 777];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            // Python's SSLSocket::close() does not always send close_notify;
            // the length assertion below still proves no truncation.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("large read failed: {e}"),
        }
    }
    assert_eq!(got.len(), 40_000);
    assert!(got.iter().all(|b| *b == b'B'));

    let _ = child.kill();
    let _ = child.wait();
}

// ------------------------------------------------------------ live network

fn live_handshake(host: &str) -> (String, TlsVersion, Option<String>) {
    let addrs: Vec<_> = (host, 443u16)
        .to_socket_addrs()
        .unwrap_or_else(|e| panic!("resolve {host}: {e}"))
        .collect();
    assert!(!addrs.is_empty(), "no addresses for {host}");
    let mut last = String::new();
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(tcp) => {
                let _ = tcp.set_read_timeout(Some(Duration::from_secs(20)));
                let _ = tcp.set_write_timeout(Some(Duration::from_secs(20)));
                let cfg = TlsConfig::new(host);
                let mut stream = match TlsStream::connect(tcp, &cfg) {
                    Ok(s) => s,
                    Err(e) => {
                        last = format!("{addr}: {e}");
                        continue;
                    }
                };
                let version = stream.version();
                let alpn = stream.alpn().map(|s| s.to_string());
                stream
                    .write_all(
                        format!(
                            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: emerag-tls-test\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .expect("write live request");
                stream.flush().expect("flush live request");
                let mut out = Vec::new();
                let mut buf = [0u8; 8192];
                while out.len() < 65_536 {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            out.extend_from_slice(&buf[..n]);
                            if out.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(e) => panic!("{host}: read failed: {e}"),
                    }
                }
                return (String::from_utf8_lossy(&out).into_owned(), version, alpn);
            }
            Err(e) => last = format!("{addr}: {e}"),
        }
    }
    panic!("could not connect to {host}:443 ({last})")
}

fn assert_http_status(host: &str, body: &str, allow_unauthorized: bool) {
    assert!(
        body.starts_with("HTTP/1.1 ") || body.starts_with("HTTP/1.0 "),
        "{host}: not an HTTP response: {:?}",
        &body[..body.len().min(200)]
    );
    let status: u16 = body
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(
        status >= 200 && status < 400 || (allow_unauthorized && status == 401),
        "{host}: unexpected HTTP status {status}"
    );
}

#[test]
#[ignore = "network"]
fn live_example_com() {
    let (body, version, _alpn) = live_handshake("example.com");
    assert_eq!(version, TlsVersion::Tls13);
    assert_http_status("example.com", &body, false);
}

#[test]
#[ignore = "network"]
fn live_github_com() {
    let (body, version, _alpn) = live_handshake("github.com");
    assert_eq!(version, TlsVersion::Tls13);
    assert_http_status("github.com", &body, false);
}

#[test]
#[ignore = "network"]
fn live_api_github_com() {
    let (body, version, _alpn) = live_handshake("api.github.com");
    assert_eq!(version, TlsVersion::Tls13);
    assert_http_status("api.github.com", &body, false);
}

#[test]
#[ignore = "network"]
fn live_api_deepseek_com() {
    // The API root answers 401 without credentials; the point of this test is
    // the TLS 1.3 handshake through DeepSeek's P-384 chain.
    let (body, version, _alpn) = live_handshake("api.deepseek.com");
    assert_eq!(version, TlsVersion::Tls13);
    assert_http_status("api.deepseek.com", &body, true);
}
