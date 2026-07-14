//! Host-side outbound TCP connectors for the virtio-net gateway.
//!
//! The guest-facing TCP stack is terminated by smoltcp. This module owns the
//! other half of each connection: either a normal host TCP connection or a
//! SOCKS5 CONNECT tunnel. Proxy credentials are deliberately hidden from
//! `Debug`, `Display`, and every generated error.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

const DEFAULT_SOCKS_PORT: u16 = 1080;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CANCELLATION_SLICE: Duration = Duration::from_millis(100);

/// A launch-only SOCKS5 endpoint.
///
/// The original URI is retained solely for the narrow parent-to-boot-child
/// handoff. Its custom formatting implementations never expose userinfo.
#[derive(Clone, PartialEq, Eq)]
pub struct EgressProxy {
    raw: String,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl EgressProxy {
    /// The proxy host without credentials.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The proxy TCP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Return the secret URI for the one per-launch child handoff.
    ///
    /// Callers must never log or persist this value.
    pub fn expose_secret(&self) -> &str {
        &self.raw
    }

    /// Whether RFC 1929 username/password negotiation is configured.
    pub fn has_auth(&self) -> bool {
        self.username.is_some()
    }

    fn endpoint(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Debug for EgressProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressProxy")
            .field("endpoint", &self.endpoint())
            .field("auth", &self.has_auth())
            .finish()
    }
}

impl fmt::Display for EgressProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.has_auth() {
            write!(f, "socks5://<redacted>@{}", self.endpoint())
        } else {
            write!(f, "socks5://{}", self.endpoint())
        }
    }
}

impl FromStr for EgressProxy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let rest = value
            .strip_prefix("socks5://")
            .ok_or_else(|| "egress proxy must use the socks5:// scheme".to_string())?;
        if rest.is_empty() || rest.contains(['/', '?', '#']) {
            return Err("egress proxy must contain only SOCKS5 userinfo and host:port".into());
        }

        let (userinfo, endpoint) = match rest.rsplit_once('@') {
            Some((userinfo, endpoint)) => (Some(userinfo), endpoint),
            None => (None, rest),
        };
        let (host, port) = parse_endpoint(endpoint)?;

        let (username, password) = match userinfo {
            Some(userinfo) => {
                let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
                let username = percent_decode(username)?;
                let password = percent_decode(password)?;
                if username.is_empty() {
                    return Err("SOCKS5 username cannot be empty".into());
                }
                if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                    return Err("SOCKS5 username and password must be at most 255 bytes".into());
                }
                (Some(username), Some(password))
            }
            None => (None, None),
        };

        Ok(Self {
            raw: value.to_string(),
            host,
            port,
            username,
            password,
        })
    }
}

fn parse_endpoint(endpoint: &str) -> Result<(String, u16), String> {
    if let Some(bracketed) = endpoint.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or_else(|| "invalid bracketed SOCKS5 proxy address".to_string())?;
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        let port = if suffix.is_empty() {
            DEFAULT_SOCKS_PORT
        } else {
            suffix
                .strip_prefix(':')
                .ok_or_else(|| "invalid SOCKS5 proxy port".to_string())?
                .parse::<u16>()
                .map_err(|_| "invalid SOCKS5 proxy port".to_string())?
        };
        if host.is_empty() || port == 0 {
            return Err("SOCKS5 proxy host and port must be non-empty".into());
        }
        return Ok((host.to_string(), port));
    }

    let (host, port) = match endpoint.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (
            host,
            port.parse::<u16>()
                .map_err(|_| "invalid SOCKS5 proxy port".to_string())?,
        ),
        Some(_) => {
            return Err("IPv6 SOCKS5 proxy addresses must be enclosed in brackets".into());
        }
        None => (endpoint, DEFAULT_SOCKS_PORT),
    };
    if host.is_empty() || port == 0 {
        return Err("SOCKS5 proxy host and port must be non-empty".into());
    }
    Ok((host.to_string(), port))
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let pair = bytes
                .get(index + 1..index + 3)
                .ok_or_else(|| "invalid percent escape in SOCKS5 credentials".to_string())?;
            let hi = hex_value(pair[0])?;
            let lo = hex_value(pair[1])?;
            decoded.push((hi << 4) | lo);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| "SOCKS5 credentials must be valid UTF-8".into())
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid percent escape in SOCKS5 credentials".into()),
    }
}

/// The destination requested by a guest TCP flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectTarget {
    /// A literal IPv4 or IPv6 destination.
    Ip(SocketAddr),
    /// A hostname recovered from the virtual-DNS mapping.
    Domain { hostname: String, port: u16 },
}

impl ConnectTarget {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(address) => address.port(),
            Self::Domain { port, .. } => *port,
        }
    }
}

/// Cooperative cancellation shared by the network runtime and relay workers.
#[derive(Clone, Debug, Default)]
pub struct ConnectCancellation(Arc<AtomicBool>);

impl ConnectCancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Opens the host-side stream for one guest TCP flow.
pub trait OutboundConnector: Send + Sync + fmt::Debug {
    fn connect(
        &self,
        target: &ConnectTarget,
        cancellation: &ConnectCancellation,
    ) -> io::Result<TcpStream>;

    fn proxy_mode(&self) -> bool {
        false
    }
}

/// Existing behavior: connect directly from the host.
#[derive(Debug, Default)]
pub struct DirectConnector;

impl OutboundConnector for DirectConnector {
    fn connect(
        &self,
        target: &ConnectTarget,
        cancellation: &ConnectCancellation,
    ) -> io::Result<TcpStream> {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        match target {
            ConnectTarget::Ip(address) => TcpStream::connect(address),
            ConnectTarget::Domain { hostname, port } => {
                TcpStream::connect((hostname.as_str(), *port))
            }
        }
    }
}

/// RFC 1928 SOCKS5 CONNECT with optional RFC 1929 authentication.
#[derive(Clone)]
pub struct Socks5Connector {
    proxy: EgressProxy,
    timeout: Duration,
}

impl Socks5Connector {
    pub fn new(proxy: EgressProxy) -> Self {
        Self {
            proxy,
            timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_timeout(proxy: EgressProxy, timeout: Duration) -> Self {
        Self { proxy, timeout }
    }
}

impl fmt::Debug for Socks5Connector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Connector")
            .field("proxy", &self.proxy)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl OutboundConnector for Socks5Connector {
    fn connect(
        &self,
        target: &ConnectTarget,
        cancellation: &ConnectCancellation,
    ) -> io::Result<TcpStream> {
        let deadline = Instant::now() + self.timeout;
        let addresses = resolve_proxy(&self.proxy, deadline, cancellation)?;
        let mut last_error = None;
        let mut stream = None;
        for address in addresses {
            match connect_with_cancellation(address, deadline, cancellation) {
                Ok(connected) => {
                    stream = Some(connected);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let mut stream = stream.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "SOCKS5 proxy has no addresses",
                )
            })
        })?;

        let methods: &[u8] = if self.proxy.username.is_some() {
            &[0x05, 0x01, 0x02]
        } else {
            &[0x05, 0x01, 0x00]
        };
        write_deadline(&mut stream, methods, deadline, cancellation)?;
        let mut selection = [0u8; 2];
        read_deadline(&mut stream, &mut selection, deadline, cancellation)?;
        if selection[0] != 0x05 {
            return Err(protocol_error("SOCKS5 proxy returned an invalid version"));
        }
        match selection[1] {
            0x00 if self.proxy.username.is_none() => {}
            0x00 => {
                return Err(protocol_error(
                    "SOCKS5 proxy selected an authentication method that was not offered",
                ));
            }
            0x02 => self.authenticate(&mut stream, deadline, cancellation)?,
            0xff => {
                return Err(protocol_error(
                    "SOCKS5 proxy rejected all authentication methods",
                ))
            }
            _ => {
                return Err(protocol_error(
                    "SOCKS5 proxy selected an unsupported authentication method",
                ))
            }
        }

        let request = connect_request(target)?;
        write_deadline(&mut stream, &request, deadline, cancellation)?;
        let mut header = [0u8; 4];
        read_deadline(&mut stream, &mut header, deadline, cancellation)?;
        if header[0] != 0x05 || header[2] != 0x00 {
            return Err(protocol_error(
                "SOCKS5 proxy returned an invalid CONNECT reply",
            ));
        }
        if header[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("SOCKS5 CONNECT failed with reply code 0x{:02x}", header[1]),
            ));
        }
        consume_bound_address(&mut stream, header[3], deadline, cancellation)?;
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        Ok(stream)
    }

    fn proxy_mode(&self) -> bool {
        true
    }
}

impl Socks5Connector {
    fn authenticate(
        &self,
        stream: &mut TcpStream,
        deadline: Instant,
        cancellation: &ConnectCancellation,
    ) -> io::Result<()> {
        let username = self.proxy.username.as_deref().ok_or_else(|| {
            protocol_error("SOCKS5 proxy requires username/password authentication")
        })?;
        let password = self.proxy.password.as_deref().unwrap_or("");
        let mut request = Vec::with_capacity(username.len() + password.len() + 3);
        request.extend_from_slice(&[0x01, username.len() as u8]);
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());
        write_deadline(stream, &request, deadline, cancellation)?;
        let mut response = [0u8; 2];
        read_deadline(stream, &mut response, deadline, cancellation)?;
        if response != [0x01, 0x00] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 username/password authentication failed",
            ));
        }
        Ok(())
    }
}

fn resolve_proxy(
    proxy: &EgressProxy,
    deadline: Instant,
    cancellation: &ConnectCancellation,
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = proxy.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, proxy.port)]);
    }
    let endpoint = proxy.endpoint();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("smolvm-proxy-dns".into())
        .spawn(move || {
            let result = endpoint.to_socket_addrs().map(|addrs| addrs.collect());
            let _ = sender.send(result);
        })
        .map_err(io::Error::other)?;
    loop {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let remaining = remaining(deadline)?;
        match receiver.recv_timeout(remaining.min(CANCELLATION_SLICE)) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "SOCKS5 proxy address resolution failed",
                ));
            }
        }
    }
}

fn connect_with_cancellation(
    address: SocketAddr,
    deadline: Instant,
    cancellation: &ConnectCancellation,
) -> io::Result<TcpStream> {
    loop {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let timeout = remaining(deadline)?.min(CANCELLATION_SLICE);
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
            Err(error) => return Err(error),
        }
    }
}

fn connect_request(target: &ConnectTarget) -> io::Result<Vec<u8>> {
    let mut request = vec![0x05, 0x01, 0x00];
    match target {
        ConnectTarget::Ip(SocketAddr::V4(address)) => {
            request.push(0x01);
            request.extend_from_slice(&address.ip().octets());
        }
        ConnectTarget::Ip(SocketAddr::V6(address)) => {
            request.push(0x04);
            request.extend_from_slice(&address.ip().octets());
        }
        ConnectTarget::Domain { hostname, .. } => {
            let hostname = hostname.as_bytes();
            if hostname.is_empty() || hostname.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 target hostname must be between 1 and 255 bytes",
                ));
            }
            request.extend_from_slice(&[0x03, hostname.len() as u8]);
            request.extend_from_slice(hostname);
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    Ok(request)
}

fn consume_bound_address(
    stream: &mut TcpStream,
    address_type: u8,
    deadline: Instant,
    cancellation: &ConnectCancellation,
) -> io::Result<()> {
    let address_len = match address_type {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            read_deadline(stream, &mut len, deadline, cancellation)?;
            len[0] as usize
        }
        _ => {
            return Err(protocol_error(
                "SOCKS5 proxy returned an invalid address type",
            ))
        }
    };
    let mut remainder = vec![0u8; address_len + 2];
    read_deadline(stream, &mut remainder, deadline, cancellation)
}

fn write_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
    cancellation: &ConnectCancellation,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        stream.set_write_timeout(Some(remaining(deadline)?.min(CANCELLATION_SLICE)))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "SOCKS5 proxy wrote zero bytes",
                ))
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_deadline(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: Instant,
    cancellation: &ConnectCancellation,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        stream.set_read_timeout(Some(remaining(deadline)?.min(CANCELLATION_SLICE)))?;
        match stream.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "SOCKS5 proxy closed during negotiation",
                ))
            }
            Ok(read) => {
                let (_, rest) = bytes.split_at_mut(read);
                bytes = rest;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 proxy connection timed out"))
}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "outbound connection cancelled")
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Build the connector selected for this launch.
pub fn outbound_connector(proxy: Option<EgressProxy>) -> Arc<dyn OutboundConnector> {
    match proxy {
        Some(proxy) => Arc::new(Socks5Connector::new(proxy)),
        None => Arc::new(DirectConnector),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;

    #[test]
    fn parses_and_redacts_proxy_credentials() {
        let proxy: EgressProxy = "socks5://hello%40world:s3cr%25t@127.0.0.1:9999"
            .parse()
            .unwrap();
        assert_eq!(proxy.username.as_deref(), Some("hello@world"));
        assert_eq!(proxy.password.as_deref(), Some("s3cr%t"));
        assert!(!format!("{proxy:?}").contains("hello"));
        assert!(!proxy.to_string().contains("s3cr"));
        assert_eq!(
            proxy.expose_secret(),
            "socks5://hello%40world:s3cr%25t@127.0.0.1:9999"
        );
    }

    #[test]
    fn rejects_non_socks_and_malformed_proxy_uris() {
        for value in [
            "http://127.0.0.1",
            "socks5://",
            "socks5://:80",
            "socks5://[::1",
        ] {
            assert!(value.parse::<EgressProxy>().is_err(), "accepted {value}");
        }
    }

    #[test]
    fn direct_connector_regression() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || listener.accept().unwrap().0);
        let stream = DirectConnector
            .connect(&ConnectTarget::Ip(address), &ConnectCancellation::default())
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), address);
        drop(stream);
        drop(server.join().unwrap());
    }

    fn fake_socks(
        auth: Option<(&'static str, &'static str)>,
        reply: u8,
    ) -> (SocketAddr, mpsc::Receiver<ConnectTarget>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (target_tx, target_rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = [0u8; 2];
            stream.read_exact(&mut header).unwrap();
            let mut methods = vec![0u8; header[1] as usize];
            stream.read_exact(&mut methods).unwrap();
            if let Some((username, password)) = auth {
                assert!(methods.contains(&0x02));
                stream.write_all(&[0x05, 0x02]).unwrap();
                let mut auth_header = [0u8; 2];
                stream.read_exact(&mut auth_header).unwrap();
                let mut user = vec![0u8; auth_header[1] as usize];
                stream.read_exact(&mut user).unwrap();
                let mut pass_len = [0u8; 1];
                stream.read_exact(&mut pass_len).unwrap();
                let mut pass = vec![0u8; pass_len[0] as usize];
                stream.read_exact(&mut pass).unwrap();
                assert_eq!(user, username.as_bytes());
                assert_eq!(pass, password.as_bytes());
                stream.write_all(&[0x01, 0x00]).unwrap();
            } else {
                assert!(methods.contains(&0x00));
                stream.write_all(&[0x05, 0x00]).unwrap();
            }

            let mut request_header = [0u8; 4];
            stream.read_exact(&mut request_header).unwrap();
            let target = match request_header[3] {
                0x01 => {
                    let mut bytes = [0u8; 6];
                    stream.read_exact(&mut bytes).unwrap();
                    ConnectTarget::Ip(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
                        u16::from_be_bytes([bytes[4], bytes[5]]),
                    ))
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).unwrap();
                    let mut host = vec![0u8; len[0] as usize];
                    stream.read_exact(&mut host).unwrap();
                    let mut port = [0u8; 2];
                    stream.read_exact(&mut port).unwrap();
                    ConnectTarget::Domain {
                        hostname: String::from_utf8(host).unwrap(),
                        port: u16::from_be_bytes(port),
                    }
                }
                other => panic!("unexpected address type {other}"),
            };
            let _ = target_tx.send(target);
            stream
                .write_all(&[0x05, reply, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .unwrap();
        });
        (address, target_rx)
    }

    #[test]
    fn socks5_no_auth_domain_and_ipv4_connect() {
        for target in [
            ConnectTarget::Domain {
                hostname: "example.test".into(),
                port: 443,
            },
            ConnectTarget::Ip("203.0.113.7:80".parse().unwrap()),
        ] {
            let (proxy_address, received) = fake_socks(None, 0x00);
            let connector =
                Socks5Connector::new(format!("socks5://{proxy_address}").parse().unwrap());
            let stream = connector
                .connect(&target, &ConnectCancellation::default())
                .unwrap();
            assert_eq!(received.recv().unwrap(), target);
            drop(stream);
        }
    }

    #[test]
    fn socks5_username_password_authentication() {
        let (proxy_address, received) = fake_socks(Some(("user", "pass")), 0x00);
        let connector = Socks5Connector::new(
            format!("socks5://user:pass@{proxy_address}")
                .parse()
                .unwrap(),
        );
        let target = ConnectTarget::Domain {
            hostname: "auth.test".into(),
            port: 8443,
        };
        connector
            .connect(&target, &ConnectCancellation::default())
            .unwrap();
        assert_eq!(received.recv().unwrap(), target);
    }

    #[test]
    fn socks5_failure_reply_is_bounded_and_redacted() {
        let (proxy_address, _) = fake_socks(Some(("secret-user", "secret-pass")), 0x05);
        let connector = Socks5Connector::new(
            format!("socks5://secret-user:secret-pass@{proxy_address}")
                .parse()
                .unwrap(),
        );
        let error = connector
            .connect(
                &ConnectTarget::Domain {
                    hostname: "failure.test".into(),
                    port: 443,
                },
                &ConnectCancellation::default(),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("0x05"));
        assert!(!error.contains("secret-user"));
        assert!(!error.contains("secret-pass"));
    }

    #[test]
    fn socks5_handshake_timeout_and_cancellation() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let _server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_secs(1));
        });
        let connector = Socks5Connector::with_timeout(
            format!("socks5://{address}").parse().unwrap(),
            Duration::from_millis(80),
        );
        let error = connector
            .connect(
                &ConnectTarget::Ip("203.0.113.1:443".parse().unwrap()),
                &ConnectCancellation::default(),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let _server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_secs(1));
        });
        let cancellation = ConnectCancellation::default();
        let cancel = cancellation.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            cancel.cancel();
        });
        let connector = Socks5Connector::new(format!("socks5://{address}").parse().unwrap());
        let error = connector
            .connect(
                &ConnectTarget::Ip("203.0.113.1:443".parse().unwrap()),
                &cancellation,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn connector_construction_is_lazy_and_proxy_down_fails_promptly() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let proxy: EgressProxy = format!("socks5://{address}").parse().unwrap();
        let _connector = outbound_connector(Some(proxy.clone()));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        drop(listener);
        let connector = Socks5Connector::with_timeout(proxy, Duration::from_millis(250));
        let started = Instant::now();
        let error = connector
            .connect(
                &ConnectTarget::Ip("203.0.113.1:443".parse().unwrap()),
                &ConnectCancellation::default(),
            )
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused | io::ErrorKind::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
