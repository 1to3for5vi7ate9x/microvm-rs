//! Guest-side outbound proxy client.
//!
//! This binary runs in the guest VM and provides a SOCKS5-like proxy
//! that forwards connections through the host via vsock.
//!
//! Usage:
//!   outbound-proxy [--listen 127.0.0.1:1080] [--vsock-port 7601]

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, Ipv4Addr, SocketAddr};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

/// Default vsock port for the outbound proxy on host.
const DEFAULT_VSOCK_PORT: u32 = 7601;
/// Host CID (always 2 for vsock).
const HOST_CID: u32 = 2;

/// Connection ID counter.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Proxy protocol message types.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum PacketType {
    Connect = 0x01,
    Response = 0x02,
    Data = 0x03,
    Close = 0x04,
}

/// Proxy packet header.
struct ProxyPacket {
    pkt_type: PacketType,
    conn_key: u64,
    payload_len: u32,
}

impl ProxyPacket {
    const HEADER_SIZE: usize = 13;

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE);
        buf.push(self.pkt_type as u8);
        buf.extend_from_slice(&self.conn_key.to_le_bytes());
        buf.extend_from_slice(&self.payload_len.to_le_bytes());
        buf
    }

    fn decode(data: &[u8]) -> io::Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Packet too short"));
        }
        let pkt_type = match data[0] {
            0x01 => PacketType::Connect,
            0x02 => PacketType::Response,
            0x03 => PacketType::Data,
            0x04 => PacketType::Close,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid packet type")),
        };
        let conn_key = u64::from_le_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]);
        let payload_len = u32::from_le_bytes([data[9], data[10], data[11], data[12]]);
        Ok(Self { pkt_type, conn_key, payload_len })
    }
}

/// Connect request for the proxy.
struct ConnectRequest {
    addr_type: u8, // 0x01 = IPv4, 0x03 = Domain
    address: Vec<u8>,
    port: u16,
}

impl ConnectRequest {
    fn ipv4(addr: Ipv4Addr, port: u16) -> Self {
        Self {
            addr_type: 0x01,
            address: addr.octets().to_vec(),
            port,
        }
    }

    fn domain(name: &str, port: u16) -> Self {
        Self {
            addr_type: 0x03,
            address: name.as_bytes().to_vec(),
            port,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let addr_len = self.address.len() as u16;
        let mut buf = Vec::with_capacity(6 + self.address.len());
        buf.push(0x01); // MessageType::Connect
        buf.push(self.addr_type);
        buf.extend_from_slice(&addr_len.to_le_bytes());
        buf.extend_from_slice(&self.address);
        buf.extend_from_slice(&self.port.to_le_bytes());
        buf
    }
}

/// Connect to vsock.
fn connect_vsock(cid: u32, port: u32) -> io::Result<i32> {
    use std::os::unix::io::FromRawFd;

    // AF_VSOCK = 40, SOCK_STREAM = 1
    let fd = unsafe { libc::socket(40, 1, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // sockaddr_vm structure
    #[repr(C)]
    struct SockaddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    let addr = SockaddrVm {
        svm_family: 40, // AF_VSOCK
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0; 4],
    };

    let ret = unsafe {
        libc::connect(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as u32,
        )
    };

    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}

/// Handle a SOCKS5 client connection.
fn handle_socks5_client(mut client: TcpStream, vsock_port: u32) -> io::Result<()> {
    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
    eprintln!("[PROXY] Connection {} from {:?}", conn_id, client.peer_addr());

    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    client.set_write_timeout(Some(Duration::from_secs(30)))?;

    // SOCKS5 greeting
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting)?;
    eprintln!("[PROXY] Greeting bytes: {:02x} {:02x}", greeting[0], greeting[1]);

    if greeting[0] != 0x05 {
        eprintln!("[PROXY] Not SOCKS5: expected 0x05, got 0x{:02x}", greeting[0]);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Not SOCKS5"));
    }

    let nmethods = greeting[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods)?;

    // No auth required
    client.write_all(&[0x05, 0x00])?;

    // SOCKS5 request
    let mut request = [0u8; 4];
    client.read_exact(&mut request)?;
    eprintln!("[PROXY] Request bytes: {:02x} {:02x} {:02x} {:02x} (ver={}, cmd={}, atyp={})",
             request[0], request[1], request[2], request[3],
             request[0], request[1], request[3]);

    if request[0] != 0x05 || request[1] != 0x01 {
        // Only CONNECT (0x01) supported, not BIND (0x02) or UDP ASSOCIATE (0x03)
        eprintln!("[PROXY] Unsupported command: {} (expected 0x01 CONNECT)", request[1]);
        client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Only CONNECT supported"));
    }

    let atyp = request[3];
    let (connect_req, dest_desc) = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr)?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf)?;
            let port = u16::from_be_bytes(port_buf);
            let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            (ConnectRequest::ipv4(ip, port), format!("{}:{}", ip, port))
        }
        0x03 => {
            // Domain
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf)?;
            let mut domain = vec![0u8; len_buf[0] as usize];
            client.read_exact(&mut domain)?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf)?;
            let port = u16::from_be_bytes(port_buf);
            let domain_str = String::from_utf8_lossy(&domain).to_string();
            (ConnectRequest::domain(&domain_str, port), format!("{}:{}", domain_str, port))
        }
        _ => {
            client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported address type"));
        }
    };

    eprintln!("[PROXY] Connection {} -> {}", conn_id, dest_desc);

    // Connect to host proxy via vsock
    let vsock_fd = match connect_vsock(HOST_CID, vsock_port) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("[PROXY] Failed to connect to host proxy: {}", e);
            client.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
            return Err(e);
        }
    };

    // Send CONNECT request to host
    let pkt_header = ProxyPacket {
        pkt_type: PacketType::Connect,
        conn_key: conn_id,
        payload_len: connect_req.encode().len() as u32,
    };

    let mut vsock_buf = pkt_header.encode();
    vsock_buf.extend_from_slice(&connect_req.encode());

    unsafe {
        if libc::write(vsock_fd, vsock_buf.as_ptr() as *const libc::c_void, vsock_buf.len()) < 0 {
            libc::close(vsock_fd);
            client.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
            return Err(io::Error::last_os_error());
        }
    }

    // Read response from host
    let mut response_buf = [0u8; ProxyPacket::HEADER_SIZE + 4];
    let mut total_read = 0;
    while total_read < response_buf.len() {
        let n = unsafe {
            libc::read(
                vsock_fd,
                response_buf[total_read..].as_mut_ptr() as *mut libc::c_void,
                response_buf.len() - total_read,
            )
        };
        if n <= 0 {
            unsafe { libc::close(vsock_fd) };
            client.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "No response from host"));
        }
        total_read += n as usize;
    }

    let resp_pkt = ProxyPacket::decode(&response_buf)?;
    if resp_pkt.pkt_type as u8 != PacketType::Response as u8 {
        unsafe { libc::close(vsock_fd) };
        client.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid response"));
    }

    // Response payload: type(1) + status(1) + bound_port(2)
    let status = response_buf[ProxyPacket::HEADER_SIZE + 1];
    if status != 0x00 {
        unsafe { libc::close(vsock_fd) };
        let socks_err = match status {
            0x02 => 0x05, // Connection refused
            0x03 => 0x04, // Host unreachable
            0x04 => 0x03, // Network unreachable
            _ => 0x01,    // General failure
        };
        client.write_all(&[0x05, socks_err, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "Host proxy refused"));
    }

    // Success - send SOCKS5 success response
    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
    eprintln!("[PROXY] Connection {} established", conn_id);

    // Relay data bidirectionally
    client.set_nonblocking(true)?;

    // Set vsock to non-blocking too to avoid deadlock
    unsafe {
        let flags = libc::fcntl(vsock_fd, libc::F_GETFL);
        libc::fcntl(vsock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let mut client_buf = [0u8; 8192];
    let mut vsock_header_buf = [0u8; ProxyPacket::HEADER_SIZE];
    let mut loop_count: u64 = 0;

    eprintln!("[PROXY] Connection {} entering relay loop", conn_id);

    loop {
        loop_count += 1;
        if loop_count % 10000 == 0 {
            eprintln!("[PROXY] Connection {} relay loop iteration {}", conn_id, loop_count);
        }
        let mut activity = false;

        // Read from client, send to vsock
        match client.read(&mut client_buf) {
            Ok(0) => {
                // Client closed
                eprintln!("[PROXY] Connection {} client closed (read returned 0)", conn_id);
                break;
            }
            Ok(n) => {
                activity = true;
                let pkt = ProxyPacket {
                    pkt_type: PacketType::Data,
                    conn_key: conn_id,
                    payload_len: n as u32,
                };
                // Combine header and data into single buffer to ensure single write
                let header = pkt.encode();
                let mut combined = Vec::with_capacity(header.len() + n);
                combined.extend_from_slice(&header);
                combined.extend_from_slice(&client_buf[..n]);
                unsafe {
                    libc::write(vsock_fd, combined.as_ptr() as *const libc::c_void, combined.len());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("[PROXY] Connection {} client read error: {}", conn_id, e);
                break;
            }
        }

        // Read from vsock, send to client
        // First, read the complete header (13 bytes) with retry for partial reads
        let mut header_read = 0;
        let mut header_retries = 0;
        while header_read < vsock_header_buf.len() && header_retries < 50 {
            let n = unsafe {
                libc::read(
                    vsock_fd,
                    vsock_header_buf[header_read..].as_mut_ptr() as *mut libc::c_void,
                    vsock_header_buf.len() - header_read,
                )
            };
            if n > 0 {
                header_read += n as usize;
                header_retries = 0;
            } else if n == 0 {
                eprintln!("[PROXY] Connection {} vsock EOF during header read (header_read={})", conn_id, header_read);
                break; // EOF
            } else {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    if header_read == 0 {
                        // No data at all, break out and continue loop
                        break;
                    }
                    // Partial read, wait for more
                    header_retries += 1;
                    thread::sleep(Duration::from_micros(100));
                } else {
                    eprintln!("[PROXY] Connection {} vsock read error: errno={}", conn_id, errno);
                    break; // Real error
                }
            }
        }

        if header_read == vsock_header_buf.len() {
            activity = true;
            if let Ok(pkt) = ProxyPacket::decode(&vsock_header_buf) {
                match pkt.pkt_type {
                    PacketType::Data => {
                        let mut data = vec![0u8; pkt.payload_len as usize];
                        let mut read = 0;
                        let mut retries = 0;
                        while read < data.len() && retries < 100 {
                            let r = unsafe {
                                libc::read(
                                    vsock_fd,
                                    data[read..].as_mut_ptr() as *mut libc::c_void,
                                    data.len() - read,
                                )
                            };
                            if r > 0 {
                                read += r as usize;
                                retries = 0;
                            } else if r == 0 {
                                break; // EOF
                            } else {
                                // r < 0: check for EAGAIN
                                let errno = unsafe { *libc::__errno_location() };
                                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                                    retries += 1;
                                    thread::sleep(Duration::from_micros(100));
                                } else {
                                    break; // Real error
                                }
                            }
                        }
                        if read > 0 {
                            let _ = client.write_all(&data[..read]);
                        }
                    }
                    PacketType::Close => {
                        eprintln!("[PROXY] Connection {} received CLOSE from host", conn_id);
                        break;
                    }
                    _ => {}
                }
            }
        }

        if !activity {
            thread::sleep(Duration::from_millis(1));
        }
    }

    // Send close packet
    let close_pkt = ProxyPacket {
        pkt_type: PacketType::Close,
        conn_key: conn_id,
        payload_len: 0,
    };
    let close_buf = close_pkt.encode();
    unsafe {
        libc::write(vsock_fd, close_buf.as_ptr() as *const libc::c_void, close_buf.len());
        libc::close(vsock_fd);
    }

    eprintln!("[PROXY] Connection {} closed after {} iterations", conn_id, loop_count);
    Ok(())
}

/// Test vsock connectivity by connecting to host proxy port
fn test_vsock_connectivity() {
    use std::io::Write as _;
    let _ = writeln!(io::stderr(), "[PROXY] Testing vsock connectivity to host proxy (CID={}, port={})...", HOST_CID, DEFAULT_VSOCK_PORT);
    let _ = io::stderr().flush();

    // Just test that we can connect to the host proxy port
    match connect_vsock(HOST_CID, DEFAULT_VSOCK_PORT) {
        Ok(fd) => {
            let _ = writeln!(io::stderr(), "[PROXY] Vsock to host proxy port {} - OK", DEFAULT_VSOCK_PORT);
            let _ = io::stderr().flush();
            unsafe { libc::close(fd) };
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "[PROXY] Vsock to host proxy port {} - FAILED: {}", DEFAULT_VSOCK_PORT, e);
            let _ = io::stderr().flush();
        }
    }
}

fn main() -> io::Result<()> {
    // Very early startup log - before anything else
    {
        use std::io::Write as _;
        let _ = writeln!(io::stderr(), "[PROXY] === OUTBOUND-PROXY STARTING ===");
        let _ = io::stderr().flush();
    }

    let args: Vec<String> = std::env::args().collect();

    let mut listen_addr = "127.0.0.1:1080".to_string();
    let mut vsock_port = DEFAULT_VSOCK_PORT;
    let mut test_vsock = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" | "-l" => {
                if i + 1 < args.len() {
                    listen_addr = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--vsock-port" | "-p" => {
                if i + 1 < args.len() {
                    vsock_port = args[i + 1].parse().unwrap_or(DEFAULT_VSOCK_PORT);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--test" | "-t" => {
                test_vsock = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    // Use write! with explicit flush to ensure output is captured
    use std::io::Write as _;
    let _ = writeln!(io::stderr(), "[PROXY] Starting outbound proxy");
    let _ = writeln!(io::stderr(), "[PROXY] SOCKS5 listen: {}", listen_addr);
    let _ = writeln!(io::stderr(), "[PROXY] Vsock host port: {}", vsock_port);
    let _ = io::stderr().flush();

    // Always test vsock connectivity on startup
    test_vsock_connectivity();

    // If --test flag, also test the proxy port specifically
    if test_vsock {
        let _ = writeln!(io::stderr(), "[PROXY] Testing vsock to proxy port {}...", vsock_port);
        let _ = io::stderr().flush();
        match connect_vsock(HOST_CID, vsock_port) {
            Ok(fd) => {
                let _ = writeln!(io::stderr(), "[PROXY] Proxy port {} reachable!", vsock_port);
                unsafe { libc::close(fd) };
            }
            Err(e) => {
                let _ = writeln!(io::stderr(), "[PROXY] Proxy port {} FAILED: {}", vsock_port, e);
            }
        }
        let _ = io::stderr().flush();
    }

    let _ = writeln!(io::stderr(), "[PROXY] Attempting to bind to {}...", listen_addr);
    let _ = io::stderr().flush();

    let listener = match TcpListener::bind(&listen_addr) {
        Ok(l) => {
            let _ = writeln!(io::stderr(), "[PROXY] Successfully bound to {}", listen_addr);
            let _ = io::stderr().flush();
            l
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "[PROXY] FAILED to bind to {}: {}", listen_addr, e);
            let _ = io::stderr().flush();
            return Err(e);
        }
    };

    let _ = writeln!(io::stderr(), "[PROXY] Listening on {}", listen_addr);
    let _ = io::stderr().flush();

    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                let port = vsock_port;
                thread::spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handle_socks5_client(client, port)
                    }));
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => eprintln!("[PROXY] Error: {}", e),
                        Err(panic) => eprintln!("[PROXY] PANIC in connection handler: {:?}", panic),
                    }
                });
            }
            Err(e) => {
                eprintln!("[PROXY] Accept error: {}", e);
            }
        }
    }

    Ok(())
}
