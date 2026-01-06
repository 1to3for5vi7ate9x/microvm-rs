//! Simple SOCKS5 test client.
//!
//! Connects to a SOCKS5 proxy and makes an HTTP request.
//!
//! Usage: socks-test [proxy-addr] [target-host] [target-port]
//! Default: socks-test 127.0.0.1:1080 example.com 80

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let proxy_addr = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1:1080");
    let target_host = args.get(2).map(|s| s.as_str()).unwrap_or("example.com");
    let target_port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(80);

    eprintln!("[SOCKS-TEST] Connecting to proxy at {}...", proxy_addr);
    eprintln!("[SOCKS-TEST] Target: {}:{}", target_host, target_port);

    // Connect to SOCKS5 proxy
    let mut stream = match TcpStream::connect(proxy_addr) {
        Ok(s) => {
            eprintln!("[SOCKS-TEST] Connected to proxy");
            s
        }
        Err(e) => {
            eprintln!("[SOCKS-TEST] Failed to connect to proxy: {}", e);
            std::process::exit(1);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

    // SOCKS5 greeting: version=5, 1 method, no auth
    eprintln!("[SOCKS-TEST] Sending SOCKS5 greeting...");
    if let Err(e) = stream.write_all(&[0x05, 0x01, 0x00]) {
        eprintln!("[SOCKS-TEST] Failed to send greeting: {}", e);
        std::process::exit(1);
    }

    // Read response
    let mut response = [0u8; 2];
    if let Err(e) = stream.read_exact(&mut response) {
        eprintln!("[SOCKS-TEST] Failed to read greeting response: {}", e);
        std::process::exit(1);
    }

    if response[0] != 0x05 || response[1] != 0x00 {
        eprintln!("[SOCKS-TEST] Invalid greeting response: {:02x} {:02x}", response[0], response[1]);
        std::process::exit(1);
    }
    eprintln!("[SOCKS-TEST] Greeting accepted (no auth)");

    // SOCKS5 connect request
    // VER=5, CMD=CONNECT(1), RSV=0, ATYP=DOMAIN(3), domain_len, domain, port_hi, port_lo
    let mut request = Vec::new();
    request.push(0x05); // VER
    request.push(0x01); // CMD = CONNECT
    request.push(0x00); // RSV
    request.push(0x03); // ATYP = DOMAIN
    request.push(target_host.len() as u8);
    request.extend_from_slice(target_host.as_bytes());
    request.push((target_port >> 8) as u8);
    request.push((target_port & 0xff) as u8);

    eprintln!("[SOCKS-TEST] Sending CONNECT request...");
    if let Err(e) = stream.write_all(&request) {
        eprintln!("[SOCKS-TEST] Failed to send connect request: {}", e);
        std::process::exit(1);
    }

    // Read connect response (at least 10 bytes for IPv4)
    let mut connect_response = [0u8; 10];
    if let Err(e) = stream.read_exact(&mut connect_response) {
        eprintln!("[SOCKS-TEST] Failed to read connect response: {}", e);
        std::process::exit(1);
    }

    if connect_response[0] != 0x05 {
        eprintln!("[SOCKS-TEST] Invalid SOCKS version in response");
        std::process::exit(1);
    }

    if connect_response[1] != 0x00 {
        let error = match connect_response[1] {
            0x01 => "general failure",
            0x02 => "connection not allowed",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        eprintln!("[SOCKS-TEST] CONNECT failed: {} (0x{:02x})", error, connect_response[1]);
        std::process::exit(1);
    }

    eprintln!("[SOCKS-TEST] CONNECT successful! Tunnel established.");

    // Send HTTP request
    let http_request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: socks-test/1.0\r\n\r\n",
        target_host
    );

    eprintln!("[SOCKS-TEST] Sending HTTP request...");
    if let Err(e) = stream.write_all(http_request.as_bytes()) {
        eprintln!("[SOCKS-TEST] Failed to send HTTP request: {}", e);
        std::process::exit(1);
    }

    // Read HTTP response
    eprintln!("[SOCKS-TEST] Reading response...");
    let mut response_buf = vec![0u8; 4096];
    match stream.read(&mut response_buf) {
        Ok(0) => {
            eprintln!("[SOCKS-TEST] Connection closed (no data)");
        }
        Ok(n) => {
            let response_text = String::from_utf8_lossy(&response_buf[..n]);
            eprintln!("[SOCKS-TEST] Received {} bytes:", n);
            // Print first few lines
            for line in response_text.lines().take(10) {
                println!("{}", line);
            }
            if response_text.lines().count() > 10 {
                println!("... (truncated)");
            }
        }
        Err(e) => {
            eprintln!("[SOCKS-TEST] Failed to read response: {}", e);
            std::process::exit(1);
        }
    }

    eprintln!("[SOCKS-TEST] Test completed successfully!");
}
