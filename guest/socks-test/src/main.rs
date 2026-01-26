//! Simple SOCKS5 test client to verify proxy works
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    let proxy_addr = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1:1080");
    let target_host = args.get(2).map(|s| s.as_str()).unwrap_or("example.com");
    let target_port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(80);
    
    eprintln!("[TEST] Connecting to SOCKS5 proxy at {}...", proxy_addr);
    
    let mut stream = match TcpStream::connect(proxy_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[TEST] Failed to connect to proxy: {}", e);
            return;
        }
    };
    
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    
    // SOCKS5 greeting: version=5, nmethods=1, methods=[0 (no auth)]
    eprintln!("[TEST] Sending SOCKS5 greeting...");
    if let Err(e) = stream.write_all(&[0x05, 0x01, 0x00]) {
        eprintln!("[TEST] Failed to send greeting: {}", e);
        return;
    }
    
    // Read greeting response
    let mut response = [0u8; 2];
    if let Err(e) = stream.read_exact(&mut response) {
        eprintln!("[TEST] Failed to read greeting response: {}", e);
        return;
    }
    
    if response[0] != 0x05 || response[1] != 0x00 {
        eprintln!("[TEST] Unexpected greeting response: {:?}", response);
        return;
    }
    eprintln!("[TEST] Greeting OK, no auth required");
    
    // SOCKS5 connect request: version=5, cmd=1 (connect), rsv=0, atyp=3 (domain)
    let mut request = vec![0x05, 0x01, 0x00, 0x03]; // VER, CMD, RSV, ATYP
    request.push(target_host.len() as u8); // Domain length
    request.extend_from_slice(target_host.as_bytes()); // Domain
    request.extend_from_slice(&target_port.to_be_bytes()); // Port (big-endian)
    
    eprintln!("[TEST] Sending CONNECT request to {}:{}...", target_host, target_port);
    if let Err(e) = stream.write_all(&request) {
        eprintln!("[TEST] Failed to send connect request: {}", e);
        return;
    }
    
    // Read connect response (at least 10 bytes for IPv4)
    let mut connect_response = [0u8; 10];
    if let Err(e) = stream.read_exact(&mut connect_response) {
        eprintln!("[TEST] Failed to read connect response: {}", e);
        return;
    }
    
    if connect_response[0] != 0x05 {
        eprintln!("[TEST] Invalid SOCKS version in response");
        return;
    }
    
    if connect_response[1] != 0x00 {
        let err = match connect_response[1] {
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
        eprintln!("[TEST] SOCKS5 connect failed: {} ({})", err, connect_response[1]);
        return;
    }
    
    eprintln!("[TEST] SOCKS5 tunnel established!");
    
    // Send HTTP request
    let http_request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target_host
    );
    
    eprintln!("[TEST] Sending HTTP request...");
    if let Err(e) = stream.write_all(http_request.as_bytes()) {
        eprintln!("[TEST] Failed to send HTTP request: {}", e);
        return;
    }
    
    // Read response
    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(n) => {
            eprintln!("[TEST] Received {} bytes", n);
            // Show first 500 bytes
            let preview = String::from_utf8_lossy(&response[..response.len().min(500)]);
            println!("{}", preview);
            if response.len() > 500 {
                println!("... ({} more bytes)", response.len() - 500);
            }
            eprintln!("\n[TEST] SUCCESS! Proxy works!");
        }
        Err(e) => {
            eprintln!("[TEST] Error reading response: {}", e);
        }
    }
}
