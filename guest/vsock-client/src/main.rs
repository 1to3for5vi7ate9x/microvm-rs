//! Simple vsock client for testing vpn-daemon from inside the guest
use std::io::{Read, Write};

fn connect_vsock(cid: u32, port: u32) -> std::io::Result<i32> {
    #[repr(C)]
    struct SockaddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    let fd = unsafe { libc::socket(40, 1, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let addr = SockaddrVm {
        svm_family: 40,
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
        return Err(std::io::Error::last_os_error());
    }

    Ok(fd)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    // CID: 2 = host, 3 = guest (we're in guest connecting to local daemon)
    // For local daemon, use VMADDR_CID_LOCAL which is typically handled by connecting to CID_ANY
    // But for our daemon listening on CID_ANY, we can connect via loopback or use the guest's own CID
    
    if args.len() < 2 {
        eprintln!("Usage: vsock-client <command>");
        eprintln!("Commands: ping, status, list, set_profile <name> <content>, start <profile>");
        return;
    }

    let cmd = &args[1];
    
    let json = match cmd.as_str() {
        "ping" => r#"{"cmd":"ping"}"#.to_string(),
        "status" => r#"{"cmd":"vpn_status"}"#.to_string(),
        "list" => r#"{"cmd":"list_profiles"}"#.to_string(),
        "stop" => r#"{"cmd":"vpn_stop"}"#.to_string(),
        "webauth" => r#"{"cmd":"vpn_check_webauth"}"#.to_string(),
        "start" => {
            let profile = args.get(2).map(|s| s.as_str()).unwrap_or("default");
            format!(r#"{{"cmd":"vpn_start","profile":"{}"}}"#, profile)
        }
        "set_profile" => {
            if args.len() < 4 {
                eprintln!("Usage: vsock-client set_profile <name> <content>");
                return;
            }
            let name = &args[2];
            let content = &args[3];
            // Escape the content for JSON
            let escaped = content.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
            format!(r#"{{"cmd":"vpn_set_profile","name":"{}","content":"{}"}}"#, name, escaped)
        }
        "raw" => {
            // Raw JSON command
            args.get(2).cloned().unwrap_or_else(|| r#"{"cmd":"ping"}"#.to_string())
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            return;
        }
    };

    // Connect to local vsock daemon (use loopback CID = 1 or try local socket)
    // Actually, for local vsock, we need to use CID=3 (our own CID) or VMADDR_CID_LOCAL
    eprintln!("[CLIENT] Sending: {}", json);
    
    // Try using Unix socket first if available, or vsock loopback
    // The daemon listens on VMADDR_CID_ANY, so we connect to our own CID or use loopback
    let fd = match connect_vsock(1, 1025) { // CID 1 = VMADDR_CID_LOCAL
        Ok(fd) => fd,
        Err(_) => {
            // Try CID 3 (guest's own CID) 
            match connect_vsock(3, 1025) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("[CLIENT] Failed to connect: {}", e);
                    return;
                }
            }
        }
    };

    eprintln!("[CLIENT] Connected!");

    // Send command with newline
    let cmd_with_newline = format!("{}\n", json);
    let written = unsafe {
        libc::write(fd, cmd_with_newline.as_ptr() as *const libc::c_void, cmd_with_newline.len())
    };
    
    if written < 0 {
        eprintln!("[CLIENT] Write failed");
        unsafe { libc::close(fd) };
        return;
    }

    // Read response
    let mut buf = [0u8; 8192];
    let n = unsafe {
        libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
    };

    if n > 0 {
        let response = String::from_utf8_lossy(&buf[..n as usize]);
        println!("{}", response.trim());
    } else {
        eprintln!("[CLIENT] No response");
    }

    unsafe { libc::close(fd) };
}
