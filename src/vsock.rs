//! Host-side vsock API for communication with guest.
//!
//! This module provides a high-level API for the host to communicate with
//! guests via VirtIO vsock. It wraps the low-level VirtioVsock device and
//! provides an async-friendly interface.
//!
//! # Example
//!
//! ```rust,no_run
//! use microvm::vsock::VsockClient;
//!
//! async fn communicate_with_guest(client: &VsockClient) {
//!     // Send a command
//!     client.send(1025, b"{\"cmd\":\"ping\"}\n").await.unwrap();
//!
//!     // Receive response
//!     let mut buf = vec![0u8; 1024];
//!     let n = client.recv(1025, &mut buf).await.unwrap();
//!     println!("Response: {}", String::from_utf8_lossy(&buf[..n]));
//! }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

/// Default guest CID (first available after host CID=2)
pub const DEFAULT_GUEST_CID: u64 = 3;

/// Host CID
pub const HOST_CID: u64 = 2;

/// Message types for vsock communication channel
#[derive(Debug)]
pub enum VsockMessage {
    /// Connect to a guest port
    Connect {
        guest_port: u32,
        response: oneshot::Sender<Result<u32, String>>, // Returns local port
    },
    /// Send data to a connection
    Send {
        local_port: u32,
        guest_port: u32,
        data: Vec<u8>,
        response: oneshot::Sender<Result<usize, String>>,
    },
    /// Receive data from a connection
    Recv {
        local_port: u32,
        guest_port: u32,
        response: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    /// Close a connection
    Close {
        local_port: u32,
        guest_port: u32,
    },
}

/// A connection to a guest vsock port.
#[derive(Debug, Clone)]
pub struct VsockConnection {
    /// Local (host) port
    pub local_port: u32,
    /// Guest port
    pub guest_port: u32,
    /// Guest CID
    pub guest_cid: u64,
    /// Channel to send messages to the VM loop
    tx: mpsc::Sender<VsockMessage>,
}

impl VsockConnection {
    /// Send data to the guest.
    pub async fn send(&self, data: &[u8]) -> Result<usize, String> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx.send(VsockMessage::Send {
            local_port: self.local_port,
            guest_port: self.guest_port,
            data: data.to_vec(),
            response: response_tx,
        }).await.map_err(|e| format!("Channel closed: {}", e))?;

        response_rx.await.map_err(|e| format!("Response channel closed: {}", e))?
    }

    /// Receive data from the guest.
    pub async fn recv(&self) -> Result<Vec<u8>, String> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx.send(VsockMessage::Recv {
            local_port: self.local_port,
            guest_port: self.guest_port,
            response: response_tx,
        }).await.map_err(|e| format!("Channel closed: {}", e))?;

        response_rx.await.map_err(|e| format!("Response channel closed: {}", e))?
    }

    /// Close the connection.
    pub async fn close(&self) -> Result<(), String> {
        self.tx.send(VsockMessage::Close {
            local_port: self.local_port,
            guest_port: self.guest_port,
        }).await.map_err(|e| format!("Channel closed: {}", e))
    }
}

/// Client for making vsock connections to the guest.
#[derive(Clone)]
pub struct VsockClient {
    /// Channel to send messages to the VM loop
    tx: mpsc::Sender<VsockMessage>,
    /// Guest CID
    guest_cid: u64,
    /// Next local port to use
    next_port: Arc<Mutex<u32>>,
}

impl VsockClient {
    /// Create a new vsock client.
    pub fn new(tx: mpsc::Sender<VsockMessage>, guest_cid: u64) -> Self {
        Self {
            tx,
            guest_cid,
            // Start from a high port number to avoid conflicts
            next_port: Arc::new(Mutex::new(50000)),
        }
    }

    /// Connect to a guest port.
    pub async fn connect(&self, guest_port: u32) -> Result<VsockConnection, String> {
        let local_port = {
            let mut port = self.next_port.lock().unwrap();
            let p = *port;
            *port += 1;
            p
        };

        let (response_tx, response_rx) = oneshot::channel();
        self.tx.send(VsockMessage::Connect {
            guest_port,
            response: response_tx,
        }).await.map_err(|e| {
            format!("Channel closed: {}", e)
        })?;

        let assigned_port = response_rx.await
            .map_err(|e| {
                format!("Response channel closed: {}", e)
            })??;

        Ok(VsockConnection {
            local_port: assigned_port,
            guest_port,
            guest_cid: self.guest_cid,
            tx: self.tx.clone(),
        })
    }

    /// Send data to a guest port (one-shot, creates temp connection).
    pub async fn send_to(&self, guest_port: u32, data: &[u8]) -> Result<usize, String> {
        let conn = self.connect(guest_port).await?;
        let result = conn.send(data).await;
        // Note: connection will be auto-closed when dropped
        result
    }

    /// Simple request/response pattern - send data and wait for response.
    pub async fn request(&self, guest_port: u32, request: &[u8]) -> Result<Vec<u8>, String> {
        let conn = self.connect(guest_port).await?;
        conn.send(request).await?;

        // Wait for response with timeout that scales with payload size
        // Base timeout: 5 seconds, plus extra time for large payloads
        let base_iterations = 500; // 5 seconds base
        let extra_iterations = request.len() / 1000; // +10ms per KB
        let max_iterations = base_iterations + extra_iterations;

        for i in 0..max_iterations {
            match conn.recv().await {
                Ok(data) if !data.is_empty() => {
                    return Ok(data);
                }
                Ok(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
                Err(e) => {
                    eprintln!("[VSOCK_CLIENT] request error: {}", e);
                    return Err(e);
                }
            }
        }

        eprintln!("[VSOCK_CLIENT] request TIMEOUT after {}ms", max_iterations * 10);
        Err(format!("Timeout waiting for response after {}ms", max_iterations * 10))
    }
}

/// Handler for vsock messages in the VM run loop.
///
/// This processes VsockMessage commands and interacts with the VirtioVsock device.
pub struct VsockHandler {
    /// Receiver for vsock commands
    rx: mpsc::Receiver<VsockMessage>,
    /// Active connections: (local_port, guest_port) -> pending data
    pending_responses: HashMap<(u32, u32), oneshot::Sender<Result<Vec<u8>, String>>>,
    /// Buffered data for connections (when data arrives before recv() is called)
    buffered_data: HashMap<(u32, u32), Vec<Vec<u8>>>,
    /// Next local port
    next_port: u32,
}

impl VsockHandler {
    /// Create a new handler.
    pub fn new(rx: mpsc::Receiver<VsockMessage>) -> Self {
        Self {
            rx,
            pending_responses: HashMap::new(),
            buffered_data: HashMap::new(),
            next_port: 50000,
        }
    }

    /// Try to receive a message (non-blocking).
    pub fn try_recv(&mut self) -> Option<VsockMessage> {
        self.rx.try_recv().ok()
    }

    /// Get next local port.
    pub fn next_local_port(&mut self) -> u32 {
        let port = self.next_port;
        self.next_port += 1;
        port
    }

    /// Store a pending recv response.
    /// If there's buffered data for this connection, immediately respond with it.
    pub fn add_pending_recv(&mut self, local_port: u32, guest_port: u32, response: oneshot::Sender<Result<Vec<u8>, String>>) {
        let key = (local_port, guest_port);

        // Check if there's buffered data first
        if let Some(buffer) = self.buffered_data.get_mut(&key) {
            if !buffer.is_empty() {
                // Return all buffered data concatenated
                let data: Vec<u8> = buffer.drain(..).flatten().collect();
                let _ = response.send(Ok(data));
                return;
            }
        }

        // No buffered data, store the pending response
        self.pending_responses.insert(key, response);
    }

    /// Complete a pending recv with data.
    /// If no pending recv, buffer the data for later.
    pub fn complete_recv(&mut self, local_port: u32, guest_port: u32, data: Vec<u8>) {
        let key = (local_port, guest_port);

        if let Some(response) = self.pending_responses.remove(&key) {
            // There's a pending recv, send the data directly
            let _ = response.send(Ok(data));
        } else {
            // No pending recv, buffer the data
            self.buffered_data.entry(key).or_insert_with(Vec::new).push(data);
        }
    }

    /// Clear buffered data for a closed connection
    pub fn clear_connection(&mut self, local_port: u32, guest_port: u32) {
        let key = (local_port, guest_port);
        self.buffered_data.remove(&key);
        self.pending_responses.remove(&key);
    }
}

/// Create a vsock channel pair.
///
/// Returns (client, handler) where:
/// - client: Used by the host application to make vsock connections
/// - handler: Used in the VM run loop to process vsock commands
pub fn create_vsock_channel(guest_cid: u64) -> (VsockClient, VsockHandler) {
    let (tx, rx) = mpsc::channel(256);
    let client = VsockClient::new(tx, guest_cid);
    let handler = VsockHandler::new(rx);
    (client, handler)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_channel() {
        let (client, _handler) = create_vsock_channel(3);
        assert_eq!(client.guest_cid, 3);
    }
}
