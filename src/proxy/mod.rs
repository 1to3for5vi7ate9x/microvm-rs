//! Vsock-based outbound proxy for guest networking.
//!
//! This module provides a way for guests to make outbound TCP connections
//! through the host without requiring vmnet.framework or special entitlements.
//!
//! # Architecture
//!
//! ```text
//! Guest                          Host
//! ┌─────────────────┐           ┌─────────────────┐
//! │ Application     │           │                 │
//! │      │          │           │                 │
//! │      ▼          │           │                 │
//! │ Proxy Client    │──vsock───▶│ Outbound Proxy  │──TCP──▶ Internet
//! │ (SOCKS5 server) │           │ (connection mgr)│
//! └─────────────────┘           └─────────────────┘
//! ```
//!
//! # Protocol
//!
//! The proxy uses a simple binary protocol over vsock:
//!
//! ## CONNECT Request (guest → host)
//! ```text
//! | type (1) | addr_type (1) | addr_len (2) | addr (var) | port (2) |
//! ```
//! - type: 0x01 = CONNECT
//! - addr_type: 0x01 = IPv4, 0x03 = Domain name
//! - addr_len: Length of address (little-endian u16)
//! - addr: Address bytes (4 for IPv4, or domain string)
//! - port: Destination port (little-endian u16)
//!
//! ## CONNECT Response (host → guest)
//! ```text
//! | type (1) | status (1) | bound_port (2) |
//! ```
//! - type: 0x02 = RESPONSE
//! - status: 0x00 = success, 0x01 = connection refused, 0x02 = host unreachable, etc.
//! - bound_port: Local port used (little-endian u16)
//!
//! ## DATA (bidirectional, after successful connect)
//! Raw TCP data is forwarded directly.

pub mod protocol;
pub mod host;

pub use protocol::{ConnectRequest, ConnectResponse, ProxyStatus};
pub use host::VsockOutboundProxy;
