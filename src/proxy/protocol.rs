//! Proxy protocol definitions.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Message types for the proxy protocol.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Connect = 0x01,
    Response = 0x02,
}

/// Address types for connect requests.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    IPv4 = 0x01,
    IPv6 = 0x04,
    Domain = 0x03,
}

/// Proxy connection status codes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyStatus {
    Success = 0x00,
    GeneralFailure = 0x01,
    ConnectionRefused = 0x02,
    HostUnreachable = 0x03,
    NetworkUnreachable = 0x04,
    ConnectionTimeout = 0x05,
    DnsFailure = 0x06,
}

impl ProxyStatus {
    pub fn from_io_error(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::ConnectionRefused => ProxyStatus::ConnectionRefused,
            io::ErrorKind::TimedOut => ProxyStatus::ConnectionTimeout,
            io::ErrorKind::AddrNotAvailable => ProxyStatus::HostUnreachable,
            _ => ProxyStatus::GeneralFailure,
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, ProxyStatus::Success)
    }
}

/// Target address for a connection.
#[derive(Debug, Clone)]
pub enum TargetAddress {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    Domain(String),
}

impl TargetAddress {
    pub fn addr_type(&self) -> AddressType {
        match self {
            TargetAddress::IPv4(_) => AddressType::IPv4,
            TargetAddress::IPv6(_) => AddressType::IPv6,
            TargetAddress::Domain(_) => AddressType::Domain,
        }
    }

    /// Encode the address to bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            TargetAddress::IPv4(addr) => addr.octets().to_vec(),
            TargetAddress::IPv6(addr) => addr.octets().to_vec(),
            TargetAddress::Domain(name) => name.as_bytes().to_vec(),
        }
    }

    /// Decode an address from bytes.
    pub fn decode(addr_type: AddressType, data: &[u8]) -> io::Result<Self> {
        match addr_type {
            AddressType::IPv4 => {
                if data.len() != 4 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid IPv4 address length"));
                }
                Ok(TargetAddress::IPv4(Ipv4Addr::new(data[0], data[1], data[2], data[3])))
            }
            AddressType::IPv6 => {
                if data.len() != 16 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid IPv6 address length"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                Ok(TargetAddress::IPv6(Ipv6Addr::from(octets)))
            }
            AddressType::Domain => {
                let name = String::from_utf8(data.to_vec())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid domain name"))?;
                Ok(TargetAddress::Domain(name))
            }
        }
    }
}

impl std::fmt::Display for TargetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetAddress::IPv4(addr) => write!(f, "{}", addr),
            TargetAddress::IPv6(addr) => write!(f, "{}", addr),
            TargetAddress::Domain(name) => write!(f, "{}", name),
        }
    }
}

/// A CONNECT request from the guest.
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub address: TargetAddress,
    pub port: u16,
}

impl ConnectRequest {
    pub fn new(address: TargetAddress, port: u16) -> Self {
        Self { address, port }
    }

    /// Create a connect request for an IPv4 address.
    pub fn ipv4(addr: Ipv4Addr, port: u16) -> Self {
        Self::new(TargetAddress::IPv4(addr), port)
    }

    /// Create a connect request for a domain name.
    pub fn domain(name: impl Into<String>, port: u16) -> Self {
        Self::new(TargetAddress::Domain(name.into()), port)
    }

    /// Encode the request to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let addr_bytes = self.address.encode();
        let addr_len = addr_bytes.len() as u16;

        let mut buf = Vec::with_capacity(6 + addr_bytes.len());
        buf.push(MessageType::Connect as u8);
        buf.push(self.address.addr_type() as u8);
        buf.extend_from_slice(&addr_len.to_le_bytes());
        buf.extend_from_slice(&addr_bytes);
        buf.extend_from_slice(&self.port.to_le_bytes());
        buf
    }

    /// Decode a request from a reader.
    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;

        let msg_type = header[0];
        if msg_type != MessageType::Connect as u8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected CONNECT message"));
        }

        let addr_type = match header[1] {
            0x01 => AddressType::IPv4,
            0x04 => AddressType::IPv6,
            0x03 => AddressType::Domain,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid address type")),
        };

        let addr_len = u16::from_le_bytes([header[2], header[3]]) as usize;

        let mut addr_buf = vec![0u8; addr_len];
        reader.read_exact(&mut addr_buf)?;

        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf)?;
        let port = u16::from_le_bytes(port_buf);

        let address = TargetAddress::decode(addr_type, &addr_buf)?;

        Ok(Self { address, port })
    }

    /// Write the request to a writer.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.encode())
    }
}

/// A CONNECT response from the host.
#[derive(Debug, Clone)]
pub struct ConnectResponse {
    pub status: ProxyStatus,
    pub bound_port: u16,
}

impl ConnectResponse {
    pub fn success(bound_port: u16) -> Self {
        Self {
            status: ProxyStatus::Success,
            bound_port,
        }
    }

    pub fn failure(status: ProxyStatus) -> Self {
        Self {
            status,
            bound_port: 0,
        }
    }

    /// Encode the response to bytes.
    pub fn encode(&self) -> Vec<u8> {
        vec![
            MessageType::Response as u8,
            self.status as u8,
            (self.bound_port & 0xFF) as u8,
            ((self.bound_port >> 8) & 0xFF) as u8,
        ]
    }

    /// Decode a response from a reader.
    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;

        if buf[0] != MessageType::Response as u8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected RESPONSE message"));
        }

        let status = match buf[1] {
            0x00 => ProxyStatus::Success,
            0x01 => ProxyStatus::GeneralFailure,
            0x02 => ProxyStatus::ConnectionRefused,
            0x03 => ProxyStatus::HostUnreachable,
            0x04 => ProxyStatus::NetworkUnreachable,
            0x05 => ProxyStatus::ConnectionTimeout,
            0x06 => ProxyStatus::DnsFailure,
            _ => ProxyStatus::GeneralFailure,
        };

        let bound_port = u16::from_le_bytes([buf[2], buf[3]]);

        Ok(Self { status, bound_port })
    }

    /// Write the response to a writer.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.encode())
    }

    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_connect_request_ipv4() {
        let req = ConnectRequest::ipv4(Ipv4Addr::new(192, 168, 1, 1), 8080);
        let encoded = req.encode();

        let mut cursor = Cursor::new(encoded);
        let decoded = ConnectRequest::decode(&mut cursor).unwrap();

        assert_eq!(decoded.port, 8080);
        match decoded.address {
            TargetAddress::IPv4(addr) => assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1)),
            _ => panic!("Expected IPv4 address"),
        }
    }

    #[test]
    fn test_connect_request_domain() {
        let req = ConnectRequest::domain("example.com", 443);
        let encoded = req.encode();

        let mut cursor = Cursor::new(encoded);
        let decoded = ConnectRequest::decode(&mut cursor).unwrap();

        assert_eq!(decoded.port, 443);
        match decoded.address {
            TargetAddress::Domain(name) => assert_eq!(name, "example.com"),
            _ => panic!("Expected domain address"),
        }
    }

    #[test]
    fn test_connect_response() {
        let resp = ConnectResponse::success(12345);
        let encoded = resp.encode();

        let mut cursor = Cursor::new(encoded);
        let decoded = ConnectResponse::decode(&mut cursor).unwrap();

        assert!(decoded.is_success());
        assert_eq!(decoded.bound_port, 12345);
    }
}
