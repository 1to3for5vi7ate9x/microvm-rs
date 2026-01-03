//! vmnet.framework backend for macOS networking.
//!
//! This module provides a NetBackend implementation using macOS's vmnet.framework
//! for high-performance VM networking with NAT or bridged modes.
//!
//! Requires the `com.apple.vm.networking` entitlement.

use crate::error::{Error, Result};
use super::net::NetBackend;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::ptr;
use std::sync::mpsc;

// vmnet.framework FFI bindings
#[cfg(target_os = "macos")]
#[allow(non_camel_case_types)]
mod ffi {
    use std::ffi::c_void;

    // Opaque types
    pub type vmnet_interface_t = *mut c_void;
    pub type dispatch_queue_t = *mut c_void;
    #[allow(dead_code)]
    pub type dispatch_semaphore_t = *mut c_void;
    pub type xpc_object_t = *mut c_void;

    // vmnet operation modes
    pub const VMNET_HOST_MODE: u32 = 1000;
    pub const VMNET_SHARED_MODE: u32 = 1001;
    #[allow(dead_code)]
    pub const VMNET_BRIDGED_MODE: u32 = 1002;

    // vmnet status codes
    pub const VMNET_SUCCESS: u32 = 1000;
    #[allow(dead_code)]
    pub const VMNET_FAILURE: u32 = 1001;

    // vmnet interface parameter keys
    pub const VMNET_OPERATION_MODE_KEY: &[u8] = b"com.apple.vmnet.operation_mode\0";
    pub const VMNET_MAC_ADDRESS_KEY: &[u8] = b"com.apple.vmnet.mac_address\0";
    pub const VMNET_MTU_KEY: &[u8] = b"com.apple.vmnet.mtu\0";
    pub const VMNET_MAX_PACKET_SIZE_KEY: &[u8] = b"com.apple.vmnet.max_packet_size\0";

    // Maximum packet size (MTU + headers)
    pub const VMNET_MAX_PACKET_SIZE: usize = 1518;

    #[repr(C)]
    pub struct iovec {
        pub iov_base: *mut c_void,
        pub iov_len: usize,
    }

    #[repr(C)]
    pub struct vmpktdesc {
        pub vm_pkt_size: usize,
        pub vm_pkt_iov: *mut iovec,
        pub vm_pkt_iovcnt: u32,
        pub vm_flags: u32,
    }

    #[link(name = "vmnet", kind = "framework")]
    extern "C" {
        // vmnet interface functions
        pub fn vmnet_start_interface(
            interface_desc: xpc_object_t,
            queue: dispatch_queue_t,
            handler: extern "C" fn(vmnet_interface_t, xpc_object_t, u32),
        ) -> vmnet_interface_t;

        pub fn vmnet_stop_interface(
            interface: vmnet_interface_t,
            queue: dispatch_queue_t,
            handler: extern "C" fn(u32),
        ) -> u32;

        pub fn vmnet_read(
            interface: vmnet_interface_t,
            packets: *mut vmpktdesc,
            pktcnt: *mut i32,
        ) -> u32;

        pub fn vmnet_write(
            interface: vmnet_interface_t,
            packets: *mut vmpktdesc,
            pktcnt: *mut i32,
        ) -> u32;

        // libdispatch functions
        pub fn dispatch_queue_create(
            label: *const u8,
            attr: *const c_void,
        ) -> dispatch_queue_t;

        pub fn dispatch_release(object: *mut c_void);

        #[allow(dead_code)]
        pub fn dispatch_semaphore_create(value: isize) -> dispatch_semaphore_t;
        #[allow(dead_code)]
        pub fn dispatch_semaphore_wait(dsema: dispatch_semaphore_t, timeout: u64) -> isize;
        #[allow(dead_code)]
        pub fn dispatch_semaphore_signal(dsema: dispatch_semaphore_t) -> isize;

        // XPC dictionary functions for interface parameters
        pub fn xpc_dictionary_create(
            keys: *const *const u8,
            values: *const xpc_object_t,
            count: usize,
        ) -> xpc_object_t;

        pub fn xpc_dictionary_set_uint64(
            xdict: xpc_object_t,
            key: *const u8,
            value: u64,
        );

        pub fn xpc_dictionary_get_uint64(
            xdict: xpc_object_t,
            key: *const u8,
        ) -> u64;

        pub fn xpc_dictionary_get_string(
            xdict: xpc_object_t,
            key: *const u8,
        ) -> *const u8;

        pub fn xpc_release(object: xpc_object_t);
    }

    #[allow(dead_code)]
    pub const DISPATCH_TIME_FOREVER: u64 = !0;
    #[allow(dead_code)]
    pub const DISPATCH_TIME_NOW: u64 = 0;
}

#[cfg(target_os = "macos")]
use ffi::*;

/// vmnet operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmnetMode {
    /// NAT mode - guest shares host's network via NAT.
    Host,
    /// Shared mode - similar to host but with internet sharing enabled.
    Shared,
    /// Bridged mode - guest appears on the same network as host.
    #[allow(dead_code)]
    Bridged,
}

#[cfg(target_os = "macos")]
impl VmnetMode {
    fn to_raw(self) -> u32 {
        match self {
            VmnetMode::Host => VMNET_HOST_MODE,
            VmnetMode::Shared => VMNET_SHARED_MODE,
            VmnetMode::Bridged => VMNET_BRIDGED_MODE,
        }
    }
}

/// vmnet.framework network backend.
#[cfg(target_os = "macos")]
pub struct VmnetBackend {
    interface: vmnet_interface_t,
    queue: dispatch_queue_t,
    rx_buffer: VecDeque<Vec<u8>>,
    mac_address: [u8; 6],
    mtu: u32,
    #[allow(dead_code)]
    max_packet_size: u32,
}

#[cfg(target_os = "macos")]
unsafe impl Send for VmnetBackend {}

#[cfg(target_os = "macos")]
impl VmnetBackend {
    /// Create a new vmnet backend with NAT mode (default).
    pub fn new() -> Result<Self> {
        Self::with_mode(VmnetMode::Shared)
    }

    /// Create a new vmnet backend with the specified mode.
    pub fn with_mode(mode: VmnetMode) -> Result<Self> {
        unsafe {
            // Create dispatch queue for vmnet callbacks
            let queue_label = b"com.microvm.vmnet\0";
            let queue = dispatch_queue_create(queue_label.as_ptr(), ptr::null());
            if queue.is_null() {
                return Err(Error::Vmnet("Failed to create dispatch queue".into()));
            }

            // Create XPC dictionary for interface parameters
            let interface_desc = xpc_dictionary_create(ptr::null(), ptr::null(), 0);
            if interface_desc.is_null() {
                dispatch_release(queue);
                return Err(Error::Vmnet("Failed to create interface descriptor".into()));
            }

            // Set operation mode
            xpc_dictionary_set_uint64(
                interface_desc,
                VMNET_OPERATION_MODE_KEY.as_ptr(),
                mode.to_raw() as u64,
            );

            // Use channels to receive the result from the callback
            let (_tx, _rx) = mpsc::channel::<(vmnet_interface_t, Option<String>, Option<[u8; 6]>, u32, u32)>();

            // Static callback that will send results through the channel
            extern "C" fn start_callback(
                interface: vmnet_interface_t,
                interface_params: xpc_object_t,
                status: u32,
            ) {
                // Get parameters from interface_params
                let (mac, mtu, max_pkt_size) = if status == VMNET_SUCCESS && !interface_params.is_null() {
                    unsafe {
                        let mac_str = xpc_dictionary_get_string(interface_params, VMNET_MAC_ADDRESS_KEY.as_ptr());
                        let mtu = xpc_dictionary_get_uint64(interface_params, VMNET_MTU_KEY.as_ptr()) as u32;
                        let max_pkt = xpc_dictionary_get_uint64(interface_params, VMNET_MAX_PACKET_SIZE_KEY.as_ptr()) as u32;

                        let mac = if !mac_str.is_null() {
                            // Parse MAC address string (format: "aa:bb:cc:dd:ee:ff")
                            let mac_cstr = std::ffi::CStr::from_ptr(mac_str as *const i8);
                            if let Ok(mac_s) = mac_cstr.to_str() {
                                parse_mac(mac_s)
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        (mac, mtu, max_pkt)
                    }
                } else {
                    (None, 0, 0)
                };

                let error_msg = if status != VMNET_SUCCESS {
                    Some(format!("vmnet_start_interface failed with status {}", status))
                } else {
                    None
                };

                // Note: We can't easily pass the channel through the callback.
                // In a real implementation, we'd use a static or global state.
                // For now, store the result in a thread-local.
                VMNET_RESULT.with(|r| {
                    *r.borrow_mut() = Some((interface, error_msg, mac, mtu, max_pkt_size));
                });
            }

            // Start the interface
            let _interface = vmnet_start_interface(interface_desc, queue, start_callback);

            // Give the callback time to complete
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Get the result from thread-local storage
            let result = VMNET_RESULT.with(|r| r.borrow_mut().take());

            xpc_release(interface_desc);

            match result {
                Some((iface, None, Some(mac), mtu, max_pkt)) if !iface.is_null() => {
                    Ok(Self {
                        interface: iface,
                        queue,
                        rx_buffer: VecDeque::new(),
                        mac_address: mac,
                        mtu: if mtu > 0 { mtu } else { 1500 },
                        max_packet_size: if max_pkt > 0 { max_pkt } else { 1518 },
                    })
                }
                Some((_, Some(err), _, _, _)) => {
                    dispatch_release(queue);
                    Err(Error::Vmnet(err))
                }
                Some((iface, None, None, _, _)) if !iface.is_null() => {
                    // Interface created but no MAC - use a default
                    Ok(Self {
                        interface: iface,
                        queue,
                        rx_buffer: VecDeque::new(),
                        mac_address: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
                        mtu: 1500,
                        max_packet_size: 1518,
                    })
                }
                _ => {
                    dispatch_release(queue);
                    Err(Error::Vmnet("Failed to start vmnet interface".into()))
                }
            }
        }
    }

    /// Get the MAC address assigned by vmnet.
    pub fn mac_address(&self) -> &[u8; 6] {
        &self.mac_address
    }

    /// Get the MTU.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Read packets from vmnet into internal buffer.
    fn poll_packets(&mut self) {
        unsafe {
            let mut buffer = vec![0u8; VMNET_MAX_PACKET_SIZE];
            let mut iov = iovec {
                iov_base: buffer.as_mut_ptr() as *mut c_void,
                iov_len: buffer.len(),
            };

            let mut pkt = vmpktdesc {
                vm_pkt_size: buffer.len(),
                vm_pkt_iov: &mut iov,
                vm_pkt_iovcnt: 1,
                vm_flags: 0,
            };

            let mut pkt_count: i32 = 1;

            let status = vmnet_read(self.interface, &mut pkt, &mut pkt_count);
            if status == VMNET_SUCCESS && pkt_count > 0 {
                buffer.truncate(pkt.vm_pkt_size);
                self.rx_buffer.push_back(buffer);
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl NetBackend for VmnetBackend {
    fn recv(&mut self) -> Option<Vec<u8>> {
        // First check buffered packets
        if let Some(pkt) = self.rx_buffer.pop_front() {
            return Some(pkt);
        }

        // Poll for new packets
        self.poll_packets();
        self.rx_buffer.pop_front()
    }

    fn send(&mut self, data: &[u8]) -> Result<()> {
        unsafe {
            let mut buffer = data.to_vec();
            let mut iov = iovec {
                iov_base: buffer.as_mut_ptr() as *mut c_void,
                iov_len: buffer.len(),
            };

            let mut pkt = vmpktdesc {
                vm_pkt_size: buffer.len(),
                vm_pkt_iov: &mut iov,
                vm_pkt_iovcnt: 1,
                vm_flags: 0,
            };

            let mut pkt_count: i32 = 1;

            let status = vmnet_write(self.interface, &mut pkt, &mut pkt_count);
            if status == VMNET_SUCCESS {
                Ok(())
            } else {
                Err(Error::Vmnet(format!("vmnet_write failed with status {}", status)))
            }
        }
    }

    fn has_data(&self) -> bool {
        !self.rx_buffer.is_empty()
    }
}

#[cfg(target_os = "macos")]
impl Drop for VmnetBackend {
    fn drop(&mut self) {
        unsafe {
            extern "C" fn stop_callback(_status: u32) {
                // Callback when interface is stopped
            }

            vmnet_stop_interface(self.interface, self.queue, stop_callback);
            // Give it time to complete
            std::thread::sleep(std::time::Duration::from_millis(50));
            dispatch_release(self.queue);
        }
    }
}

// Thread-local storage for vmnet callback results
#[cfg(target_os = "macos")]
thread_local! {
    static VMNET_RESULT: std::cell::RefCell<Option<(vmnet_interface_t, Option<String>, Option<[u8; 6]>, u32, u32)>> = std::cell::RefCell::new(None);
}

/// Parse MAC address from string format "aa:bb:cc:dd:ee:ff"
#[cfg(target_os = "macos")]
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

// Stub for non-macOS platforms
#[cfg(not(target_os = "macos"))]
pub struct VmnetBackend {
    _private: (),
}

#[cfg(not(target_os = "macos"))]
impl VmnetBackend {
    pub fn new() -> Result<Self> {
        Err(Error::NotSupported("vmnet is only available on macOS".into()))
    }

    pub fn with_mode(_mode: VmnetMode) -> Result<Self> {
        Err(Error::NotSupported("vmnet is only available on macOS".into()))
    }

    pub fn mac_address(&self) -> &[u8; 6] {
        static MAC: [u8; 6] = [0; 6];
        &MAC
    }
}

#[cfg(not(target_os = "macos"))]
impl NetBackend for VmnetBackend {
    fn recv(&mut self) -> Option<Vec<u8>> {
        None
    }

    fn send(&mut self, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn has_data(&self) -> bool {
        false
    }
}
