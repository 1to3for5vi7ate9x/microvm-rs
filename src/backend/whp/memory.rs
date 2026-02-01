//! Guest memory management for WHP.
//!
//! TODO: Implement on Windows machine.

use crate::error::{Error, Result};

#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::*;

/// Guest physical memory region.
pub struct GuestMemory {
    #[cfg(target_os = "windows")]
    ptr: *mut std::ffi::c_void,

    #[cfg(not(target_os = "windows"))]
    ptr: *mut u8,

    size: usize,
}

// Safety: GuestMemory owns its allocation and can be sent between threads
unsafe impl Send for GuestMemory {}
unsafe impl Sync for GuestMemory {}

impl GuestMemory {
    /// Allocate a new guest memory region.
    #[cfg(target_os = "windows")]
    pub fn new(size: usize) -> Result<Self> {
        if size == 0 {
            return Err(Error::MemoryAllocationFailed(
                "Size must be greater than 0".to_string(),
            ));
        }

        unsafe {
            let ptr = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if ptr.is_null() {
                return Err(Error::MemoryAllocationFailed(format!(
                    "VirtualAlloc failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            Ok(Self { ptr, size })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn new(size: usize) -> Result<Self> {
        if size == 0 {
            return Err(Error::MemoryAllocationFailed(
                "Size must be greater than 0".to_string(),
            ));
        }

        // Allocate with mmap on non-Windows for testing
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(Error::MemoryAllocationFailed(format!(
                "mmap failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
        })
    }

    /// Get a raw pointer to the memory region.
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }

    /// Get a mutable raw pointer to the memory region.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr as *mut u8
    }

    /// Get the size of the memory region in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get a slice view of the memory region.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.size) }
    }

    /// Get a mutable slice view of the memory region.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr as *mut u8, self.size) }
    }

    /// Read bytes from a guest physical address.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<()> {
        if offset + buf.len() > self.size {
            return Err(Error::InvalidGuestAddress((offset + buf.len()) as u64));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                (self.ptr as *const u8).add(offset),
                buf.as_mut_ptr(),
                buf.len(),
            );
        }

        Ok(())
    }

    /// Write bytes to a guest physical address.
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<()> {
        if offset + data.len() > self.size {
            return Err(Error::InvalidGuestAddress((offset + data.len()) as u64));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                (self.ptr as *mut u8).add(offset),
                data.len(),
            );
        }

        Ok(())
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        unsafe {
            if !self.ptr.is_null() {
                let _ = VirtualFree(self.ptr, 0, MEM_RELEASE);
            }
        }

        #[cfg(not(target_os = "windows"))]
        unsafe {
            if !self.ptr.is_null() {
                libc::munmap(self.ptr as *mut libc::c_void, self.size);
            }
        }
    }
}

// Implement MemoryWriter trait for kernel loader
impl crate::loader::linux::MemoryWriter for GuestMemory {
    fn write(&mut self, addr: usize, data: &[u8]) -> Result<()> {
        GuestMemory::write(self, addr, data)
    }
}
