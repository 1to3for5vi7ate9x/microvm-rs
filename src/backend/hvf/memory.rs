//! Guest memory management for HVF.

use crate::error::{Error, Result};

/// Guest physical memory region.
///
/// This allocates a contiguous region of host memory that can be
/// mapped into the guest's physical address space.
pub struct GuestMemory {
    /// Pointer to the allocated memory
    ptr: *mut u8,
    /// Size of the allocation in bytes
    size: usize,
}

// Safety: GuestMemory owns its allocation and can be sent between threads
unsafe impl Send for GuestMemory {}
unsafe impl Sync for GuestMemory {}

impl GuestMemory {
    /// Allocate a new guest memory region.
    ///
    /// The memory is page-aligned and zero-initialized.
    pub fn new(size: usize) -> Result<Self> {
        if size == 0 {
            return Err(Error::MemoryAllocationFailed(
                "Size must be greater than 0".to_string(),
            ));
        }

        // Round up to page size
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let aligned_size = (size + page_size - 1) & !(page_size - 1);

        // Allocate page-aligned memory
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned_size,
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
            size: aligned_size,
        })
    }

    /// Get a raw pointer to the memory region.
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Get a mutable raw pointer to the memory region.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    /// Get the size of the memory region in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get a slice view of the memory region.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size) }
    }

    /// Get a mutable slice view of the memory region.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    /// Read bytes from a guest physical address.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<()> {
        if offset + buf.len() > self.size {
            return Err(Error::InvalidGuestAddress((offset + buf.len()) as u64));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.add(offset), buf.as_mut_ptr(), buf.len());
        }

        Ok(())
    }

    /// Write bytes to a guest physical address.
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<()> {
        if offset + data.len() > self.size {
            return Err(Error::InvalidGuestAddress((offset + data.len()) as u64));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len());
        }

        Ok(())
    }

    /// Read a value from a guest physical address.
    pub fn read_obj<T: Copy>(&self, offset: usize) -> Result<T> {
        if offset + std::mem::size_of::<T>() > self.size {
            return Err(Error::InvalidGuestAddress(offset as u64));
        }

        unsafe { Ok(std::ptr::read_unaligned(self.ptr.add(offset) as *const T)) }
    }

    /// Write a value to a guest physical address.
    pub fn write_obj<T: Copy>(&mut self, offset: usize, value: T) -> Result<()> {
        if offset + std::mem::size_of::<T>() > self.size {
            return Err(Error::InvalidGuestAddress(offset as u64));
        }

        unsafe {
            std::ptr::write_unaligned(self.ptr.add(offset) as *mut T, value);
        }

        Ok(())
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.size);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_memory_allocation() {
        let mem = GuestMemory::new(4096).unwrap();
        assert!(mem.size() >= 4096);
        assert!(!mem.as_ptr().is_null());
    }

    #[test]
    fn test_guest_memory_read_write() {
        let mut mem = GuestMemory::new(4096).unwrap();

        // Write some data
        let data = b"Hello, VM!";
        mem.write(0, data).unwrap();

        // Read it back
        let mut buf = [0u8; 10];
        mem.read(0, &mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn test_guest_memory_obj() {
        let mut mem = GuestMemory::new(4096).unwrap();

        // Write a u32
        mem.write_obj(0, 0xDEADBEEFu32).unwrap();

        // Read it back
        let value: u32 = mem.read_obj(0).unwrap();
        assert_eq!(value, 0xDEADBEEF);
    }
}
