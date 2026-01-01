//! Guest memory region abstraction.

/// Represents a region of guest physical memory.
#[derive(Debug, Clone)]
pub struct GuestMemoryRegion {
    /// Guest physical address
    pub guest_addr: u64,
    /// Size in bytes
    pub size: u64,
    /// Whether this region is read-only
    pub readonly: bool,
}

impl GuestMemoryRegion {
    /// Create a new memory region.
    pub fn new(guest_addr: u64, size: u64) -> Self {
        Self {
            guest_addr,
            size,
            readonly: false,
        }
    }

    /// Create a read-only memory region.
    pub fn readonly(guest_addr: u64, size: u64) -> Self {
        Self {
            guest_addr,
            size,
            readonly: true,
        }
    }

    /// Check if an address falls within this region.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.guest_addr && addr < self.guest_addr + self.size
    }

    /// Get the offset of an address within this region.
    pub fn offset(&self, addr: u64) -> Option<u64> {
        if self.contains(addr) {
            Some(addr - self.guest_addr)
        } else {
            None
        }
    }
}
