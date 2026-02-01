//! x86_64-specific boot setup.
//!
//! x86_64 Linux boot requires:
//! 1. Boot params structure at known address
//! 2. Protected mode kernel at 1MB
//! 3. GDT set up
//! 4. CPU in 64-bit long mode
//!
//! This implements the Linux boot protocol (version 2.15+).

/// Boot params structure offsets (Linux boot protocol).
#[allow(dead_code)]
pub mod boot_params {
    pub const SETUP_SECTS: usize = 0x1f1;
    pub const ROOT_FLAGS: usize = 0x1f2;
    pub const SYSSIZE: usize = 0x1f4;
    pub const VIDMODE: usize = 0x1fa;
    pub const ROOT_DEV: usize = 0x1fc;
    pub const BOOT_FLAG: usize = 0x1fe;
    pub const HEADER: usize = 0x202;
    pub const VERSION: usize = 0x206;
    pub const TYPE_OF_LOADER: usize = 0x210;
    pub const LOADFLAGS: usize = 0x211;
    pub const CODE32_START: usize = 0x214;
    pub const RAMDISK_IMAGE: usize = 0x218;
    pub const RAMDISK_SIZE: usize = 0x21c;
    pub const CMD_LINE_PTR: usize = 0x228;
    pub const INITRD_ADDR_MAX: usize = 0x22c;
    pub const KERNEL_ALIGNMENT: usize = 0x230;
    pub const CMDLINE_SIZE: usize = 0x238;
    pub const PREF_ADDRESS: usize = 0x258;
    pub const INIT_SIZE: usize = 0x260;
}

/// Load flags in boot protocol.
#[allow(dead_code)]
pub mod loadflags {
    pub const LOADED_HIGH: u8 = 0x01;
    pub const CAN_USE_HEAP: u8 = 0x80;
}

/// x86_64 boot configuration.
#[derive(Debug, Clone)]
pub struct X86BootConfig {
    /// Boot params address
    pub boot_params_addr: u64,
    /// Kernel entry point
    pub kernel_addr: u64,
    /// Command line address
    pub cmdline_addr: u64,
    /// Initrd address
    pub initrd_addr: u64,
    /// Initial stack pointer
    pub sp: u64,
}

impl Default for X86BootConfig {
    fn default() -> Self {
        Self {
            boot_params_addr: 0x10000,  // 64KB
            kernel_addr: 0x100000,      // 1MB
            cmdline_addr: 0x20000,      // 128KB
            initrd_addr: 0x800000,      // 8MB
            sp: 0x8000,                 // 32KB
        }
    }
}

/// E820 memory map entry types.
#[allow(dead_code)]
pub mod e820_type {
    pub const RAM: u32 = 1;
    pub const RESERVED: u32 = 2;
    pub const ACPI_RECLAIMABLE: u32 = 3;
    pub const ACPI_NVS: u32 = 4;
    pub const BAD_MEMORY: u32 = 5;
}

/// E820 memory map entry.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
}

impl E820Entry {
    pub const SIZE: usize = 20;

    pub fn new(addr: u64, size: u64, type_: u32) -> Self {
        Self { addr, size, type_ }
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0..8].copy_from_slice(&self.addr.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.size.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.type_.to_le_bytes());
        bytes
    }
}

/// Build a basic E820 memory map.
pub fn build_e820_map(memory_size: u64) -> Vec<E820Entry> {
    vec![
        // Low memory (0 - 640KB is usable)
        E820Entry::new(0, 0x9fc00, e820_type::RAM),
        // EBDA and video memory (reserved)
        E820Entry::new(0x9fc00, 0x60400, e820_type::RESERVED),
        // High memory (1MB to end of RAM)
        E820Entry::new(0x100000, memory_size - 0x100000, e820_type::RAM),
    ]
}

/// GDT entry.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct GdtEntry {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_middle: u8,
    pub access: u8,
    pub granularity: u8,
    pub base_high: u8,
}

impl GdtEntry {
    pub const SIZE: usize = 8;

    /// Create a null descriptor.
    pub fn null() -> Self {
        Self::default()
    }

    /// Create a 64-bit code segment.
    pub fn code64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x9A,       // Present, ring 0, code, execute/read
            granularity: 0xAF,  // 64-bit, 4KB granularity, limit 0xF
            base_high: 0,
        }
    }

    /// Create a 64-bit data segment.
    pub fn data64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x92,       // Present, ring 0, data, read/write
            granularity: 0xCF,  // 32-bit, 4KB granularity, limit 0xF
            base_high: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..2].copy_from_slice(&self.limit_low.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.base_low.to_le_bytes());
        bytes[4] = self.base_middle;
        bytes[5] = self.access;
        bytes[6] = self.granularity;
        bytes[7] = self.base_high;
        bytes
    }
}

/// Build a minimal GDT for 64-bit mode (Linux boot protocol compatible).
pub fn build_gdt() -> Vec<u8> {
    let mut gdt = Vec::new();

    // Linux boot protocol requires:
    // __BOOT_CS = 0x10 (entry 2)
    // __BOOT_DS = 0x18 (entry 3)

    // Entry 0: Null descriptor (selector 0x00)
    gdt.extend_from_slice(&GdtEntry::null().to_bytes());

    // Entry 1: Reserved/null descriptor (selector 0x08)
    gdt.extend_from_slice(&GdtEntry::null().to_bytes());

    // Entry 2: 64-bit code segment (selector 0x10 = __BOOT_CS)
    gdt.extend_from_slice(&GdtEntry::code64().to_bytes());

    // Entry 3: 64-bit data segment (selector 0x18 = __BOOT_DS)
    gdt.extend_from_slice(&GdtEntry::data64().to_bytes());

    gdt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e820_entry() {
        let entry = E820Entry::new(0x100000, 0x1000000, e820_type::RAM);
        let bytes = entry.to_bytes();

        // Check address
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 0x100000);
        // Check size
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0x1000000);
        // Check type
        assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), e820_type::RAM);
    }

    #[test]
    fn test_build_gdt() {
        let gdt = build_gdt();
        assert_eq!(gdt.len(), 32); // 4 entries * 8 bytes
    }

    #[test]
    fn test_build_e820_map() {
        let map = build_e820_map(256 * 1024 * 1024); // 256MB
        assert_eq!(map.len(), 3);
        assert_eq!(map[0].type_, e820_type::RAM);
        assert_eq!(map[2].type_, e820_type::RAM);
    }
}
