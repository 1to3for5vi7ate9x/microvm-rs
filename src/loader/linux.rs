//! Linux kernel loader.
//!
//! Supports loading Linux kernel images for both ARM64 and x86_64.
//!
//! ## ARM64 (aarch64)
//!
//! ARM64 Linux kernel uses the "Image" format with a specific header.
//! The kernel is typically loaded at a 2MB aligned address.
//!
//! ## x86_64
//!
//! x86_64 Linux kernel uses the bzImage format with boot protocol.
//! The setup code runs in real mode, then transitions to protected/long mode.

use crate::error::{Error, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Linux kernel image information.
#[derive(Debug, Clone)]
pub struct KernelInfo {
    /// Entry point address
    pub entry: u64,
    /// Load address
    pub load_addr: u64,
    /// Kernel size in bytes
    pub size: usize,
    /// Kernel format
    pub format: KernelFormat,
    /// Initrd start address (if loaded)
    pub initrd_start: Option<u64>,
    /// Initrd end address (if loaded)
    pub initrd_end: Option<u64>,
}

/// Kernel image format.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KernelFormat {
    /// ARM64 Image format
    Arm64Image,
    /// x86_64 bzImage format
    BzImage,
    /// ELF executable format
    Elf,
    /// Raw binary (unknown format)
    Raw,
}

/// Linux kernel loader.
pub struct LinuxLoader {
    /// Kernel image data
    kernel_data: Vec<u8>,
    /// Initrd data (optional)
    initrd_data: Option<Vec<u8>>,
    /// Kernel command line
    cmdline: String,
    /// Memory size in MB (for E820 map on x86_64)
    memory_mb: u32,
}

impl LinuxLoader {
    /// Create a new Linux loader from a kernel path.
    pub fn new<P: AsRef<Path>>(kernel_path: P) -> Result<Self> {
        let kernel_data = Self::read_file(kernel_path.as_ref())?;

        Ok(Self {
            kernel_data,
            initrd_data: None,
            cmdline: String::new(),
            memory_mb: 512, // Default 512MB
        })
    }

    /// Set the memory size in MB (used for E820 map on x86_64).
    pub fn with_memory_mb(mut self, mb: u32) -> Self {
        self.memory_mb = mb;
        self
    }

    /// Set the initrd/initramfs image.
    pub fn with_initrd<P: AsRef<Path>>(mut self, initrd_path: P) -> Result<Self> {
        self.initrd_data = Some(Self::read_file(initrd_path.as_ref())?);
        Ok(self)
    }

    /// Set the kernel command line.
    pub fn with_cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.cmdline = cmdline.into();
        self
    }

    /// Get kernel image data.
    pub fn kernel_data(&self) -> &[u8] {
        &self.kernel_data
    }

    /// Get initrd data if present.
    pub fn initrd_data(&self) -> Option<&[u8]> {
        self.initrd_data.as_deref()
    }

    /// Get command line.
    pub fn cmdline(&self) -> &str {
        &self.cmdline
    }

    /// Detect kernel format.
    pub fn detect_format(&self) -> KernelFormat {
        if self.kernel_data.len() < 64 {
            return KernelFormat::Raw;
        }

        // Check for ELF magic: 0x7F 'E' 'L' 'F'
        if self.kernel_data.len() >= 4 && &self.kernel_data[0..4] == b"\x7fELF" {
            return KernelFormat::Elf;
        }

        // Check for ARM64 Image header
        // Magic at offset 0x38: 0x644d5241 ("ARM\x64" in little endian)
        if self.kernel_data.len() >= 0x40 {
            let magic = u32::from_le_bytes([
                self.kernel_data[0x38],
                self.kernel_data[0x39],
                self.kernel_data[0x3a],
                self.kernel_data[0x3b],
            ]);
            if magic == 0x644d5241 {
                return KernelFormat::Arm64Image;
            }
        }

        // Check for x86 bzImage magic
        // "HdrS" at offset 0x202 in setup header
        if self.kernel_data.len() >= 0x206 {
            let magic = &self.kernel_data[0x202..0x206];
            if magic == b"HdrS" {
                return KernelFormat::BzImage;
            }
        }

        KernelFormat::Raw
    }

    /// Load kernel into guest memory and return kernel info.
    pub fn load(&self, memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        match self.detect_format() {
            KernelFormat::Arm64Image => self.load_arm64(memory),
            KernelFormat::BzImage => self.load_x86_64(memory),
            KernelFormat::Elf => self.load_elf(memory),
            KernelFormat::Raw => self.load_raw(memory),
        }
    }

    /// Load ARM64 Image format kernel.
    #[cfg(target_arch = "aarch64")]
    fn load_arm64(&self, memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        // ARM64 Image header structure:
        // 0x00: code0 (executable code)
        // 0x04: code1 (executable code)
        // 0x08: text_offset (offset from start of RAM to kernel image)
        // 0x10: image_size
        // 0x18: flags
        // 0x20: res2
        // 0x28: res3
        // 0x30: res4
        // 0x38: magic (0x644d5241 "ARM\x64")
        // 0x3c: res5

        if self.kernel_data.len() < 0x40 {
            return Err(Error::InvalidKernel("Kernel too small".into()));
        }

        // Read text_offset
        let text_offset = u64::from_le_bytes([
            self.kernel_data[0x08],
            self.kernel_data[0x09],
            self.kernel_data[0x0a],
            self.kernel_data[0x0b],
            self.kernel_data[0x0c],
            self.kernel_data[0x0d],
            self.kernel_data[0x0e],
            self.kernel_data[0x0f],
        ]);

        // Kernel load address (RAM base + 2MB aligned offset)
        // RAM starts at 0x40000000 (1GB), not 0
        // ARM64 requires 2MB alignment for the kernel image base
        const RAM_BASE: u64 = 0x4000_0000; // 1GB - matches vm.rs and arm64.rs
        const KERNEL_OFFSET: u64 = 0x20_0000; // 2MB aligned offset within RAM

        // text_offset from kernel header is relative offset, usually 0 for modern kernels
        // We ignore it and use a fixed 2MB offset for simplicity
        let _ = text_offset; // Suppress warning
        let load_addr = RAM_BASE + KERNEL_OFFSET;

        // Entry point is at the load address
        let entry = load_addr;

        // Write kernel to memory
        // Note: memory.write() takes an offset from buffer start, not GPA
        // Our buffer is mapped at RAM_BASE, so offset = GPA - RAM_BASE
        let offset = (load_addr - RAM_BASE) as usize;
        memory.write(offset, &self.kernel_data)?;

        // Load initrd if present
        let (initrd_start, initrd_end) = if let Some(initrd) = &self.initrd_data {
            // Place initrd after kernel, aligned to 4KB
            let initrd_gpa = align_up(load_addr + self.kernel_data.len() as u64, 4096);
            let initrd_offset = (initrd_gpa - RAM_BASE) as usize;
            memory.write(initrd_offset, initrd)?;
            (Some(initrd_gpa), Some(initrd_gpa + initrd.len() as u64))
        } else {
            (None, None)
        };

        Ok(KernelInfo {
            entry,
            load_addr,
            size: self.kernel_data.len(),
            format: KernelFormat::Arm64Image,
            initrd_start,
            initrd_end,
        })
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn load_arm64(&self, _memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        Err(Error::InvalidKernel("ARM64 kernel not supported on this architecture".into()))
    }

    /// Load x86_64 bzImage format kernel.
    #[cfg(target_arch = "x86_64")]
    fn load_x86_64(&self, memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        self.load_x86_64_with_mem_size(memory, self.memory_mb)
    }

    /// Load x86_64 bzImage format kernel with specified memory size.
    #[cfg(target_arch = "x86_64")]
    pub fn load_x86_64_with_mem_size(&self, memory: &mut impl MemoryWriter, memory_mb: u32) -> Result<KernelInfo> {
        // bzImage structure:
        // - Setup code (real mode, first sectors)
        // - Protected mode kernel (rest)
        //
        // Boot protocol requires:
        // 1. Load setup code at 0x10000 (or other suitable address)
        // 2. Load protected mode kernel at 0x100000 (1MB)
        // 3. Set up boot_params structure with E820 map
        // 4. Jump to protected mode entry

        if self.kernel_data.len() < 0x206 {
            return Err(Error::InvalidKernel("Kernel too small for bzImage".into()));
        }

        // Read setup sectors count
        let setup_sects = self.kernel_data[0x1f1];
        let setup_sects = if setup_sects == 0 { 4 } else { setup_sects as usize };
        let setup_size = (setup_sects + 1) * 512;

        if self.kernel_data.len() < setup_size {
            return Err(Error::InvalidKernel("Invalid setup size".into()));
        }

        // Boot params at 0x10000
        const BOOT_PARAMS_ADDR: u64 = 0x10000;
        // Command line at 128KB
        const CMDLINE_ADDR: u64 = 0x20000;

        // Read preferred load address from header (offset 0x258)
        // Modern kernels prefer loading at 16MB (0x1000000) with 16MB alignment
        // But for compatibility, default to 1MB if pref_address is not readable
        let pref_address = if self.kernel_data.len() >= 0x260 {
            u64::from_le_bytes(self.kernel_data[0x258..0x260].try_into().unwrap_or([0; 8]))
        } else {
            0x100000 // Default 1MB
        };

        // Use preferred address if valid, otherwise use 16MB as default for modern kernels
        let kernel_addr = if pref_address >= 0x100000 {
            pref_address
        } else {
            0x1000000 // 16MB default for modern kernels
        };

        // Initrd should be placed after the kernel
        // init_size tells us how much space the kernel needs
        let init_size = if self.kernel_data.len() >= 0x264 {
            u32::from_le_bytes(self.kernel_data[0x260..0x264].try_into().unwrap_or([0; 4])) as u64
        } else {
            0x2000000 // Default 32MB for kernel space
        };
        let initrd_addr = kernel_addr + init_size;

        // Create boot_params buffer (4KB, zeroed)
        let mut boot_params = vec![0u8; 4096];

        // Copy the setup header from the kernel image (offset 0x1f1 to ~0x290)
        // This contains the boot protocol information
        if setup_size >= 0x202 {
            // Copy the setup header portion (from 0x1f1 onwards)
            let header_start = 0x1f1;
            let header_end = std::cmp::min(setup_size, 0x290);
            boot_params[header_start..header_end].copy_from_slice(&self.kernel_data[header_start..header_end]);
        }

        // Set type_of_loader (0x210) - 0xff = undefined boot loader
        boot_params[0x210] = 0xff;

        // Set loadflags (0x211)
        // Bit 0: LOADED_HIGH - kernel is loaded at 0x100000
        // Bit 6: CAN_USE_HEAP
        // Bit 7: Kernel can be loaded above 4GB (if xloadflags supports)
        boot_params[0x211] = 0x81; // LOADED_HIGH | CAN_USE_HEAP

        // Set heap_end_ptr (0x224) - relative to 0x10000
        let heap_end: u16 = 0xfe00; // Leave room at top of setup segment
        boot_params[0x224..0x226].copy_from_slice(&heap_end.to_le_bytes());

        // Set command line
        if !self.cmdline.is_empty() {
            // Store command line pointer (0x228)
            boot_params[0x228..0x22c].copy_from_slice(&(CMDLINE_ADDR as u32).to_le_bytes());
        }

        // Set up initrd if present
        if let Some(initrd) = &self.initrd_data {
            // ramdisk_image (0x218) - address of initrd
            boot_params[0x218..0x21c].copy_from_slice(&(initrd_addr as u32).to_le_bytes());
            // ramdisk_size (0x21c) - size of initrd
            boot_params[0x21c..0x220].copy_from_slice(&(initrd.len() as u32).to_le_bytes());
        }

        // Set up E820 memory map
        // E820 map entries start at offset 0x2d0 in boot_params
        // e820_entries count is at offset 0x1e8
        // Each entry is 20 bytes: addr (8), size (8), type (4)

        // E820 types: 1=RAM, 2=Reserved, 3=ACPI reclaimable, 4=ACPI NVS, 5=Unusable
        let memory_size = (memory_mb as u64) * 1024 * 1024;

        let e820_entries: Vec<(u64, u64, u32)> = vec![
            // Entry 0: Low memory (0 - 0x9fc00) - usable RAM below video memory
            (0x0000_0000, 0x0009_fc00, 1),
            // Entry 1: Reserved (0x9fc00 - 0xa0000) - EBDA
            (0x0009_fc00, 0x0000_0400, 2),
            // Entry 2: Reserved (0xa0000 - 0x100000) - Video memory and ROM
            (0x000a_0000, 0x0006_0000, 2),
            // Entry 3: Usable RAM (1MB to end of memory)
            (0x0010_0000, memory_size - 0x0010_0000, 1),
        ];

        // Write e820_entries count
        boot_params[0x1e8] = e820_entries.len() as u8;

        // Write E820 map entries at offset 0x2d0
        for (i, (addr, size, entry_type)) in e820_entries.iter().enumerate() {
            let offset = 0x2d0 + i * 20;
            boot_params[offset..offset+8].copy_from_slice(&addr.to_le_bytes());
            boot_params[offset+8..offset+16].copy_from_slice(&size.to_le_bytes());
            boot_params[offset+16..offset+20].copy_from_slice(&entry_type.to_le_bytes());
        }

        // Write boot params to memory
        memory.write(BOOT_PARAMS_ADDR as usize, &boot_params)?;

        // Write protected mode kernel at the preferred address
        let kernel_code = &self.kernel_data[setup_size..];
        memory.write(kernel_addr as usize, kernel_code)?;

        // Write command line
        if !self.cmdline.is_empty() {
            let mut cmdline_bytes = self.cmdline.as_bytes().to_vec();
            cmdline_bytes.push(0); // Null terminate
            memory.write(CMDLINE_ADDR as usize, &cmdline_bytes)?;
        }

        // Load initrd if present
        if let Some(initrd) = &self.initrd_data {
            memory.write(initrd_addr as usize, initrd)?;
        }

        let (initrd_start, initrd_end) = if let Some(initrd) = &self.initrd_data {
            (Some(initrd_addr), Some(initrd_addr + initrd.len() as u64))
        } else {
            (None, None)
        };

        // For 64-bit boot, the entry point is startup_64, which is at offset 0x200
        // from the start of the protected mode kernel (startup_32 is at offset 0)
        const STARTUP_64_OFFSET: u64 = 0x200;

        Ok(KernelInfo {
            entry: kernel_addr + STARTUP_64_OFFSET, // 64-bit entry point
            load_addr: kernel_addr,
            size: self.kernel_data.len() - setup_size,
            format: KernelFormat::BzImage,
            initrd_start,
            initrd_end,
        })
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn load_x86_64(&self, _memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        Err(Error::InvalidKernel("x86_64 kernel not supported on this architecture".into()))
    }

    /// Load ELF format kernel.
    #[cfg(target_arch = "x86_64")]
    fn load_elf(&self, memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        // ELF header structure (64-bit):
        // 0x00: e_ident[16] (magic + class + endian + version)
        // 0x10: e_type (2 bytes)
        // 0x12: e_machine (2 bytes)
        // 0x14: e_version (4 bytes)
        // 0x18: e_entry (8 bytes) - entry point
        // 0x20: e_phoff (8 bytes) - program header offset
        // 0x28: e_shoff (8 bytes) - section header offset
        // 0x30: e_flags (4 bytes)
        // 0x34: e_ehsize (2 bytes)
        // 0x36: e_phentsize (2 bytes) - program header entry size
        // 0x38: e_phnum (2 bytes) - program header count

        if self.kernel_data.len() < 0x40 {
            return Err(Error::InvalidKernel("ELF file too small".into()));
        }

        // Verify ELF64 (class = 2)
        if self.kernel_data[4] != 2 {
            return Err(Error::InvalidKernel("Not a 64-bit ELF file".into()));
        }

        // Verify little-endian (data = 1)
        if self.kernel_data[5] != 1 {
            return Err(Error::InvalidKernel("Not a little-endian ELF file".into()));
        }

        // Verify x86_64 (e_machine = 0x3E)
        let e_machine = u16::from_le_bytes([self.kernel_data[0x12], self.kernel_data[0x13]]);
        if e_machine != 0x3E {
            return Err(Error::InvalidKernel(format!("Not an x86_64 ELF (machine=0x{:x})", e_machine)));
        }

        // Read entry point
        let entry = u64::from_le_bytes(self.kernel_data[0x18..0x20].try_into().unwrap());

        // Read program header info
        let e_phoff = u64::from_le_bytes(self.kernel_data[0x20..0x28].try_into().unwrap()) as usize;
        let e_phentsize = u16::from_le_bytes([self.kernel_data[0x36], self.kernel_data[0x37]]) as usize;
        let e_phnum = u16::from_le_bytes([self.kernel_data[0x38], self.kernel_data[0x39]]) as usize;

        // Load each PT_LOAD segment
        let mut lowest_addr = u64::MAX;
        let mut highest_addr = 0u64;

        for i in 0..e_phnum {
            let ph_offset = e_phoff + i * e_phentsize;
            if ph_offset + e_phentsize > self.kernel_data.len() {
                break;
            }

            // Program header structure (64-bit):
            // 0x00: p_type (4 bytes)
            // 0x04: p_flags (4 bytes)
            // 0x08: p_offset (8 bytes) - file offset
            // 0x10: p_vaddr (8 bytes) - virtual address
            // 0x18: p_paddr (8 bytes) - physical address
            // 0x20: p_filesz (8 bytes) - size in file
            // 0x28: p_memsz (8 bytes) - size in memory
            // 0x30: p_align (8 bytes)

            let p_type = u32::from_le_bytes(self.kernel_data[ph_offset..ph_offset+4].try_into().unwrap());

            // PT_LOAD = 1
            if p_type != 1 {
                continue;
            }

            let p_offset = u64::from_le_bytes(self.kernel_data[ph_offset+0x08..ph_offset+0x10].try_into().unwrap()) as usize;
            let p_paddr = u64::from_le_bytes(self.kernel_data[ph_offset+0x18..ph_offset+0x20].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(self.kernel_data[ph_offset+0x20..ph_offset+0x28].try_into().unwrap()) as usize;
            let p_memsz = u64::from_le_bytes(self.kernel_data[ph_offset+0x28..ph_offset+0x30].try_into().unwrap());

            if p_filesz > 0 && p_offset + p_filesz <= self.kernel_data.len() {
                let segment_data = &self.kernel_data[p_offset..p_offset + p_filesz];
                memory.write(p_paddr as usize, segment_data)?;

                if p_paddr < lowest_addr {
                    lowest_addr = p_paddr;
                }
                if p_paddr + p_memsz > highest_addr {
                    highest_addr = p_paddr + p_memsz;
                }
            }
        }

        // Set up boot params at 0x10000
        const BOOT_PARAMS_ADDR: u64 = 0x10000;

        // Write basic boot params header (minimal)
        // type_of_loader at 0x210, loadflags at 0x211
        let mut boot_params = vec![0u8; 4096];
        boot_params[0x210] = 0xff; // type_of_loader = unknown
        boot_params[0x211] = 0x81; // loadflags: LOADED_HIGH | CAN_USE_HEAP

        // Set up command line
        if !self.cmdline.is_empty() {
            const CMDLINE_ADDR: u64 = 0x20000;
            let mut cmdline_bytes = self.cmdline.as_bytes().to_vec();
            cmdline_bytes.push(0);
            memory.write(CMDLINE_ADDR as usize, &cmdline_bytes)?;

            // cmd_line_ptr at 0x228
            let ptr_bytes = (CMDLINE_ADDR as u32).to_le_bytes();
            boot_params[0x228..0x22c].copy_from_slice(&ptr_bytes);
        }

        // Load initrd if present
        let (initrd_start, initrd_end) = if let Some(initrd) = &self.initrd_data {
            const INITRD_ADDR: u64 = 0x8000000; // 128MB
            memory.write(INITRD_ADDR as usize, initrd)?;

            // ramdisk_image at 0x218, ramdisk_size at 0x21c
            let addr_bytes = (INITRD_ADDR as u32).to_le_bytes();
            let size_bytes = (initrd.len() as u32).to_le_bytes();
            boot_params[0x218..0x21c].copy_from_slice(&addr_bytes);
            boot_params[0x21c..0x220].copy_from_slice(&size_bytes);

            (Some(INITRD_ADDR), Some(INITRD_ADDR + initrd.len() as u64))
        } else {
            (None, None)
        };

        memory.write(BOOT_PARAMS_ADDR as usize, &boot_params)?;

        Ok(KernelInfo {
            entry,
            load_addr: lowest_addr,
            size: (highest_addr - lowest_addr) as usize,
            format: KernelFormat::Elf,
            initrd_start,
            initrd_end,
        })
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn load_elf(&self, _memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        Err(Error::InvalidKernel("ELF kernel not supported on this architecture".into()))
    }

    /// Load raw kernel at default address.
    fn load_raw(&self, memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        // ARM64: RAM starts at 0x40000000 (1GB), kernel loaded at RAM + 512KB
        // x86_64: RAM starts at 0, kernel loaded at 1MB
        #[cfg(target_arch = "aarch64")]
        const RAM_BASE: u64 = 0x4000_0000;
        #[cfg(target_arch = "aarch64")]
        const LOAD_OFFSET: u64 = 0x8_0000; // 512KB - standard ARM64 text_offset

        #[cfg(target_arch = "x86_64")]
        const RAM_BASE: u64 = 0;
        #[cfg(target_arch = "x86_64")]
        const LOAD_OFFSET: u64 = 0x100000; // 1MB

        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        const RAM_BASE: u64 = 0;
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        const LOAD_OFFSET: u64 = 0x10000;

        // Write to memory buffer offset (memory buffer starts at RAM_BASE in guest PA space)
        memory.write(LOAD_OFFSET as usize, &self.kernel_data)?;

        // Entry point is the guest physical address
        let entry = RAM_BASE + LOAD_OFFSET;

        Ok(KernelInfo {
            entry,
            load_addr: entry,
            size: self.kernel_data.len(),
            format: KernelFormat::Raw,
            initrd_start: None,
            initrd_end: None,
        })
    }

    /// Read a file into a Vec<u8>.
    fn read_file(path: &Path) -> Result<Vec<u8>> {
        let mut file = File::open(path)
            .map_err(|_| Error::KernelNotFound(path.to_path_buf()))?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| Error::Io(e))?;

        Ok(data)
    }
}

/// Trait for writing to guest memory.
pub trait MemoryWriter {
    fn write(&mut self, addr: usize, data: &[u8]) -> Result<()>;
}

/// Align value up to the given alignment.
#[allow(dead_code)]
fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_raw_format() {
        let loader = LinuxLoader {
            kernel_data: vec![0x00; 64],
            initrd_data: None,
            cmdline: String::new(),
        };
        assert_eq!(loader.detect_format(), KernelFormat::Raw);
    }

    #[test]
    fn test_detect_arm64_format() {
        let mut kernel_data = vec![0x00; 0x40];
        // ARM64 magic at offset 0x38
        kernel_data[0x38] = 0x41; // 'A'
        kernel_data[0x39] = 0x52; // 'R'
        kernel_data[0x3a] = 0x4d; // 'M'
        kernel_data[0x3b] = 0x64; // 'd'

        let loader = LinuxLoader {
            kernel_data,
            initrd_data: None,
            cmdline: String::new(),
        };
        assert_eq!(loader.detect_format(), KernelFormat::Arm64Image);
    }

    #[test]
    fn test_detect_bzimage_format() {
        let mut kernel_data = vec![0x00; 0x206];
        // bzImage magic "HdrS" at offset 0x202
        kernel_data[0x202] = b'H';
        kernel_data[0x203] = b'd';
        kernel_data[0x204] = b'r';
        kernel_data[0x205] = b'S';

        let loader = LinuxLoader {
            kernel_data,
            initrd_data: None,
            cmdline: String::new(),
        };
        assert_eq!(loader.detect_format(), KernelFormat::BzImage);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
    }
}
