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
}

/// Kernel image format.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KernelFormat {
    /// ARM64 Image format
    Arm64Image,
    /// x86_64 bzImage format
    BzImage,
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
}

impl LinuxLoader {
    /// Create a new Linux loader from a kernel path.
    pub fn new<P: AsRef<Path>>(kernel_path: P) -> Result<Self> {
        let kernel_data = Self::read_file(kernel_path.as_ref())?;

        Ok(Self {
            kernel_data,
            initrd_data: None,
            cmdline: String::new(),
        })
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
        if let Some(initrd) = &self.initrd_data {
            // Place initrd after kernel, aligned to 4KB
            let initrd_gpa = align_up(load_addr + self.kernel_data.len() as u64, 4096);
            let initrd_offset = (initrd_gpa - RAM_BASE) as usize;
            memory.write(initrd_offset, initrd)?;
        }

        // TODO: Set up device tree with boot parameters

        Ok(KernelInfo {
            entry,
            load_addr,
            size: self.kernel_data.len(),
            format: KernelFormat::Arm64Image,
        })
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn load_arm64(&self, _memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        Err(Error::InvalidKernel("ARM64 kernel not supported on this architecture".into()))
    }

    /// Load x86_64 bzImage format kernel.
    #[cfg(target_arch = "x86_64")]
    fn load_x86_64(&self, memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        // bzImage structure:
        // - Setup code (real mode, first sectors)
        // - Protected mode kernel (rest)
        //
        // Boot protocol requires:
        // 1. Load setup code at 0x10000 (or other suitable address)
        // 2. Load protected mode kernel at 0x100000 (1MB)
        // 3. Set up boot_params structure
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
        // Protected mode kernel at 1MB
        const KERNEL_ADDR: u64 = 0x100000;

        // Write boot params (setup header at offset 0x1f1)
        let boot_params = &self.kernel_data[..setup_size];
        memory.write(BOOT_PARAMS_ADDR as usize, boot_params)?;

        // Write protected mode kernel
        let kernel_code = &self.kernel_data[setup_size..];
        memory.write(KERNEL_ADDR as usize, kernel_code)?;

        // Set up command line
        if !self.cmdline.is_empty() {
            const CMDLINE_ADDR: u64 = 0x20000;
            let mut cmdline_bytes = self.cmdline.as_bytes().to_vec();
            cmdline_bytes.push(0); // Null terminate
            memory.write(CMDLINE_ADDR as usize, &cmdline_bytes)?;

            // Update cmd_line_ptr in boot params
            let ptr_bytes = (CMDLINE_ADDR as u32).to_le_bytes();
            memory.write((BOOT_PARAMS_ADDR + 0x228) as usize, &ptr_bytes)?;
        }

        // Load initrd if present
        if let Some(initrd) = &self.initrd_data {
            const INITRD_ADDR: u64 = 0x800000; // 8MB
            memory.write(INITRD_ADDR as usize, initrd)?;

            // Update ramdisk_image and ramdisk_size in boot params
            let addr_bytes = (INITRD_ADDR as u32).to_le_bytes();
            let size_bytes = (initrd.len() as u32).to_le_bytes();
            memory.write((BOOT_PARAMS_ADDR + 0x218) as usize, &addr_bytes)?;
            memory.write((BOOT_PARAMS_ADDR + 0x21c) as usize, &size_bytes)?;
        }

        Ok(KernelInfo {
            entry: KERNEL_ADDR,
            load_addr: KERNEL_ADDR,
            size: self.kernel_data.len() - setup_size,
            format: KernelFormat::BzImage,
        })
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn load_x86_64(&self, _memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        Err(Error::InvalidKernel("x86_64 kernel not supported on this architecture".into()))
    }

    /// Load raw kernel at default address.
    fn load_raw(&self, memory: &mut impl MemoryWriter) -> Result<KernelInfo> {
        // Default load address - use low addresses since our VM memory starts at 0
        #[cfg(target_arch = "aarch64")]
        const LOAD_ADDR: u64 = 0x8_0000; // 512KB - standard ARM64 text_offset
        #[cfg(target_arch = "x86_64")]
        const LOAD_ADDR: u64 = 0x100000; // 1MB
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        const LOAD_ADDR: u64 = 0x10000;

        memory.write(LOAD_ADDR as usize, &self.kernel_data)?;

        Ok(KernelInfo {
            entry: LOAD_ADDR,
            load_addr: LOAD_ADDR,
            size: self.kernel_data.len(),
            format: KernelFormat::Raw,
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
