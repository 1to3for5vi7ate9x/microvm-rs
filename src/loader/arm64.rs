//! ARM64-specific boot setup.
//!
//! ARM64 Linux boot requires:
//! 1. Kernel loaded at text_offset from start of RAM
//! 2. Device tree blob (DTB) passed in x0
//! 3. x1, x2, x3 = 0 (reserved)
//! 4. MMU off, D-cache off, I-cache on or off
//! 5. Primary CPU at EL1 or EL2

/// ARM64 boot configuration.
#[derive(Debug, Clone)]
pub struct Arm64BootConfig {
    /// Kernel entry point
    pub entry: u64,
    /// Device tree blob address
    pub dtb_addr: u64,
    /// Initial stack pointer (optional)
    pub sp: u64,
}

impl Default for Arm64BootConfig {
    fn default() -> Self {
        Self {
            entry: 0x4008_0000,   // Default kernel load address
            dtb_addr: 0x4000_0000, // DTB before kernel
            sp: 0x4800_0000,       // Stack in high memory
        }
    }
}

/// Minimal device tree blob for booting.
///
/// This creates a minimal FDT that provides:
/// - Memory node
/// - Chosen node with bootargs
/// - UART node (PL011)
pub struct DeviceTreeBuilder {
    buffer: Vec<u8>,
    strings: Vec<u8>,
    string_offsets: Vec<(String, u32)>,
}

impl DeviceTreeBuilder {
    // FDT constants
    const FDT_MAGIC: u32 = 0xd00dfeed;
    const FDT_VERSION: u32 = 17;
    const FDT_LAST_COMP_VERSION: u32 = 16;

    const FDT_BEGIN_NODE: u32 = 0x00000001;
    const FDT_END_NODE: u32 = 0x00000002;
    const FDT_PROP: u32 = 0x00000003;
    const FDT_END: u32 = 0x00000009;

    /// Create a new device tree builder.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            strings: Vec::new(),
            string_offsets: Vec::new(),
        }
    }

    /// Standard RAM base address for ARM64 virt machine.
    /// MMIO regions (GIC, UART) are below this address.
    pub const RAM_BASE: u64 = 0x4000_0000; // 1GB

    /// VirtIO MMIO base address.
    pub const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
    /// VirtIO MMIO size per device.
    pub const VIRTIO_MMIO_SIZE: u64 = 0x200;
    /// VirtIO console IRQ (SPI).
    pub const VIRTIO_CONSOLE_IRQ: u32 = 16;

    /// Build a minimal device tree for Linux boot.
    pub fn build_minimal(
        memory_size: u64,
        cmdline: &str,
        initrd_start: Option<u64>,
        initrd_end: Option<u64>,
    ) -> Vec<u8> {
        let mut builder = Self::new();
        builder.build(memory_size, cmdline, initrd_start, initrd_end, false)
    }

    /// Build a device tree with VirtIO console support.
    pub fn build_with_console(
        memory_size: u64,
        cmdline: &str,
        initrd_start: Option<u64>,
        initrd_end: Option<u64>,
    ) -> Vec<u8> {
        let mut builder = Self::new();
        builder.build(memory_size, cmdline, initrd_start, initrd_end, true)
    }

    fn build(
        &mut self,
        memory_size: u64,
        cmdline: &str,
        initrd_start: Option<u64>,
        initrd_end: Option<u64>,
        with_console: bool,
    ) -> Vec<u8> {
        // Start with structure block
        self.begin_node("");

        // Root properties
        self.add_prop_u32("#address-cells", 2);
        self.add_prop_u32("#size-cells", 2);
        self.add_prop_string("compatible", "linux,dummy-virt");
        self.add_prop_string("model", "microvm-rs Virtual Machine");

        // Memory node - starts at RAM_BASE (0x40000000) to avoid MMIO regions
        // GIC is at 0x08000000, UART at 0x09000000
        let ram_base = Self::RAM_BASE;
        self.begin_node(&format!("memory@{:x}", ram_base));
        self.add_prop_string("device_type", "memory");
        self.add_prop_reg64(ram_base, memory_size);
        self.end_node();

        // Chosen node
        self.begin_node("chosen");
        self.add_prop_string("bootargs", cmdline);
        self.add_prop_string("stdout-path", "/pl011@9000000");

        if let (Some(start), Some(end)) = (initrd_start, initrd_end) {
            self.add_prop_u64("linux,initrd-start", start);
            self.add_prop_u64("linux,initrd-end", end);
        }
        self.end_node();

        // CPU nodes
        self.begin_node("cpus");
        self.add_prop_u32("#address-cells", 1);
        self.add_prop_u32("#size-cells", 0);

        self.begin_node("cpu@0");
        self.add_prop_string("device_type", "cpu");
        self.add_prop_string("compatible", "arm,cortex-a53");
        self.add_prop_u32("reg", 0);
        self.add_prop_string("enable-method", "psci");
        self.end_node();

        self.end_node(); // cpus

        // GICv2 interrupt controller
        self.begin_node("intc@8000000");
        self.add_prop_string("compatible", "arm,cortex-a15-gic");
        self.add_prop_u32("#interrupt-cells", 3);
        self.add_prop_empty("interrupt-controller");
        // reg: distributor @ 0x08000000, cpu interface @ 0x08010000
        self.add_prop_reg64_dual(0x0800_0000, 0x1_0000, 0x0801_0000, 0x1_0000);
        self.add_prop_u32("phandle", 1);
        self.end_node();

        // Fixed clock for UART (defined before PL011 that references it)
        self.begin_node("apb-pclk");
        self.add_prop_string("compatible", "fixed-clock");
        self.add_prop_u32("#clock-cells", 0);
        self.add_prop_u32("clock-frequency", 24000000); // 24MHz
        self.add_prop_string("clock-output-names", "clk24mhz");
        self.add_prop_u32("phandle", 2);
        self.end_node();

        // Aliases for serial port
        self.begin_node("aliases");
        self.add_prop_string("serial0", "/pl011@9000000");
        self.end_node();

        // PL011 UART
        self.begin_node("pl011@9000000");
        self.add_prop_string("compatible", "arm,pl011\0arm,primecell");
        self.add_prop_reg64(0x0900_0000, 0x1000);
        // Interrupt: SPI 1 (33), level high
        self.add_prop_interrupts(0, 1, 4); // GIC_SPI, IRQ 1, level high
        self.add_prop_u32("interrupt-parent", 1); // phandle of GIC
        self.add_prop_string("clock-names", "uartclk\0apb_pclk");
        // Clocks - reference fixed clock
        self.add_prop_u32_pair("clocks", 2, 2); // phandle 2 for both clocks
        self.add_prop_string("status", "okay");
        self.add_prop_u32("phandle", 3); // Give uart a phandle too
        self.end_node();

        // PSCI node
        self.begin_node("psci");
        self.add_prop_string("compatible", "arm,psci-1.0\0arm,psci-0.2\0arm,psci");
        self.add_prop_string("method", "hvc");
        self.end_node();

        // Timer node
        self.begin_node("timer");
        self.add_prop_string("compatible", "arm,armv8-timer");
        self.add_prop_u32("always-on", 1);
        // Timer interrupts (PPI): secure phys, non-secure phys, virt, hyp
        self.add_prop_timer_interrupts();
        self.add_prop_u32("interrupt-parent", 1);
        self.end_node();

        // VirtIO console (if enabled)
        if with_console {
            let virtio_addr = Self::VIRTIO_MMIO_BASE;
            self.begin_node(&format!("virtio_mmio@{:x}", virtio_addr));
            self.add_prop_string("compatible", "virtio,mmio");
            self.add_prop_reg64(virtio_addr, Self::VIRTIO_MMIO_SIZE);
            // Interrupt: SPI 16, level high
            self.add_prop_interrupts(0, Self::VIRTIO_CONSOLE_IRQ, 4); // GIC_SPI, IRQ 16, level high
            self.add_prop_u32("interrupt-parent", 1); // phandle of GIC
            self.add_prop_empty("dma-coherent");
            self.end_node();
        }

        self.end_node(); // root

        // End marker
        self.write_u32(Self::FDT_END);

        self.finalize()
    }

    fn finalize(&self) -> Vec<u8> {
        let struct_size = self.buffer.len();
        let strings_size = self.strings.len();

        // Header size (10 u32 fields = 40 bytes)
        let header_size: usize = 40;
        // Memory reservation map: one empty entry (16 bytes: two u64 zeros)
        let mem_rsvmap_size: usize = 16;

        // Calculate offsets
        let off_mem_rsvmap = header_size;
        let off_dt_struct = header_size + mem_rsvmap_size;
        let off_dt_strings = off_dt_struct + struct_size;
        let total_size = off_dt_strings + strings_size;

        let mut fdt = Vec::with_capacity(total_size);

        // Write header (40 bytes)
        fdt.extend_from_slice(&Self::FDT_MAGIC.to_be_bytes());
        fdt.extend_from_slice(&(total_size as u32).to_be_bytes());
        fdt.extend_from_slice(&(off_dt_struct as u32).to_be_bytes());
        fdt.extend_from_slice(&(off_dt_strings as u32).to_be_bytes());
        fdt.extend_from_slice(&(off_mem_rsvmap as u32).to_be_bytes());
        fdt.extend_from_slice(&Self::FDT_VERSION.to_be_bytes());
        fdt.extend_from_slice(&Self::FDT_LAST_COMP_VERSION.to_be_bytes());
        fdt.extend_from_slice(&0u32.to_be_bytes()); // boot_cpuid_phys
        fdt.extend_from_slice(&(strings_size as u32).to_be_bytes());
        fdt.extend_from_slice(&(struct_size as u32).to_be_bytes());

        // Write memory reservation map (empty, just terminator)
        fdt.extend_from_slice(&0u64.to_be_bytes()); // address = 0
        fdt.extend_from_slice(&0u64.to_be_bytes()); // size = 0 (terminator)

        // Write structure block
        fdt.extend_from_slice(&self.buffer);

        // Write strings block
        fdt.extend_from_slice(&self.strings);

        fdt
    }

    fn begin_node(&mut self, name: &str) {
        self.write_u32(Self::FDT_BEGIN_NODE);
        self.write_string(name);
    }

    fn end_node(&mut self) {
        self.write_u32(Self::FDT_END_NODE);
    }

    fn add_prop_u32(&mut self, name: &str, value: u32) {
        let name_off = self.add_string(name);
        self.write_u32(Self::FDT_PROP);
        self.write_u32(4); // length
        self.write_u32(name_off);
        self.write_u32(value);
    }

    fn add_prop_u64(&mut self, name: &str, value: u64) {
        let name_off = self.add_string(name);
        self.write_u32(Self::FDT_PROP);
        self.write_u32(8); // length
        self.write_u32(name_off);
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    fn add_prop_string(&mut self, name: &str, value: &str) {
        let name_off = self.add_string(name);
        let value_bytes: Vec<u8> = value.bytes().chain(std::iter::once(0)).collect();
        let len = value_bytes.len() as u32;

        self.write_u32(Self::FDT_PROP);
        self.write_u32(len);
        self.write_u32(name_off);
        self.buffer.extend_from_slice(&value_bytes);
        self.align4();
    }

    fn add_prop_reg64(&mut self, addr: u64, size: u64) {
        let name_off = self.add_string("reg");
        self.write_u32(Self::FDT_PROP);
        self.write_u32(16); // 2 x u64
        self.write_u32(name_off);
        self.buffer.extend_from_slice(&addr.to_be_bytes());
        self.buffer.extend_from_slice(&size.to_be_bytes());
    }

    fn add_prop_reg64_dual(&mut self, addr1: u64, size1: u64, addr2: u64, size2: u64) {
        let name_off = self.add_string("reg");
        self.write_u32(Self::FDT_PROP);
        self.write_u32(32); // 4 x u64
        self.write_u32(name_off);
        self.buffer.extend_from_slice(&addr1.to_be_bytes());
        self.buffer.extend_from_slice(&size1.to_be_bytes());
        self.buffer.extend_from_slice(&addr2.to_be_bytes());
        self.buffer.extend_from_slice(&size2.to_be_bytes());
    }

    fn add_prop_empty(&mut self, name: &str) {
        let name_off = self.add_string(name);
        self.write_u32(Self::FDT_PROP);
        self.write_u32(0);
        self.write_u32(name_off);
    }

    fn add_prop_interrupts(&mut self, irq_type: u32, irq_num: u32, flags: u32) {
        let name_off = self.add_string("interrupts");
        self.write_u32(Self::FDT_PROP);
        self.write_u32(12); // 3 x u32
        self.write_u32(name_off);
        self.write_u32(irq_type);
        self.write_u32(irq_num);
        self.write_u32(flags);
    }

    fn add_prop_u32_pair(&mut self, name: &str, val1: u32, val2: u32) {
        let name_off = self.add_string(name);
        self.write_u32(Self::FDT_PROP);
        self.write_u32(8); // 2 x u32
        self.write_u32(name_off);
        self.write_u32(val1);
        self.write_u32(val2);
    }

    fn add_prop_timer_interrupts(&mut self) {
        // Timer interrupts for ARMv8: 4 PPIs (type=1)
        // Secure Phys: PPI 13, Non-secure Phys: PPI 14, Virt: PPI 11, Hyp: PPI 10
        // Flags: 0xf08 = level high, IRQ
        let name_off = self.add_string("interrupts");
        self.write_u32(Self::FDT_PROP);
        self.write_u32(48); // 4 interrupts x 3 cells x u32
        self.write_u32(name_off);
        // GIC_PPI = 1
        // Secure Physical Timer (PPI 13)
        self.write_u32(1); self.write_u32(13); self.write_u32(0xf08);
        // Non-secure Physical Timer (PPI 14)
        self.write_u32(1); self.write_u32(14); self.write_u32(0xf08);
        // Virtual Timer (PPI 11)
        self.write_u32(1); self.write_u32(11); self.write_u32(0xf08);
        // Hypervisor Timer (PPI 10)
        self.write_u32(1); self.write_u32(10); self.write_u32(0xf08);
    }

    fn write_u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    fn write_string(&mut self, s: &str) {
        self.buffer.extend_from_slice(s.as_bytes());
        self.buffer.push(0);
        self.align4();
    }

    fn align4(&mut self) {
        while self.buffer.len() % 4 != 0 {
            self.buffer.push(0);
        }
    }

    fn add_string(&mut self, s: &str) -> u32 {
        // Check if string already exists
        for (existing, offset) in &self.string_offsets {
            if existing == s {
                return *offset;
            }
        }

        // Add new string
        let offset = self.strings.len() as u32;
        self.strings.extend_from_slice(s.as_bytes());
        self.strings.push(0);
        self.string_offsets.push((s.to_string(), offset));
        offset
    }
}

impl Default for DeviceTreeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dtb() {
        let dtb = DeviceTreeBuilder::build_minimal(
            256 * 1024 * 1024, // 256MB
            "console=ttyAMA0",
            None,
            None,
        );

        // Check FDT magic
        let magic = u32::from_be_bytes([dtb[0], dtb[1], dtb[2], dtb[3]]);
        assert_eq!(magic, 0xd00dfeed);

        // Should have reasonable size
        assert!(dtb.len() > 100);
        assert!(dtb.len() < 4096);
    }

    #[test]
    fn test_build_dtb_with_console() {
        let dtb = DeviceTreeBuilder::build_with_console(
            256 * 1024 * 1024, // 256MB
            "console=hvc0",
            None,
            None,
        );

        // Check FDT magic
        let magic = u32::from_be_bytes([dtb[0], dtb[1], dtb[2], dtb[3]]);
        assert_eq!(magic, 0xd00dfeed);

        // Should have reasonable size (larger with virtio node)
        assert!(dtb.len() > 100);
        assert!(dtb.len() < 8192);
    }
}
