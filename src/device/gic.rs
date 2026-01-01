//! Simple GIC (Generic Interrupt Controller) stub for ARM64.
//!
//! This provides a minimal GICv2 implementation that allows Linux to boot.
//! It doesn't actually handle interrupts, but returns sensible values
//! for Linux's probing and initialization.

/// GICv2 Distributor base address
pub const GICD_BASE: u64 = 0x0800_0000;
/// GICv2 Distributor size
pub const GICD_SIZE: u64 = 0x1_0000;

/// GICv2 CPU Interface base address
pub const GICC_BASE: u64 = 0x0801_0000;
/// GICv2 CPU Interface size
pub const GICC_SIZE: u64 = 0x1_0000;

/// GIC Distributor registers
mod gicd {
    pub const CTLR: u64 = 0x000;      // Distributor Control
    pub const TYPER: u64 = 0x004;     // Interrupt Controller Type
    pub const IIDR: u64 = 0x008;      // Distributor Implementer ID
    pub const IGROUPR: u64 = 0x080;   // Interrupt Group (base)
    pub const ISENABLER: u64 = 0x100; // Interrupt Set-Enable (base)
    pub const ICENABLER: u64 = 0x180; // Interrupt Clear-Enable (base)
    pub const ISPENDR: u64 = 0x200;   // Interrupt Set-Pending (base)
    pub const ICPENDR: u64 = 0x280;   // Interrupt Clear-Pending (base)
    pub const ISACTIVER: u64 = 0x300; // Interrupt Set-Active (base)
    pub const ICACTIVER: u64 = 0x380; // Interrupt Clear-Active (base)
    pub const IPRIORITYR: u64 = 0x400; // Interrupt Priority (base)
    pub const ITARGETSR: u64 = 0x800; // Interrupt Targets (base)
    pub const ICFGR: u64 = 0xC00;     // Interrupt Config (base)
    pub const SGIR: u64 = 0xF00;      // Software Generated Interrupt
    pub const PIDR2: u64 = 0xFE8;     // Peripheral ID2
}

/// GIC CPU Interface registers
mod gicc {
    pub const CTLR: u64 = 0x000;   // CPU Interface Control
    pub const PMR: u64 = 0x004;    // Interrupt Priority Mask
    pub const BPR: u64 = 0x008;    // Binary Point
    pub const IAR: u64 = 0x00C;    // Interrupt Acknowledge
    pub const EOIR: u64 = 0x010;   // End of Interrupt
    pub const RPR: u64 = 0x014;    // Running Priority
    pub const HPPIR: u64 = 0x018;  // Highest Priority Pending Interrupt
    pub const IIDR: u64 = 0x00FC;  // CPU Interface Identification
}

/// Simple GIC stub that allows Linux to boot.
#[derive(Default)]
pub struct Gic {
    /// Distributor control register
    gicd_ctlr: u32,
    /// CPU interface control register
    gicc_ctlr: u32,
    /// Priority mask
    gicc_pmr: u32,
}

impl Gic {
    /// Create a new GIC instance.
    pub fn new() -> Self {
        Self {
            gicd_ctlr: 0,
            gicc_ctlr: 0,
            gicc_pmr: 0xFF, // All priorities enabled
        }
    }

    /// Check if address is in GIC range.
    pub fn contains(&self, addr: u64) -> bool {
        (addr >= GICD_BASE && addr < GICD_BASE + GICD_SIZE)
            || (addr >= GICC_BASE && addr < GICC_BASE + GICC_SIZE)
    }

    /// Read from GIC register.
    pub fn read(&self, addr: u64) -> u32 {
        if addr >= GICD_BASE && addr < GICD_BASE + GICD_SIZE {
            self.read_distributor(addr - GICD_BASE)
        } else if addr >= GICC_BASE && addr < GICC_BASE + GICC_SIZE {
            self.read_cpu_interface(addr - GICC_BASE)
        } else {
            0
        }
    }

    /// Write to GIC register.
    pub fn write(&mut self, addr: u64, value: u32) {
        if addr >= GICD_BASE && addr < GICD_BASE + GICD_SIZE {
            self.write_distributor(addr - GICD_BASE, value);
        } else if addr >= GICC_BASE && addr < GICC_BASE + GICC_SIZE {
            self.write_cpu_interface(addr - GICC_BASE, value);
        }
    }

    fn read_distributor(&self, offset: u64) -> u32 {
        match offset {
            gicd::CTLR => self.gicd_ctlr,
            gicd::TYPER => {
                // ITLinesNumber=7 (256 interrupts), CPUNumber=0, SecurityExtn=0
                0x07
            }
            gicd::IIDR => {
                // ARM GIC, revision 2
                0x0200043B
            }
            gicd::PIDR2 => {
                // GICv2
                0x20
            }
            _ => 0,
        }
    }

    fn write_distributor(&mut self, offset: u64, value: u32) {
        match offset {
            gicd::CTLR => self.gicd_ctlr = value,
            _ => {}
        }
    }

    fn read_cpu_interface(&self, offset: u64) -> u32 {
        match offset {
            gicc::CTLR => self.gicc_ctlr,
            gicc::PMR => self.gicc_pmr,
            gicc::IAR => {
                // No pending interrupt (spurious)
                1023
            }
            gicc::IIDR => {
                // ARM GIC
                0x0202043B
            }
            _ => 0,
        }
    }

    fn write_cpu_interface(&mut self, offset: u64, value: u32) {
        match offset {
            gicc::CTLR => self.gicc_ctlr = value,
            gicc::PMR => self.gicc_pmr = value,
            gicc::EOIR => {
                // Acknowledge end of interrupt - nothing to do for stub
            }
            _ => {}
        }
    }
}
