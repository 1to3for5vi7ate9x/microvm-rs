//! Simple GIC (Generic Interrupt Controller) for ARM64.
//!
//! This provides a minimal GICv2 implementation that handles timer
//! interrupts, allowing Linux to boot and run.

/// GICv2 Distributor base address
pub const GICD_BASE: u64 = 0x0800_0000;
/// GICv2 Distributor size
pub const GICD_SIZE: u64 = 0x1_0000;

/// GICv2 CPU Interface base address
pub const GICC_BASE: u64 = 0x0801_0000;
/// GICv2 CPU Interface size
pub const GICC_SIZE: u64 = 0x1_0000;

/// Virtual Timer IRQ (PPI 11 = IRQ 27)
pub const VTIMER_IRQ: u32 = 27;

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

/// GIC that tracks pending interrupts.
pub struct Gic {
    /// Distributor control register
    gicd_ctlr: u32,
    /// CPU interface control register
    gicc_ctlr: u32,
    /// Priority mask
    gicc_pmr: u32,
    /// Pending interrupt bitmap (256 interrupts)
    pending: [u32; 8],
    /// Enabled interrupt bitmap (256 interrupts)
    enabled: [u32; 8],
    /// Currently active interrupt (being serviced)
    active_irq: Option<u32>,
}

impl Default for Gic {
    fn default() -> Self {
        Self::new()
    }
}

impl Gic {
    /// Create a new GIC instance.
    pub fn new() -> Self {
        let mut enabled = [0u32; 8];
        // Enable PPIs (16-31) by default - they include timer interrupts
        enabled[0] = 0xFFFF_0000;

        Self {
            gicd_ctlr: 0,
            gicc_ctlr: 0,
            gicc_pmr: 0xFF, // All priorities enabled
            pending: [0u32; 8],
            enabled,
            active_irq: None,
        }
    }

    /// Set an interrupt as pending.
    pub fn set_pending(&mut self, irq: u32) {
        if irq < 256 {
            let idx = (irq / 32) as usize;
            let bit = irq % 32;
            self.pending[idx] |= 1 << bit;
        }
    }

    /// Clear a pending interrupt.
    pub fn clear_pending(&mut self, irq: u32) {
        if irq < 256 {
            let idx = (irq / 32) as usize;
            let bit = irq % 32;
            self.pending[idx] &= !(1 << bit);
        }
    }

    /// Check if an interrupt is pending.
    pub fn is_pending(&self, irq: u32) -> bool {
        if irq < 256 {
            let idx = (irq / 32) as usize;
            let bit = irq % 32;
            (self.pending[idx] & (1 << bit)) != 0
        } else {
            false
        }
    }

    /// Check if an interrupt is enabled.
    pub fn is_enabled(&self, irq: u32) -> bool {
        if irq < 256 {
            let idx = (irq / 32) as usize;
            let bit = irq % 32;
            (self.enabled[idx] & (1 << bit)) != 0
        } else {
            false
        }
    }

    /// Get the highest priority pending interrupt.
    pub fn get_pending_irq(&self) -> Option<u32> {
        for idx in 0..8 {
            let pending_enabled = self.pending[idx] & self.enabled[idx];
            if pending_enabled != 0 {
                // Find lowest set bit (highest priority)
                let bit = pending_enabled.trailing_zeros();
                return Some((idx as u32) * 32 + bit);
            }
        }
        None
    }

    /// Check if address is in GIC range.
    pub fn contains(&self, addr: u64) -> bool {
        (addr >= GICD_BASE && addr < GICD_BASE + GICD_SIZE)
            || (addr >= GICC_BASE && addr < GICC_BASE + GICC_SIZE)
    }

    /// Read from GIC register.
    pub fn read(&mut self, addr: u64) -> u32 {
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
            o if o >= gicd::ISENABLER && o < gicd::ISENABLER + 32 => {
                let idx = ((o - gicd::ISENABLER) / 4) as usize;
                if idx < 8 { self.enabled[idx] } else { 0 }
            }
            o if o >= gicd::ISPENDR && o < gicd::ISPENDR + 32 => {
                let idx = ((o - gicd::ISPENDR) / 4) as usize;
                if idx < 8 { self.pending[idx] } else { 0 }
            }
            _ => 0,
        }
    }

    fn write_distributor(&mut self, offset: u64, value: u32) {
        match offset {
            gicd::CTLR => self.gicd_ctlr = value,
            o if o >= gicd::ISENABLER && o < gicd::ISENABLER + 32 => {
                // Set-enable: writing 1 enables the interrupt
                let idx = ((o - gicd::ISENABLER) / 4) as usize;
                if idx < 8 { self.enabled[idx] |= value; }
            }
            o if o >= gicd::ICENABLER && o < gicd::ICENABLER + 32 => {
                // Clear-enable: writing 1 disables the interrupt
                let idx = ((o - gicd::ICENABLER) / 4) as usize;
                if idx < 8 { self.enabled[idx] &= !value; }
            }
            o if o >= gicd::ISPENDR && o < gicd::ISPENDR + 32 => {
                // Set-pending: writing 1 sets interrupt pending
                let idx = ((o - gicd::ISPENDR) / 4) as usize;
                if idx < 8 { self.pending[idx] |= value; }
            }
            o if o >= gicd::ICPENDR && o < gicd::ICPENDR + 32 => {
                // Clear-pending: writing 1 clears pending state
                let idx = ((o - gicd::ICPENDR) / 4) as usize;
                if idx < 8 { self.pending[idx] &= !value; }
            }
            _ => {}
        }
    }

    fn read_cpu_interface(&mut self, offset: u64) -> u32 {
        match offset {
            gicc::CTLR => self.gicc_ctlr,
            gicc::PMR => self.gicc_pmr,
            gicc::IAR => {
                // Return the highest priority pending interrupt
                if let Some(irq) = self.get_pending_irq() {
                    // Clear pending and mark as active
                    self.clear_pending(irq);
                    self.active_irq = Some(irq);
                    irq
                } else {
                    // No pending interrupt (spurious)
                    1023
                }
            }
            gicc::HPPIR => {
                // Return highest priority pending without acknowledging
                self.get_pending_irq().unwrap_or(1023)
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
                // End of interrupt - clear active state
                if self.active_irq == Some(value) {
                    self.active_irq = None;
                }
            }
            _ => {}
        }
    }
}
