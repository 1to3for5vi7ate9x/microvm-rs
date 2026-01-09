//! PL011 UART device for ARM64.
//!
//! The PL011 is the standard UART used on ARM platforms.
//! This implementation provides basic serial console I/O.
//!
//! ## Memory Map (default base: 0x09000000)
//!
//! | Offset | Name | Description |
//! |--------|------|-------------|
//! | 0x000  | DR   | Data Register |
//! | 0x018  | FR   | Flag Register |
//! | 0x024  | IBRD | Integer Baud Rate Register |
//! | 0x028  | FBRD | Fractional Baud Rate Register |
//! | 0x02C  | LCR_H| Line Control Register |
//! | 0x030  | CR   | Control Register |
//! | 0x038  | IMSC | Interrupt Mask Set/Clear |
//! | 0x044  | ICR  | Interrupt Clear Register |

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

/// PL011 register offsets
#[allow(dead_code)]
mod reg {
    pub const DR: u64 = 0x000;      // Data Register
    pub const RSR: u64 = 0x004;     // Receive Status Register
    pub const FR: u64 = 0x018;      // Flag Register
    pub const ILPR: u64 = 0x020;    // IrDA Low-Power Counter
    pub const IBRD: u64 = 0x024;    // Integer Baud Rate
    pub const FBRD: u64 = 0x028;    // Fractional Baud Rate
    pub const LCR_H: u64 = 0x02C;   // Line Control
    pub const CR: u64 = 0x030;      // Control Register
    pub const IFLS: u64 = 0x034;    // Interrupt FIFO Level Select
    pub const IMSC: u64 = 0x038;    // Interrupt Mask Set/Clear
    pub const RIS: u64 = 0x03C;     // Raw Interrupt Status
    pub const MIS: u64 = 0x040;     // Masked Interrupt Status
    pub const ICR: u64 = 0x044;     // Interrupt Clear
    pub const DMACR: u64 = 0x048;   // DMA Control
}

/// Flag Register bits
mod fr {
    pub const TXFE: u32 = 1 << 7;   // Transmit FIFO empty
    pub const RXFF: u32 = 1 << 6;   // Receive FIFO full
    pub const TXFF: u32 = 1 << 5;   // Transmit FIFO full
    pub const RXFE: u32 = 1 << 4;   // Receive FIFO empty
    pub const BUSY: u32 = 1 << 3;   // UART busy
}

/// Control Register bits
#[allow(dead_code)]
mod cr {
    pub const UARTEN: u32 = 1 << 0; // UART enable
    pub const TXE: u32 = 1 << 8;    // Transmit enable
    pub const RXE: u32 = 1 << 9;    // Receive enable
}

/// PL011 UART device state.
pub struct Pl011 {
    /// Base address in guest physical memory
    base_addr: u64,
    /// Flag register
    fr: u32,
    /// Integer baud rate divisor
    ibrd: u32,
    /// Fractional baud rate divisor
    fbrd: u32,
    /// Line control register
    lcr_h: u32,
    /// Control register
    cr: u32,
    /// Interrupt mask
    imsc: u32,
    /// Raw interrupt status
    ris: u32,
    /// Input buffer (data from host to guest)
    rx_fifo: VecDeque<u8>,
    /// Output writer
    output: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl Pl011 {
    /// Default MMIO base address for PL011 on many ARM platforms.
    pub const DEFAULT_BASE: u64 = 0x0900_0000;

    /// Size of the MMIO region.
    pub const SIZE: u64 = 0x1000;

    /// Create a new PL011 UART that writes to stdout.
    pub fn new(base_addr: u64) -> Self {
        Self::with_output(base_addr, Arc::new(Mutex::new(Box::new(io::stdout()))))
    }

    /// Create a new PL011 UART with a custom output writer.
    pub fn with_output(base_addr: u64, output: Arc<Mutex<Box<dyn Write + Send>>>) -> Self {
        Self {
            base_addr,
            fr: fr::TXFE | fr::RXFE, // TX empty, RX empty
            ibrd: 0,
            fbrd: 0,
            lcr_h: 0,
            cr: cr::TXE | cr::RXE, // TX and RX enabled by default
            imsc: 0,
            ris: 0,
            rx_fifo: VecDeque::with_capacity(16),
            output,
        }
    }

    /// Get the base address.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Check if an address is within this device's MMIO region.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base_addr && addr < self.base_addr + Self::SIZE
    }

    /// Queue input data (from host to guest).
    pub fn queue_input(&mut self, data: &[u8]) {
        for &byte in data {
            if self.rx_fifo.len() < 16 {
                self.rx_fifo.push_back(byte);
            }
        }
        self.update_flags();
    }

    /// Update flag register based on FIFO state.
    fn update_flags(&mut self) {
        // Update RX flags
        if self.rx_fifo.is_empty() {
            self.fr |= fr::RXFE;
            self.fr &= !fr::RXFF;
        } else {
            self.fr &= !fr::RXFE;
            if self.rx_fifo.len() >= 16 {
                self.fr |= fr::RXFF;
            }
        }

        // TX is always ready (we write immediately)
        self.fr |= fr::TXFE;
        self.fr &= !fr::TXFF;
        self.fr &= !fr::BUSY;
    }

    /// Handle a read from a PL011 register.
    pub fn read(&mut self, addr: u64) -> u32 {
        let offset = addr - self.base_addr;

        match offset {
            reg::DR => {
                // Read from receive FIFO
                if let Some(byte) = self.rx_fifo.pop_front() {
                    self.update_flags();
                    byte as u32
                } else {
                    0
                }
            }
            reg::RSR => 0, // No errors
            reg::FR => self.fr,
            reg::IBRD => self.ibrd,
            reg::FBRD => self.fbrd,
            reg::LCR_H => self.lcr_h,
            reg::CR => self.cr,
            reg::IMSC => self.imsc,
            reg::RIS => self.ris,
            reg::MIS => self.ris & self.imsc,
            // PrimeCell ID registers (required for AMBA bus driver)
            // PID0-3: Peripheral ID (0x00041011 for PL011)
            0xFE0 => 0x11, // PID0
            0xFE4 => 0x10, // PID1
            0xFE8 => 0x14, // PID2 (revision 1, designer 0x41 = ARM)
            0xFEC => 0x00, // PID3
            // CID0-3: PrimeCell Component ID (0xB105F00D)
            0xFF0 => 0x0D, // CID0
            0xFF4 => 0xF0, // CID1
            0xFF8 => 0x05, // CID2
            0xFFC => 0xB1, // CID3
            _ => 0,
        }
    }

    /// Handle a write to a PL011 register.
    pub fn write(&mut self, addr: u64, value: u32) {
        let offset = addr - self.base_addr;

        match offset {
            reg::DR => {
                // Write to transmit - output the character
                let byte = (value & 0xFF) as u8;
                if let Ok(mut output) = self.output.lock() {
                    let _ = output.write_all(&[byte]);
                    let _ = output.flush();
                }
            }
            reg::RSR => {
                // Writing clears errors
            }
            reg::IBRD => self.ibrd = value & 0xFFFF,
            reg::FBRD => self.fbrd = value & 0x3F,
            reg::LCR_H => self.lcr_h = value & 0xFF,
            reg::CR => self.cr = value & 0xFFFF,
            reg::IFLS => {
                // Interrupt FIFO level - ignored for now
            }
            reg::IMSC => self.imsc = value & 0x7FF,
            reg::ICR => {
                // Clear interrupts
                self.ris &= !value;
            }
            _ => {}
        }
    }
}

impl Default for Pl011 {
    fn default() -> Self {
        Self::new(Self::DEFAULT_BASE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct TestWriter {
        data: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.data.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_pl011_write() {
        let output_data = Arc::new(Mutex::new(Vec::new()));
        let writer = TestWriter {
            data: output_data.clone(),
        };

        let mut uart = Pl011::with_output(
            Pl011::DEFAULT_BASE,
            Arc::new(Mutex::new(Box::new(writer))),
        );

        // Write "Hi"
        uart.write(Pl011::DEFAULT_BASE + reg::DR, b'H' as u32);
        uart.write(Pl011::DEFAULT_BASE + reg::DR, b'i' as u32);

        assert_eq!(&*output_data.lock().unwrap(), b"Hi");
    }

    #[test]
    fn test_pl011_read() {
        let mut uart = Pl011::default();

        // Queue some input
        uart.queue_input(b"test");

        // Check flags show data available
        let flags = uart.read(Pl011::DEFAULT_BASE + reg::FR);
        assert_eq!(flags & fr::RXFE, 0); // Not empty

        // Read the data
        assert_eq!(uart.read(Pl011::DEFAULT_BASE + reg::DR), b't' as u32);
        assert_eq!(uart.read(Pl011::DEFAULT_BASE + reg::DR), b'e' as u32);
        assert_eq!(uart.read(Pl011::DEFAULT_BASE + reg::DR), b's' as u32);
        assert_eq!(uart.read(Pl011::DEFAULT_BASE + reg::DR), b't' as u32);

        // Check flags show empty
        let flags = uart.read(Pl011::DEFAULT_BASE + reg::FR);
        assert_ne!(flags & fr::RXFE, 0); // Empty
    }
}
