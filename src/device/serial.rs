//! Simple 8250 UART serial console.
//!
//! This provides a basic serial console for early boot output
//! before virtio-console is available.

use std::collections::VecDeque;
use std::io::{self, Write};

/// 8250 UART register offsets.
mod reg {
    pub const RBR: u16 = 0; // Receive Buffer Register (read)
    pub const THR: u16 = 0; // Transmit Holding Register (write)
    pub const IER: u16 = 1; // Interrupt Enable Register
    pub const IIR: u16 = 2; // Interrupt Identification Register (read)
    pub const FCR: u16 = 2; // FIFO Control Register (write)
    pub const LCR: u16 = 3; // Line Control Register
    pub const MCR: u16 = 4; // Modem Control Register
    pub const LSR: u16 = 5; // Line Status Register
    pub const MSR: u16 = 6; // Modem Status Register
    pub const SCR: u16 = 7; // Scratch Register
}

/// Line Status Register bits.
mod lsr {
    pub const DATA_READY: u8 = 0x01;
    pub const THR_EMPTY: u8 = 0x20;
    pub const BOTH_EMPTY: u8 = 0x40;
}

/// Simple 8250 UART emulation.
pub struct Serial {
    /// Interrupt Enable Register
    ier: u8,
    /// Interrupt Identification Register
    iir: u8,
    /// Line Control Register
    lcr: u8,
    /// Modem Control Register
    mcr: u8,
    /// Line Status Register
    lsr: u8,
    /// Modem Status Register
    msr: u8,
    /// Scratch Register
    scr: u8,
    /// Divisor Latch (set when DLAB=1)
    divisor: u16,
    /// Input buffer (data from host to guest)
    input_buffer: VecDeque<u8>,
    /// Output writer
    output: Box<dyn Write + Send>,
}

impl Serial {
    /// Create a new serial console that writes to stdout.
    pub fn new() -> Self {
        Self::with_output(Box::new(io::stdout()))
    }

    /// Create a new serial console with a custom output writer.
    pub fn with_output(output: Box<dyn Write + Send>) -> Self {
        Self {
            ier: 0,
            iir: 0x01, // No interrupt pending
            lcr: 0,
            mcr: 0,
            lsr: lsr::THR_EMPTY | lsr::BOTH_EMPTY,
            msr: 0,
            scr: 0,
            divisor: 12, // 9600 baud
            input_buffer: VecDeque::new(),
            output,
        }
    }

    /// Queue input data (from host to guest).
    pub fn queue_input(&mut self, data: &[u8]) {
        self.input_buffer.extend(data);
        if !self.input_buffer.is_empty() {
            self.lsr |= lsr::DATA_READY;
        }
    }

    /// Check if the DLAB (Divisor Latch Access Bit) is set.
    fn dlab(&self) -> bool {
        (self.lcr & 0x80) != 0
    }

    /// Handle a read from a UART register.
    pub fn read(&mut self, offset: u16) -> u8 {
        match offset {
            reg::RBR if !self.dlab() => {
                // Read from receive buffer
                if let Some(byte) = self.input_buffer.pop_front() {
                    if self.input_buffer.is_empty() {
                        self.lsr &= !lsr::DATA_READY;
                    }
                    byte
                } else {
                    0
                }
            }
            reg::RBR if self.dlab() => {
                // Divisor Latch Low
                (self.divisor & 0xFF) as u8
            }
            reg::IER if !self.dlab() => self.ier,
            reg::IER if self.dlab() => {
                // Divisor Latch High
                ((self.divisor >> 8) & 0xFF) as u8
            }
            reg::IIR => self.iir,
            reg::LCR => self.lcr,
            reg::MCR => self.mcr,
            reg::LSR => self.lsr,
            reg::MSR => self.msr,
            reg::SCR => self.scr,
            _ => 0,
        }
    }

    /// Handle a write to a UART register.
    pub fn write(&mut self, offset: u16, value: u8) {
        match offset {
            reg::THR if !self.dlab() => {
                // Write to transmit buffer
                let _ = self.output.write_all(&[value]);
                let _ = self.output.flush();
            }
            reg::THR if self.dlab() => {
                // Divisor Latch Low
                self.divisor = (self.divisor & 0xFF00) | (value as u16);
            }
            reg::IER if !self.dlab() => {
                self.ier = value & 0x0F;
            }
            reg::IER if self.dlab() => {
                // Divisor Latch High
                self.divisor = (self.divisor & 0x00FF) | ((value as u16) << 8);
            }
            reg::FCR => {
                // FIFO Control Register
                if (value & 0x02) != 0 {
                    // Clear receive FIFO
                    self.input_buffer.clear();
                    self.lsr &= !lsr::DATA_READY;
                }
            }
            reg::LCR => self.lcr = value,
            reg::MCR => self.mcr = value & 0x1F,
            reg::SCR => self.scr = value,
            _ => {}
        }
    }
}

impl Default for Serial {
    fn default() -> Self {
        Self::new()
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
    fn test_serial_output() {
        let output_data = Arc::new(Mutex::new(Vec::new()));
        let writer = TestWriter {
            data: output_data.clone(),
        };

        let mut serial = Serial::with_output(Box::new(writer));

        // Write "Hi" to the serial port
        serial.write(reg::THR, b'H');
        serial.write(reg::THR, b'i');

        assert_eq!(&*output_data.lock().unwrap(), b"Hi");
    }

    #[test]
    fn test_serial_input() {
        let mut serial = Serial::new();

        // Queue some input
        serial.queue_input(b"test");

        // LSR should show data ready
        assert_ne!(serial.read(reg::LSR) & lsr::DATA_READY, 0);

        // Read the data
        assert_eq!(serial.read(reg::RBR), b't');
        assert_eq!(serial.read(reg::RBR), b'e');
        assert_eq!(serial.read(reg::RBR), b's');
        assert_eq!(serial.read(reg::RBR), b't');

        // LSR should show no data
        assert_eq!(serial.read(reg::LSR) & lsr::DATA_READY, 0);
    }
}
