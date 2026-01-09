//! VirtIO MMIO transport layer.
//!
//! This implements the virtio-mmio transport as described in the virtio spec 4.2.

use super::{mmio, status, Queue, VIRTIO_MAGIC, VIRTIO_VENDOR, VIRTIO_VERSION};
use crate::device::VirtioDevice;

/// Size of the MMIO region for a virtio device.
pub const VIRTIO_MMIO_SIZE: u64 = 0x200;

/// VirtIO MMIO transport state.
pub struct VirtioMmioTransport<D: VirtioDevice> {
    /// The underlying virtio device.
    device: D,
    /// Device status.
    status: u8,
    /// Selected feature page (0 or 1).
    device_features_sel: u32,
    /// Selected feature page for driver (0 or 1).
    driver_features_sel: u32,
    /// Acknowledged driver features (low 32 bits).
    driver_features_lo: u32,
    /// Acknowledged driver features (high 32 bits).
    driver_features_hi: u32,
    /// Selected queue index.
    queue_sel: u32,
    /// Queue configurations.
    queues: Vec<Queue>,
    /// Interrupt status.
    interrupt_status: u32,
    /// Base address of this device.
    base_addr: u64,
}

impl<D: VirtioDevice> VirtioMmioTransport<D> {
    /// Create a new MMIO transport for a virtio device.
    pub fn new(device: D, base_addr: u64) -> Self {
        Self {
            device,
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features_lo: 0,
            driver_features_hi: 0,
            queue_sel: 0,
            queues: vec![Queue::default()], // At least one queue
            interrupt_status: 0,
            base_addr,
        }
    }

    /// Get the base address.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Check if an address falls within this device's MMIO region.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base_addr && addr < self.base_addr + VIRTIO_MMIO_SIZE
    }

    /// Get a reference to the underlying device.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Get a mutable reference to the underlying device.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Get a reference to a queue by index.
    pub fn queue(&self, index: usize) -> Option<&Queue> {
        self.queues.get(index)
    }

    /// Get all queues (for syncing to device).
    pub fn queues(&self) -> &[Queue] {
        &self.queues
    }

    /// Check if a specific queue is ready.
    pub fn is_queue_ready(&self, index: usize) -> bool {
        self.queues.get(index).map(|q| q.ready).unwrap_or(false)
    }

    /// Check if device is in DRIVER_OK state.
    pub fn is_driver_ok(&self) -> bool {
        self.status & status::DRIVER_OK != 0
    }

    /// Get the currently selected queue index.
    pub fn queue_sel(&self) -> u32 {
        self.queue_sel
    }

    /// Get the current queue.
    fn current_queue(&self) -> Option<&Queue> {
        self.queues.get(self.queue_sel as usize)
    }

    /// Get the current queue mutably.
    fn current_queue_mut(&mut self) -> Option<&mut Queue> {
        self.queues.get_mut(self.queue_sel as usize)
    }

    /// Read from an MMIO register.
    pub fn read(&self, addr: u64) -> u32 {
        let offset = addr - self.base_addr;

        match offset {
            mmio::MAGIC_VALUE => VIRTIO_MAGIC,
            mmio::VERSION => VIRTIO_VERSION,
            mmio::DEVICE_ID => self.device.device_type(),
            mmio::VENDOR_ID => VIRTIO_VENDOR,
            mmio::DEVICE_FEATURES => {
                let features = self.device.features();
                if self.device_features_sel == 0 {
                    features as u32
                } else {
                    (features >> 32) as u32
                }
            }
            mmio::QUEUE_NUM_MAX => {
                // Return max_size, not the configured size
                self.current_queue()
                    .map(|q| q.max_size as u32)
                    .unwrap_or(0)
            }
            mmio::QUEUE_READY => {
                self.current_queue()
                    .map(|q| if q.ready { 1 } else { 0 })
                    .unwrap_or(0)
            }
            mmio::INTERRUPT_STATUS => self.interrupt_status,
            mmio::STATUS => self.status as u32,
            mmio::CONFIG_GENERATION => 0, // We don't track config changes
            offset if offset >= mmio::CONFIG => {
                // Config space read
                let config_offset = offset - mmio::CONFIG;
                let mut data = [0u8; 4];
                self.device.read_config(config_offset, &mut data);
                u32::from_le_bytes(data)
            }
            _ => 0,
        }
    }

    /// Write to an MMIO register.
    pub fn write(&mut self, addr: u64, value: u32) {
        let offset = addr - self.base_addr;

        match offset {
            mmio::DEVICE_FEATURES_SEL => {
                self.device_features_sel = value;
            }
            mmio::DRIVER_FEATURES => {
                if self.driver_features_sel == 0 {
                    eprintln!("[VIRTIO] DRIVER_FEATURES_LO set to 0x{:08x} (sel={})", value, self.driver_features_sel);
                    self.driver_features_lo = value;
                } else {
                    eprintln!("[VIRTIO] DRIVER_FEATURES_HI set to 0x{:08x} (sel={})", value, self.driver_features_sel);
                    self.driver_features_hi = value;
                }
            }
            mmio::DRIVER_FEATURES_SEL => {
                self.driver_features_sel = value;
            }
            mmio::QUEUE_SEL => {
                self.queue_sel = value;
                // Extend queues vector if needed
                while self.queues.len() <= value as usize {
                    self.queues.push(Queue::default());
                }
            }
            mmio::QUEUE_NUM => {
                let qsel = self.queue_sel;
                if let Some(queue) = self.current_queue_mut() {
                    eprintln!("[VIRTIO] Queue {} QUEUE_NUM set to {} (max={})",
                              qsel, value, queue.max_size);
                    queue.size = value as u16;
                }
            }
            mmio::QUEUE_READY => {
                let qsel = self.queue_sel;
                if let Some(queue) = self.current_queue_mut() {
                    queue.ready = value != 0;
                    if queue.ready {
                        eprintln!("[VIRTIO] Queue {} ready: desc=0x{:x} avail=0x{:x} used=0x{:x} size={}",
                                  qsel, queue.desc_table, queue.avail_ring,
                                  queue.used_ring, queue.size);
                    }
                }
            }
            mmio::QUEUE_NOTIFY => {
                // Queue notification - device should process the queue
                // This is handled externally
            }
            mmio::INTERRUPT_ACK => {
                self.interrupt_status &= !value;
            }
            mmio::STATUS => {
                // STATUS is 8-bit, mask to prevent garbage values
                let new_status = (value & 0xFF) as u8;
                let old_status = self.status;
                eprintln!("[VIRTIO] STATUS change: 0x{:02x} -> 0x{:02x} (raw value: 0x{:08x})",
                          old_status, new_status, value);

                if new_status == 0 {
                    // Reset
                    eprintln!("[VIRTIO] Device reset");
                    self.device.reset();
                    for queue in &mut self.queues {
                        queue.reset();
                    }
                    self.interrupt_status = 0;
                }
                // Check if FEATURES_OK is being set (transition check)
                if new_status & status::FEATURES_OK != 0 && old_status & status::FEATURES_OK == 0 {
                    // Ack features on transition to FEATURES_OK
                    let features = (self.driver_features_hi as u64) << 32
                        | self.driver_features_lo as u64;
                    eprintln!("[VIRTIO] FEATURES_OK set, acked features: 0x{:016x}", features);
                    self.device.ack_features(features);
                }
                // Check if DRIVER_OK is being set (transition check)
                if new_status & status::DRIVER_OK != 0 && old_status & status::DRIVER_OK == 0 {
                    // Activate device on transition to DRIVER_OK
                    eprintln!("[VIRTIO] DRIVER_OK set, activating device (type={})", self.device.device_type());
                    let _ = self.device.activate();
                }

                self.status = new_status;
            }
            mmio::QUEUE_DESC_LOW => {
                if let Some(queue) = self.current_queue_mut() {
                    queue.desc_table = (queue.desc_table & 0xFFFF_FFFF_0000_0000)
                        | value as u64;
                }
            }
            mmio::QUEUE_DESC_HIGH => {
                if let Some(queue) = self.current_queue_mut() {
                    queue.desc_table = (queue.desc_table & 0x0000_0000_FFFF_FFFF)
                        | ((value as u64) << 32);
                }
            }
            mmio::QUEUE_DRIVER_LOW => {
                if let Some(queue) = self.current_queue_mut() {
                    queue.avail_ring = (queue.avail_ring & 0xFFFF_FFFF_0000_0000)
                        | value as u64;
                }
            }
            mmio::QUEUE_DRIVER_HIGH => {
                if let Some(queue) = self.current_queue_mut() {
                    queue.avail_ring = (queue.avail_ring & 0x0000_0000_FFFF_FFFF)
                        | ((value as u64) << 32);
                }
            }
            mmio::QUEUE_DEVICE_LOW => {
                if let Some(queue) = self.current_queue_mut() {
                    queue.used_ring = (queue.used_ring & 0xFFFF_FFFF_0000_0000)
                        | value as u64;
                }
            }
            mmio::QUEUE_DEVICE_HIGH => {
                if let Some(queue) = self.current_queue_mut() {
                    queue.used_ring = (queue.used_ring & 0x0000_0000_FFFF_FFFF)
                        | ((value as u64) << 32);
                }
            }
            offset if offset >= mmio::CONFIG => {
                // Config space write
                let config_offset = offset - mmio::CONFIG;
                let data = value.to_le_bytes();
                self.device.write_config(config_offset, &data);
            }
            _ => {}
        }
    }

    /// Signal an interrupt to the guest.
    pub fn signal_interrupt(&mut self) {
        self.interrupt_status |= 1;
    }

    /// Check if there's a pending interrupt.
    pub fn has_pending_interrupt(&self) -> bool {
        self.interrupt_status != 0
    }
}
