//! Virtio device implementations.
//!
//! This module provides virtio-mmio device emulation.
//! Devices are exposed to the guest via memory-mapped I/O.

pub mod queue;
pub mod mmio_transport;
pub mod net;
pub mod vsock;
pub mod blk;
pub mod console;
pub mod rng;
// vmnet disabled - causes binary to link vmnet.framework which requires
// com.apple.vm.networking entitlement. Ad-hoc signed binaries get SIGKILL
// when this entitlement is present. Needs proper code signing to enable.
// pub mod vmnet;

pub use queue::{Queue, Descriptor, DescriptorChain};
pub use mmio_transport::{VirtioMmioTransport, VIRTIO_MMIO_SIZE};
pub use blk::VirtioBlk;
pub use net::{VirtioNet, NetBackend, NullBackend, LoopbackBackend};
pub use console::VirtioConsole;
pub use vsock::VirtioVsock;
pub use rng::VirtioRng;
// pub use vmnet::{VmnetBackend, VmnetMode};

/// Virtio MMIO register offsets.
pub mod mmio {
    pub const MAGIC_VALUE: u64 = 0x000;
    pub const VERSION: u64 = 0x004;
    pub const DEVICE_ID: u64 = 0x008;
    pub const VENDOR_ID: u64 = 0x00C;
    pub const DEVICE_FEATURES: u64 = 0x010;
    pub const DEVICE_FEATURES_SEL: u64 = 0x014;
    pub const DRIVER_FEATURES: u64 = 0x020;
    pub const DRIVER_FEATURES_SEL: u64 = 0x024;
    pub const QUEUE_SEL: u64 = 0x030;
    pub const QUEUE_NUM_MAX: u64 = 0x034;
    pub const QUEUE_NUM: u64 = 0x038;
    pub const QUEUE_READY: u64 = 0x044;
    pub const QUEUE_NOTIFY: u64 = 0x050;
    pub const INTERRUPT_STATUS: u64 = 0x060;
    pub const INTERRUPT_ACK: u64 = 0x064;
    pub const STATUS: u64 = 0x070;
    pub const QUEUE_DESC_LOW: u64 = 0x080;
    pub const QUEUE_DESC_HIGH: u64 = 0x084;
    pub const QUEUE_DRIVER_LOW: u64 = 0x090;
    pub const QUEUE_DRIVER_HIGH: u64 = 0x094;
    pub const QUEUE_DEVICE_LOW: u64 = 0x0A0;
    pub const QUEUE_DEVICE_HIGH: u64 = 0x0A4;
    pub const CONFIG_GENERATION: u64 = 0x0FC;
    pub const CONFIG: u64 = 0x100;
}

/// Virtio magic value ("virt" in little-endian).
pub const VIRTIO_MAGIC: u32 = 0x74726976;

/// Virtio MMIO version.
pub const VIRTIO_VERSION: u32 = 2;

/// Virtio vendor ID (we use a custom one).
pub const VIRTIO_VENDOR: u32 = 0x4D564D52; // "MVMR" - MicroVM-RS

/// Device status bits.
pub mod status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    pub const FAILED: u8 = 128;
}

/// Common virtio feature bits.
pub mod feature {
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
    pub const VIRTIO_F_RING_PACKED: u64 = 1 << 34;
}
