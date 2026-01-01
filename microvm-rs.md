# microvm-rs

> A cross-platform, embeddable microVM library for Rust

## Executive Summary

**microvm-rs** is a Rust library that enables applications to spawn lightweight, hardware-isolated virtual machines on macOS, Linux, and Windows. It provides a unified API across all platforms, abstracting away the underlying hypervisor differences.

**Status**: Planning Phase
**License**: MIT OR Apache-2.0
**Repository**: github.com/anthropics/microvm-rs (TBD)

---

## Table of Contents

1. [Why We're Building This](#why-were-building-this)
2. [How It Helps Velocitty](#how-it-helps-velocitty)
3. [Market Gap Analysis](#market-gap-analysis)
4. [Architecture Overview](#architecture-overview)
5. [Platform Backends](#platform-backends)
6. [API Design](#api-design)
7. [Guest Images](#guest-images)
8. [Development Roadmap](#development-roadmap)
9. [Technical Deep Dive](#technical-deep-dive)
10. [Risk Assessment](#risk-assessment)
11. [Success Metrics](#success-metrics)
12. [Open Questions](#open-questions)

---

## Why We're Building This

### The Problem

Modern applications increasingly need **hardware-level isolation** for security-sensitive operations:

- Running untrusted code
- Isolating network traffic (VPNs)
- Secure development environments
- Sandboxed AI agent execution
- Privacy-focused browsing

Current solutions have significant drawbacks:

| Solution | Problem |
|----------|---------|
| Docker/containers | Shared kernel, weaker isolation |
| QEMU | Heavy, complex, not embeddable |
| Firecracker | Linux-only, not embeddable |
| Lima | macOS-only, external dependency |
| Platform-specific VMs | No unified API, fragmented code |

### The Solution

**microvm-rs** provides:

- **True hardware isolation** via platform-native hypervisors
- **Single unified API** across macOS, Linux, and Windows
- **Embeddable** - ships as a library, not a separate process
- **Minimal footprint** - VMs boot in milliseconds, use minimal RAM
- **Rust-native** - safe, fast, no C dependencies in public API

---

## How It Helps Velocitty

### Current State (with Lima)

```
User Experience:
1. Download Velocitty
2. Realize Lima is required
3. Open terminal
4. Run: brew install lima
5. Wait for Lima to install
6. Return to Velocitty
7. Finally use the app

Problems:
- Extra dependency
- Platform lock-in (macOS only)
- Lima updates can break Velocitty
- Poor user experience
- Can't distribute on App Store
```

### Future State (with microvm-rs)

```
User Experience:
1. Download Velocitty
2. Run it
3. Done

Benefits:
- Zero external dependencies
- Works on macOS, Linux, Windows
- Velocitty controls the VM lifecycle
- App Store compatible
- Professional, polished experience
```

### Velocitty Use Cases

#### Today: VPN Isolation
```rust
// Spawn isolated network VM
let vm = MicroVM::builder()
    .template(VelocittyTemplates::VpnGateway)
    .memory_mb(128)
    .build()?;

// Route VPN traffic through VM
// Host machine's network stack is never touched
```

#### Future: Isolation Platform

```rust
// Isolated development environment
let dev_vm = MicroVM::builder()
    .template(VelocittyTemplates::DevEnvironment)
    .memory_mb(2048)
    .cpus(4)
    .mount("/projects", "/home/dev/projects")
    .build()?;

// Sandboxed code execution
let sandbox = MicroVM::builder()
    .template(VelocittyTemplates::Sandbox)
    .memory_mb(256)
    .network(false)  // No network access
    .build()?;

// Run untrusted AI agent
let agent_vm = MicroVM::builder()
    .template(VelocittyTemplates::AiAgent)
    .memory_mb(512)
    .timeout(Duration::from_secs(300))
    .build()?;
```

### Value Proposition

| Feature | Without microvm-rs | With microvm-rs |
|---------|-------------------|-----------------|
| Installation | Multi-step | One-click |
| Platform support | macOS only | All platforms |
| Dependencies | Lima, QEMU, etc. | None |
| VM boot time | Seconds | Milliseconds |
| App Store distribution | No | Yes |
| Control over updates | No | Yes |
| Future isolation features | Complex | Easy |

---

## Market Gap Analysis

### Existing Solutions Comparison

| Project | Rust | Cross-Platform | Embeddable | Maintained | Use Case |
|---------|------|----------------|------------|------------|----------|
| Firecracker | Yes | Linux only | No | Yes (AWS) | Serverless |
| Cloud Hypervisor | Yes | Linux only | No | Yes (Intel) | Cloud VMs |
| CrosVM | Yes | Linux mainly | No | Yes (Google) | Chrome OS |
| QEMU | No (C) | Yes | Partial | Yes | General |
| Lima | No (Go) | macOS only | No | Yes | Dev VMs |
| VirtualBox | No (C++) | Yes | No | Yes (Oracle) | Desktop VMs |
| **microvm-rs** | **Yes** | **Yes** | **Yes** | **TBD** | **Embedded VMs** |

### The Gap We Fill

```
                    Cross-Platform
                          │
                          │
         QEMU ─────────── │ ─────────── (microvm-rs)
        VirtualBox        │                  │
                          │                  │
    ──────────────────────┼──────────────────┼───────── Embeddable
                          │                  │
                          │                  │
      Firecracker ─────── │                  │
      Cloud Hypervisor    │                  │
      CrosVM              │                  │
                          │
                    Linux Only
```

**microvm-rs occupies a unique position**: embeddable + cross-platform + Rust-native.

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Application                         │
│                          (Velocitty)                             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                          microvm-rs                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                      Public API                            │  │
│  │   MicroVM::builder() -> VmBuilder -> MicroVM              │  │
│  │   vm.boot() / vm.shutdown() / vm.attach_device()          │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                │                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Device Layer                            │  │
│  │   VirtioNet | VirtioBlk | VirtioVsock | VirtioConsole     │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                │                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Backend Trait                            │  │
│  │   trait HypervisorBackend { ... }                         │  │
│  └───────────────────────────────────────────────────────────┘  │
│           │                    │                    │           │
│  ┌────────┴───────┐  ┌────────┴───────┐  ┌────────┴───────┐   │
│  │  KVM Backend   │  │  HVF Backend   │  │  WHP Backend   │   │
│  │    (Linux)     │  │    (macOS)     │  │   (Windows)    │   │
│  └────────────────┘  └────────────────┘  └────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Operating System APIs                         │
│         /dev/kvm        Hypervisor.framework        WHP          │
│          (Linux)              (macOS)             (Windows)      │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         CPU Hardware                             │
│              Intel VT-x / AMD-V / Apple Silicon                  │
└─────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility |
|-----------|---------------|
| **Public API** | User-facing interface, platform-agnostic |
| **Device Layer** | virtio device emulation (network, block, console, vsock) |
| **Backend Trait** | Abstract interface for hypervisor operations |
| **KVM Backend** | Linux-specific implementation using /dev/kvm |
| **HVF Backend** | macOS-specific using Hypervisor.framework |
| **WHP Backend** | Windows-specific using Windows Hypervisor Platform |

### Data Flow: VM Boot Sequence

```
1. User calls MicroVM::builder().kernel(path).build()
         │
         ▼
2. Builder validates config, selects platform backend
         │
         ▼
3. Backend creates VM partition/context
         │
         ▼
4. Memory regions mapped into guest physical address space
         │
         ▼
5. Kernel loaded at 0x100000 (Linux boot protocol)
         │
         ▼
6. virtio devices initialized (PCI or MMIO)
         │
         ▼
7. vCPU created and configured (registers, CPUID)
         │
         ▼
8. User calls vm.boot()
         │
         ▼
9. vCPU enters guest mode, starts executing kernel
         │
         ▼
10. VM exits handled (I/O, interrupts, etc.)
```

---

## Platform Backends

### Linux: KVM Backend

**KVM (Kernel-based Virtual Machine)** is the most mature and well-documented virtualization API.

```rust
// Simplified flow
let kvm = Kvm::new()?;                    // Open /dev/kvm
let vm = kvm.create_vm()?;                // KVM_CREATE_VM
vm.set_user_memory_region(slot, mem)?;    // KVM_SET_USER_MEMORY_REGION
let vcpu = vm.create_vcpu(0)?;            // KVM_CREATE_VCPU
vcpu.set_regs(initial_regs)?;             // KVM_SET_REGS

loop {
    match vcpu.run()? {                   // KVM_RUN
        VcpuExit::IoOut { port, data } => handle_io(port, data),
        VcpuExit::MmioWrite { addr, data } => handle_mmio(addr, data),
        VcpuExit::Hlt => break,
        // ...
    }
}
```

**Existing Crates We Can Use:**
- `kvm-ioctls` - KVM ioctl wrappers
- `kvm-bindings` - KVM struct definitions
- `vm-memory` - Guest memory management
- `linux-loader` - Linux kernel loading

**What We Build:**
- Integration layer
- virtio device emulation
- Unified API adaptation

### macOS: Hypervisor.framework Backend

**Hypervisor.framework** is Apple's virtualization API, available on both Intel and Apple Silicon Macs.

```rust
// Simplified flow (via objc/FFI)
hv_vm_create(HV_VM_DEFAULT)?;             // Create VM
hv_vm_map(guest_mem, guest_addr, size)?;  // Map memory
hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT)?;  // Create vCPU
hv_vcpu_write_register(vcpu, HV_X86_RIP, entry)?;  // Set registers

loop {
    hv_vcpu_run(vcpu)?;                   // Enter guest
    match hv_vcpu_exit_reason(vcpu) {
        HV_EXIT_REASON_IO => handle_io(),
        HV_EXIT_REASON_MMIO => handle_mmio(),
        HV_EXIT_REASON_HLT => break,
        // ...
    }
}
```

**Existing Crates:**
- `hypervisor` - Basic bindings exist but incomplete
- We'll likely need to write our own comprehensive bindings

**Architecture Support:**
- Intel Macs: x86_64 virtualization
- Apple Silicon: ARM64 virtualization (different API surface)

**What We Build:**
- Complete Hypervisor.framework Rust bindings
- Apple Silicon support
- virtio device emulation
- Unified API adaptation

### Windows: WHP Backend

**Windows Hypervisor Platform (WHP)** is Microsoft's API for third-party hypervisors.

```rust
// Simplified flow (via windows-rs)
WHvCreatePartition(&partition)?;
WHvSetPartitionProperty(partition, ...)?;
WHvSetupPartition(partition)?;
WHvMapGpaRange(partition, mem, guest_addr, size, ...)?;
WHvCreateVirtualProcessor(partition, 0, 0)?;

loop {
    WHvRunVirtualProcessor(partition, 0, &exit_context, ...)?;
    match exit_context.ExitReason {
        WHvRunVpExitReasonX64IoPortAccess => handle_io(),
        WHvRunVpExitReasonMemoryAccess => handle_mmio(),
        WHvRunVpExitReasonX64Halt => break,
        // ...
    }
}
```

**Existing Crates:**
- `windows-rs` - Windows API bindings (WHP included)
- Very few examples of WHP usage in Rust

**Requirements:**
- Windows 10 version 1803+
- Hyper-V enabled
- Virtualization enabled in BIOS

**What We Build:**
- WHP wrapper with ergonomic Rust API
- virtio device emulation
- Unified API adaptation

---

## API Design

### Core Types

```rust
/// Main VM handle
pub struct MicroVM {
    // Platform-specific backend
    backend: Box<dyn HypervisorBackend>,
    // Attached devices
    devices: Vec<Box<dyn VirtioDevice>>,
    // VM state
    state: VmState,
}

/// VM configuration builder
pub struct VmBuilder {
    kernel: Option<PathBuf>,
    rootfs: Option<PathBuf>,
    initrd: Option<PathBuf>,
    cmdline: String,
    memory_mb: u32,
    vcpus: u32,
    // ...
}

/// VM lifecycle states
pub enum VmState {
    Created,
    Booting,
    Running,
    Paused,
    Shutdown,
    Failed(String),
}
```

### Builder Pattern API

```rust
use microvm::{MicroVM, VirtioNet, VirtioVsock, VirtioBlk};

// Minimal VM
let vm = MicroVM::builder()
    .kernel("/path/to/vmlinuz")
    .memory_mb(128)
    .build()?;

// Full-featured VM
let vm = MicroVM::builder()
    // Kernel configuration
    .kernel("/path/to/vmlinuz")
    .initrd("/path/to/initrd.img")      // Optional
    .rootfs("/path/to/rootfs.ext4")     // Optional
    .cmdline("console=ttyS0 quiet")

    // Resources
    .memory_mb(512)
    .vcpus(2)

    // Devices attached during build
    .device(VirtioNet::new())
    .device(VirtioVsock::new(5000))
    .device(VirtioBlk::from_file("/path/to/disk.img")?)

    .build()?;
```

### VM Lifecycle API

```rust
// Boot the VM (async)
vm.boot().await?;

// Check state
assert_eq!(vm.state(), VmState::Running);

// Pause/resume
vm.pause().await?;
vm.resume().await?;

// Graceful shutdown (sends ACPI power button)
vm.shutdown().await?;

// Force kill
vm.kill()?;

// Wait for exit
let exit_code = vm.wait().await?;
```

### Device API

```rust
// Network device
let net = VirtioNet::builder()
    .mac_address([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    .tap_name("vmtap0")      // Linux
    .build()?;

let net_handle = vm.attach(net)?;

// Send/receive packets
net_handle.send_packet(&ethernet_frame).await?;
let packet = net_handle.recv_packet().await?;

// Vsock (host <-> guest sockets)
let vsock = VirtioVsock::new(5000);  // CID = 5000
let vsock_handle = vm.attach(vsock)?;

// Connect to guest service
let stream = vsock_handle.connect(8080).await?;  // Guest port 8080
stream.write_all(b"hello").await?;

// Block device
let disk = VirtioBlk::builder()
    .file("/path/to/disk.img")
    .readonly(true)
    .build()?;

vm.attach(disk)?;
```

### Console API

```rust
// Serial console I/O
let console = vm.console();

// Write to guest
console.write(b"echo hello\n").await?;

// Read from guest
let mut buf = [0u8; 1024];
let n = console.read(&mut buf).await?;
```

### Error Handling

```rust
use microvm::{Error, Result};

pub enum Error {
    // Platform errors
    HypervisorNotAvailable,
    HypervisorError(String),

    // Configuration errors
    InvalidKernel(PathBuf),
    InvalidMemorySize(u32),

    // Runtime errors
    VmNotRunning,
    DeviceError(String),
    IoError(std::io::Error),

    // Platform-specific
    #[cfg(target_os = "linux")]
    KvmError(kvm_ioctls::Error),

    #[cfg(target_os = "macos")]
    HvfError(i32),

    #[cfg(target_os = "windows")]
    WhpError(windows::core::Error),
}
```

### Feature Flags

```toml
[features]
default = ["virtio-net", "virtio-vsock"]

# Devices
virtio-net = []
virtio-blk = []
virtio-vsock = []
virtio-console = []
virtio-fs = []      # Shared filesystem

# Backends (auto-detected by default)
kvm = []            # Linux
hvf = []            # macOS
whp = []            # Windows

# Optional features
serde = ["dep:serde"]  # Serialization for configs
tracing = ["dep:tracing"]  # Logging/tracing support
```

---

## Guest Images

### What We Need to Ship

For Velocitty, we bundle minimal guest images:

```
velocitty.app/
└── Resources/
    └── vm/
        ├── vmlinuz           # Linux kernel (~8 MB)
        ├── rootfs.squashfs   # Root filesystem (~20-50 MB)
        └── config.json       # VM configuration
```

### Minimal Linux Kernel

Custom kernel config optimized for microVMs:

```
# Required
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS=y
CONFIG_NET=y
CONFIG_INET=y
CONFIG_TUN=y             # For VPN

# Disabled (reduce size)
CONFIG_MODULES=n         # No module loading
CONFIG_SOUND=n
CONFIG_USB=n
CONFIG_WIRELESS=n
CONFIG_BLUETOOTH=n
CONFIG_GPU=n
# ... many more
```

**Expected kernel size:** ~5-8 MB

### Minimal Root Filesystem

Using Alpine Linux or custom buildroot:

```
/
├── bin/
│   └── busybox          # All basic utilities
├── sbin/
│   ├── init             # Simple init script
│   └── openvpn          # VPN client
├── lib/
│   └── ld-musl-*.so     # musl libc (smaller than glibc)
├── etc/
│   ├── resolv.conf
│   └── passwd           # Minimal
└── velocitty/
    └── daemon           # Our daemon (Rust, statically linked)
```

**Expected rootfs size:** ~20-30 MB (compressed squashfs)

### Even Smaller: Rust-Only Guest

If we rewrite the daemon in Rust with static linking:

```
/
├── init                 # Rust binary, statically linked
└── (that's it)
```

Using `#![no_std]` + custom init:
- Total guest size: ~5-10 MB
- Boot time: <100ms

### Image Builder Tool

Ship a tool to build/customize images:

```bash
# Build default Velocitty guest image
microvm-build --template velocitty-vpn --output guest.img

# Custom image
microvm-build \
  --base alpine:3.19 \
  --install openvpn,wireguard \
  --add-file daemon:/usr/bin/daemon \
  --output custom.img
```

---

## Development Roadmap

### Phase 0: Project Setup

**Objective:** Establish project foundation

- [ ] Create GitHub repository
- [ ] Set up CI/CD (GitHub Actions)
  - Linux: Ubuntu runners
  - macOS: macOS runners
  - Windows: Windows runners
- [ ] Project structure
- [ ] Basic documentation
- [ ] License (MIT OR Apache-2.0)
- [ ] Contributing guidelines

**Deliverable:** Empty project that builds on all platforms

### Phase 1: Linux MVP

**Objective:** Working VM on Linux using KVM

#### Step 1: Core Infrastructure
- [ ] Backend trait definition
- [ ] Memory management abstraction
- [ ] KVM backend scaffolding
- [ ] Basic VM creation

#### Step 2: Boot Linux
- [ ] Linux kernel loader (bzImage)
- [ ] Boot protocol implementation
- [ ] Serial console output
- [ ] Successfully boot to kernel panic (no rootfs yet)

#### Step 3: Devices & Rootfs
- [ ] virtio-blk implementation
- [ ] Mount rootfs, boot to shell
- [ ] virtio-console for I/O
- [ ] First end-to-end test

**Deliverable:** Boot minimal Linux on Linux host

### Phase 2: Linux Networking

**Objective:** Full networking stack

#### Step 1: virtio-net
- [ ] virtio-net device implementation
- [ ] TAP device integration
- [ ] Guest can ping host

#### Step 2: virtio-vsock
- [ ] virtio-vsock implementation
- [ ] Host-guest socket communication
- [ ] Benchmark vsock vs TCP

**Deliverable:** Velocitty VPN daemon works in VM (Linux host)

### Phase 3: macOS Backend

**Objective:** Port to macOS using Hypervisor.framework

#### Step 1: HVF Bindings
- [ ] Hypervisor.framework Rust bindings
- [ ] Intel Mac support
- [ ] Basic VM creation

#### Step 2: Apple Silicon
- [ ] ARM64 virtualization support
- [ ] Different register handling
- [ ] Universal binary

#### Step 3: Device Porting
- [ ] Port virtio devices to macOS
- [ ] Networking on macOS (vmnet.framework)
- [ ] Full test suite passing

**Deliverable:** Velocitty VPN daemon works in VM (macOS host)

### Phase 4: Windows Backend

**Objective:** Port to Windows using WHP

#### Step 1: WHP Bindings
- [ ] WHP API wrappers
- [ ] Basic VM creation
- [ ] Boot Linux kernel

#### Step 2: Device Porting
- [ ] virtio devices on Windows
- [ ] Networking (needs research)
- [ ] vsock support

#### Step 3: Testing & Polish
- [ ] Full test suite
- [ ] Performance optimization
- [ ] Documentation

**Deliverable:** Velocitty VPN daemon works in VM (Windows host)

### Phase 5: Production Readiness

**Objective:** Ready for Velocitty integration

- [ ] API stabilization
- [ ] Performance benchmarks
- [ ] Security audit
- [ ] Documentation complete
- [ ] Examples and tutorials
- [ ] Publish to crates.io
- [ ] Integrate into Velocitty

**Deliverable:** microvm-rs v0.1.0 released

---

## Technical Deep Dive

### Memory Layout

Standard x86_64 guest physical memory layout:

```
0x0000_0000 - 0x0000_0FFF : Reserved (real mode IVT, BDA)
0x0000_1000 - 0x0000_9FFF : Usable (boot params, cmdline)
0x000A_0000 - 0x000F_FFFF : Reserved (VGA, ROM)
0x0010_0000 - 0x????_???? : Kernel loaded here (1 MB mark)
     ...
0x????_???? - END         : Usable RAM

High memory (above 4GB if configured):
0x1_0000_0000+            : Additional RAM
```

### virtio Device Model

We use virtio-mmio for simplicity (no PCI emulation needed):

```
MMIO Region (per device):
Offset  Size  Description
0x000   4     Magic value (0x74726976)
0x004   4     Version (2)
0x008   4     Device ID
0x00C   4     Vendor ID
0x010   4     Device features
0x014   4     Device features select
0x020   4     Driver features
0x024   4     Driver features select
0x030   4     Queue select
0x034   4     Queue num max
0x038   4     Queue num
0x044   4     Queue ready
0x050   4     Queue notify
0x060   4     Interrupt status
0x064   4     Interrupt ACK
0x070   4     Status
0x080   4     Queue desc low
0x084   4     Queue desc high
0x090   4     Queue driver low
0x094   4     Queue driver high
0x0A0   4     Queue device low
0x0A4   4     Queue device high
0x100+  ...   Device-specific config
```

### vCPU Exit Handling

The vCPU run loop handles these exit types:

```rust
enum VcpuExit {
    // I/O port access (x86 IN/OUT instructions)
    IoIn { port: u16, size: u8 },
    IoOut { port: u16, data: &[u8] },

    // Memory-mapped I/O
    MmioRead { addr: u64, size: u8 },
    MmioWrite { addr: u64, data: &[u8] },

    // Interrupts
    IrqWindowOpen,

    // CPU state changes
    Hlt,                    // Guest halted
    Shutdown,               // Triple fault or shutdown

    // Errors
    FailEntry { reason: u64 },
    InternalError,

    // Platform-specific
    Unknown(u32),
}
```

### Interrupt Handling

Using MSI-X for virtio devices (cleaner than legacy IRQs):

```
Guest                     Host
  │                         │
  │  ←── virtio-net IRQ ────│  (packet arrived)
  │                         │
  ├─→ Read interrupt status │
  │                         │
  ├─→ Process virtqueue     │
  │                         │
  ├─→ ACK interrupt ───────→│
  │                         │
```

---

## Risk Assessment

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Windows WHP poorly documented | High | Medium | Research thoroughly, prototype early |
| Apple Silicon edge cases | Medium | High | Get dedicated Apple Silicon test hardware |
| virtio device bugs | Medium | High | Extensive testing, compare with QEMU behavior |
| Performance issues | Low | Medium | Profile early, optimize hot paths |
| Security vulnerabilities | Low | Critical | Security audit before v1.0 |

### Platform-Specific Risks

**Linux:**
- Lowest risk, best documented
- KVM is battle-tested

**macOS:**
- Hypervisor.framework less documented
- Apple Silicon is newer, fewer examples
- Need to handle Apple's entitlements/signing

**Windows:**
- Highest risk, least documentation
- WHP requires specific Windows versions
- Fewer Rust examples to reference

### Resource Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Underestimated complexity | Medium | High | MVP first, iterate |
| Scope creep | Medium | Medium | Strict feature prioritization |
| Maintainer burnout | Low | High | Document everything, seek contributors early |

---

## Success Metrics

### Phase 1 (Linux MVP)
- [ ] Boot Linux kernel in <500ms
- [ ] Memory usage <50MB for minimal VM
- [ ] Serial console I/O works
- [ ] All unit tests pass

### Phase 2 (Networking)
- [ ] Guest can reach internet through host
- [ ] vsock latency <1ms
- [ ] Network throughput >500 Mbps

### Phase 3 (macOS)
- [ ] Works on Intel Macs
- [ ] Works on Apple Silicon Macs
- [ ] Same API as Linux, no #[cfg] in user code

### Phase 4 (Windows)
- [ ] Works on Windows 10/11
- [ ] Same API as Linux/macOS
- [ ] <10% performance difference from Linux

### Final Release
- [ ] <5 second Velocitty startup (including VM boot)
- [ ] Zero external dependencies
- [ ] All platforms reach feature parity
- [ ] Documentation complete
- [ ] At least 10 GitHub stars from non-team-members (external validation)

---

## Open Questions

### Technical

1. **virtio transport: MMIO vs PCI?**
   - MMIO is simpler (no PCI enumeration)
   - PCI is more standard, better driver support
   - **Leaning:** Start with MMIO, add PCI later if needed

2. **ARM64 support?**
   - Apple Silicon requires it
   - Linux ARM64 VMs would be nice
   - Windows ARM64 is rare
   - **Decision:** macOS ARM64 required, others are nice-to-have

3. **GPU passthrough?**
   - Not for v1.0
   - Future consideration for dev environments
   - **Decision:** Out of scope for now

4. **Snapshot/restore?**
   - Useful for instant resume
   - Significant complexity
   - **Decision:** v2.0 feature

### Business/Community

1. **Separate repo or monorepo with Velocitty?**
   - Separate enables community contributions
   - Monorepo simplifies development
   - **Leaning:** Separate repo, but closely coordinated

2. **Governance model?**
   - Who can merge PRs?
   - How to handle breaking changes?
   - **Decision:** TBD, start simple

3. **Crates.io publishing cadence?**
   - Follow semver strictly
   - Pre-1.0 breaking changes allowed
   - **Decision:** Publish 0.x until stable, then 1.0

---

## References

### Documentation
- [KVM API Documentation](https://www.kernel.org/doc/html/latest/virt/kvm/api.html)
- [Hypervisor.framework Reference](https://developer.apple.com/documentation/hypervisor)
- [Windows Hypervisor Platform](https://docs.microsoft.com/en-us/virtualization/api/)
- [virtio Specification](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html)
- [Linux Boot Protocol](https://www.kernel.org/doc/html/latest/x86/boot.html)

### Existing Projects (Reference Only)
- [Firecracker](https://github.com/firecracker-microvm/firecracker) - AWS microVM
- [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) - Intel microVM
- [rust-vmm](https://github.com/rust-vmm) - Rust VMM building blocks
- [CrosVM](https://chromium.googlesource.com/crosvm/crosvm/) - Chrome OS VMM

### Learning Resources
- [Writing a KVM hypervisor in Rust](https://www.codeproject.com/Articles/5306251/Writing-a-KVM-hypervisor-in-Rust)
- [LWN.net KVM Articles](https://lwn.net/Kernel/Index/#Virtualization-KVM)
- [virtio specification walkthrough](https://blogs.oracle.com/linux/post/introduction-to-virtio)

---

## Appendix A: Code Snippets

### Minimal KVM Example (Linux)

```rust
use kvm_ioctls::{Kvm, VcpuExit};
use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_LOG_DIRTY_PAGES};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open KVM
    let kvm = Kvm::new()?;

    // Create VM
    let vm = kvm.create_vm()?;

    // Allocate guest memory (1 MB)
    let mem_size = 0x100000;
    let guest_mem = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
            -1,
            0,
        )
    };

    // Map memory into guest
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: mem_size as u64,
        userspace_addr: guest_mem as u64,
        flags: 0,
    };
    unsafe { vm.set_user_memory_region(mem_region)? };

    // Load code at address 0
    let code = [
        0xba, 0xf8, 0x03,  // mov dx, 0x3f8 (serial port)
        0xb0, 0x48,        // mov al, 'H'
        0xee,              // out dx, al
        0xb0, 0x69,        // mov al, 'i'
        0xee,              // out dx, al
        0xf4,              // hlt
    ];
    unsafe {
        std::ptr::copy_nonoverlapping(
            code.as_ptr(),
            guest_mem as *mut u8,
            code.len(),
        );
    }

    // Create vCPU
    let vcpu = vm.create_vcpu(0)?;

    // Set up registers
    let mut sregs = vcpu.get_sregs()?;
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu.set_sregs(&sregs)?;

    let mut regs = vcpu.get_regs()?;
    regs.rip = 0;  // Start at address 0
    regs.rflags = 2;
    vcpu.set_regs(&regs)?;

    // Run!
    loop {
        match vcpu.run()? {
            VcpuExit::IoOut { port, data } => {
                if port == 0x3f8 {
                    print!("{}", data[0] as char);
                }
            }
            VcpuExit::Hlt => {
                println!("\nGuest halted");
                break;
            }
            exit => {
                println!("Unexpected exit: {:?}", exit);
                break;
            }
        }
    }

    Ok(())
}
```

### Minimal HVF Example (macOS)

```rust
// Note: This is pseudocode - actual implementation needs objc bindings

#[cfg(target_os = "macos")]
mod hvf {
    use std::ffi::c_void;

    #[link(name = "Hypervisor", kind = "framework")]
    extern "C" {
        fn hv_vm_create(flags: u64) -> i32;
        fn hv_vm_destroy() -> i32;
        fn hv_vm_map(uva: *mut c_void, gpa: u64, size: u64, flags: u64) -> i32;
        fn hv_vcpu_create(vcpu: *mut u64, flags: u64) -> i32;
        fn hv_vcpu_run(vcpu: u64) -> i32;
        fn hv_vcpu_read_register(vcpu: u64, reg: u32, value: *mut u64) -> i32;
        fn hv_vcpu_write_register(vcpu: u64, reg: u32, value: u64) -> i32;
    }

    pub fn example() -> Result<(), i32> {
        unsafe {
            // Create VM
            let ret = hv_vm_create(0);
            if ret != 0 { return Err(ret); }

            // Create vCPU
            let mut vcpu: u64 = 0;
            let ret = hv_vcpu_create(&mut vcpu, 0);
            if ret != 0 { return Err(ret); }

            // ... setup memory, registers, run loop ...

            Ok(())
        }
    }
}
```

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **KVM** | Kernel-based Virtual Machine, Linux's built-in hypervisor |
| **HVF** | Hypervisor.framework, macOS's virtualization API |
| **WHP** | Windows Hypervisor Platform, Windows' third-party hypervisor API |
| **virtio** | Standard for virtual I/O devices in VMs |
| **vCPU** | Virtual CPU, a virtualized processor core |
| **GPA** | Guest Physical Address, address as seen by the VM |
| **HVA** | Host Virtual Address, address in the host process |
| **MMIO** | Memory-Mapped I/O, accessing devices through memory addresses |
| **vsock** | Virtual socket, high-performance host-guest communication |
| **VMM** | Virtual Machine Monitor, the software managing VMs |
| **microVM** | Lightweight VM optimized for fast boot and minimal resources |

---

## Document History

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| 2024-12-31 | 0.1 | Velocitty Team | Initial draft |

---

*This document is a living specification. Updates will be made as the project evolves.*
