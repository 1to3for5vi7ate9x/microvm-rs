# CLAUDE.md - Project Context for AI Assistants

## Project Overview

**microvm-rs** is a cross-platform, embeddable microVM library for Rust. It enables applications to spawn lightweight, hardware-isolated virtual machines using platform-native hypervisors.

### Why This Exists

This library is being built primarily to replace Lima in [Velocitty](~/Documents/velocitty), an AI-powered SSH terminal application. Currently, Velocitty uses Lima (macOS-only) to run an isolated Linux VM for VPN networking. This creates friction:

- External dependency (`brew install lima`)
- macOS-only (blocks Windows/Linux users)
- Slow VM boot times (QEMU overhead)
- Complex port forwarding for host-guest communication
- Can't distribute on App Store

microvm-rs solves these by providing a library that embeds directly into the application.

---

## End Goals

### Primary Goal
Replace Lima in Velocitty with an embedded, cross-platform microVM solution.

### Success Criteria
1. **Zero external dependencies** — Ships as a Rust library, no brew/apt/choco installs
2. **Cross-platform** — Works on macOS (Intel + Apple Silicon), Windows 10/11, Linux
3. **Fast boot** — VM starts in <500ms (Lima takes 10-30 seconds)
4. **SOCKS5 proxy support** — Guest runs SOCKS5 proxy for VPN traffic routing
5. **vsock communication** — Direct host-guest channel, no port forwarding hacks
6. **Minimal footprint** — <50MB memory for minimal VM

### Velocitty Integration

Current Velocitty flow:
```
SSH Client → localhost:1080 (SOCKS5) → Lima VM → OpenVPN → Target
                    ↑
            Lima port forwarding (slow, fragile)
```

Target flow with microvm-rs:
```
SSH Client → vsock (SOCKS5) → microvm → OpenVPN → Target
                    ↑
            Direct vsock channel (fast, reliable)
```

---

## Current Status

**Phase:** Initial Development
**Platform Focus:** macOS (Hypervisor.framework) first, then Windows (WHP)

### Development Order
1. **macOS (HVF)** — Primary development platform (current)
2. **Windows (WHP)** — Secondary platform (will clone repo to Windows machine)
3. **Linux (KVM)** — Future, if needed (best documented, can add later)

### What's Done
- [x] Project specification (`microvm-rs.md`)
- [x] CLAUDE.md context file
- [x] Initial project structure
- [x] HVF Rust bindings (Hypervisor.framework) - ARM64 + x86_64
- [x] Basic VM creation on macOS
- [x] Memory mapping (guest physical address space)
- [x] vCPU creation and run loop
- [x] **MILESTONE: Code execution working!** (ARM64 "Hi!" test passes)
- [x] MMIO exit handling (for UART output)
- [x] WFI instruction handling (guest halt)
- [x] PL011 UART device for ARM64
- [x] 8250 Serial device for x86_64
- [x] virtio-net device with backend traits (Null, Loopback)
- [x] virtio-vsock device with connection management
- [x] Linux kernel loader module (ARM64 Image + x86_64 bzImage)
- [x] Device tree builder for ARM64 boot
- [x] E820 memory map and GDT for x86_64 boot
- [x] WHP backend for Windows (basic VM creation, memory, vCPU)
- [x] **MILESTONE: hello_vm test working on Windows WHP!**
- [x] WHP 64-bit long mode CPU setup
- [x] WHP I/O port emulation (serial, PIT, PCI config)
- [x] WHP CPUID emulation
- [x] WHP APIC emulation configuration

### Known Limitations

#### Windows WHP MSR Handling Bug
WHP has a significant limitation where MSR exits don't properly report the MSR number being accessed. The `MsrNumber` field in the exit context and the `ECX` register (which should contain the MSR number per x86 spec) both show 0 instead of the actual MSR number.

**Investigation performed:**
- Tried reading ECX register directly during MSR exits - WHP clears it to 0
- Tried instruction decoding (looking for `mov ecx, imm32` patterns before RDMSR/WRMSR) - kernel uses indirect MSR access via paravirt
- Tried reading MSR number from memory via RDX register (for `mov ecx, [rdx]` patterns) - the memory locations are uninitialized (contain 0)
- QEMU's WHPX backend has the same issue and just returns 0 for all RDMSR and ignores all WRMSR

**Impact:** Standard Linux kernels cannot boot because they rely on MSRs for:
- CPU feature detection
- APIC configuration
- Timer calibration (TSC, kvmclock)
- Paravirt operations

**Workaround options:**
1. Use a custom-built minimal kernel that avoids paravirt MSR patterns
2. Use the KVM backend on Linux or HVF on macOS (both have proper MSR support)
3. Wait for Microsoft to fix the WHP MSR handling
4. Build kernel with `CONFIG_PARAVIRT=n` and minimal MSR usage

### What's Next
- [ ] Boot real Linux kernel on macOS (HVF) - primary path forward
- [ ] Port KVM backend for Linux
- [ ] TAP backend for virtio-net
- [ ] User-mode NAT/SOCKS backend
- [ ] Investigate WHP MSR workarounds or wait for API improvements

---

## Architecture

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
│  │  HVF Backend   │  │  WHP Backend   │  │  KVM Backend   │   │
│  │    (macOS)     │  │   (Windows)    │  │    (Linux)     │   │
│  └────────────────┘  └────────────────┘  └────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
microvm-rs/
├── CLAUDE.md              # This file - AI context
├── microvm-rs.md          # Full project specification
├── Cargo.toml             # Workspace manifest
├── src/
│   ├── lib.rs             # Public API exports
│   ├── builder.rs         # VmBuilder implementation
│   ├── vm.rs              # MicroVM struct and lifecycle
│   ├── error.rs           # Error types
│   ├── backend/
│   │   ├── mod.rs         # Backend trait definition
│   │   ├── hvf/           # macOS Hypervisor.framework
│   │   │   ├── mod.rs
│   │   │   ├── bindings.rs    # Raw FFI bindings
│   │   │   ├── vm.rs          # VM implementation
│   │   │   ├── vcpu.rs        # vCPU implementation
│   │   │   └── memory.rs      # Memory mapping
│   │   ├── whp/           # Windows Hypervisor Platform
│   │   │   ├── mod.rs
│   │   │   ├── bindings.rs
│   │   │   ├── vm.rs
│   │   │   ├── vcpu.rs
│   │   │   └── memory.rs
│   │   └── kvm/           # Linux KVM (future)
│   │       └── mod.rs
│   ├── device/
│   │   ├── mod.rs         # Device traits
│   │   ├── pl011.rs       # ARM64 PL011 UART
│   │   ├── serial.rs      # x86 8250 UART
│   │   └── virtio/
│   │       ├── mod.rs
│   │       ├── net.rs     # virtio-net
│   │       ├── blk.rs     # virtio-blk
│   │       ├── vsock.rs   # virtio-vsock
│   │       └── console.rs # virtio-console
│   ├── loader/
│   │   ├── mod.rs         # Kernel loader exports
│   │   ├── linux.rs       # Linux kernel loader
│   │   ├── arm64.rs       # ARM64 boot setup, DTB builder
│   │   └── x86_64.rs      # x86_64 boot setup, E820, GDT
│   └── memory/
│       ├── mod.rs
│       └── guest.rs       # Guest memory abstraction
├── examples/
│   ├── minimal.rs         # Minimal VM example
│   └── boot_linux.rs      # Boot Linux kernel
├── tests/
│   └── integration/
├── guest/                 # Guest image building (future)
│   ├── kernel/            # Kernel configs
│   └── rootfs/            # Rootfs building
└── docs/
    └── architecture.md
```

---

## Platform-Specific Notes

### macOS (Hypervisor.framework)

**API Documentation:** https://developer.apple.com/documentation/hypervisor

**Key Functions:**
- `hv_vm_create()` — Create VM context
- `hv_vm_map()` — Map host memory to guest physical address
- `hv_vcpu_create()` — Create virtual CPU
- `hv_vcpu_run()` — Enter guest execution
- `hv_vcpu_read_register()` / `hv_vcpu_write_register()` — Register access

**Architecture Differences:**
- **Intel Macs:** x86_64 virtualization, similar to KVM concepts
- **Apple Silicon:** ARM64 virtualization, different register set, different exit reasons

**Entitlements Required:**
```xml
<key>com.apple.security.hypervisor</key>
<true/>
```

**Linking:**
```rust
#[link(name = "Hypervisor", kind = "framework")]
```

### Windows (WHP)

**API Documentation:** https://docs.microsoft.com/en-us/virtualization/api/

**Key Functions:**
- `WHvCreatePartition()` — Create VM partition
- `WHvSetupPartition()` — Finalize partition setup
- `WHvMapGpaRange()` — Map memory
- `WHvCreateVirtualProcessor()` — Create vCPU
- `WHvRunVirtualProcessor()` — Run vCPU

**Requirements:**
- Windows 10 version 1803+
- Hyper-V enabled in Windows Features
- Virtualization enabled in BIOS

**Crate:** Use `windows-rs` for bindings

### Linux (KVM) — Future

**Existing Crates:**
- `kvm-ioctls` — KVM ioctl wrappers
- `kvm-bindings` — Struct definitions
- `vm-memory` — Guest memory management

Best documented platform, can leverage rust-vmm ecosystem.

---

## Key Technical Decisions

### Already Decided

1. **virtio-mmio over PCI** — Simpler, no PCI enumeration needed
2. **Start with serial console** — Prove VM works before adding virtio devices
3. **vsock for host-guest communication** — Cleaner than TCP port forwarding
4. **Async API** — Use tokio for non-blocking operations

### Open Questions

1. **Guest image format?** — Raw disk image vs embedded initramfs
2. **Network backend on macOS?** — vmnet.framework vs userspace NAT
3. **ARM64 boot protocol?** — Different from x86 Linux boot protocol

---

## Development Guidelines

### Philosophy
1. **Get it working first** — Optimize later
2. **Minimal viable features** — Don't over-engineer
3. **Platform parity** — Same API across all platforms
4. **Test on real hardware** — Simulators lie

### Code Style
- Standard Rust formatting (`cargo fmt`)
- Use `thiserror` for error types
- Use `tracing` for logging (optional feature)
- Avoid `unsafe` where possible, isolate when necessary
- Document public API with examples

### Testing Strategy
1. **Unit tests** — Backend-specific functionality
2. **Integration tests** — Boot VM, run commands
3. **Platform CI** — GitHub Actions for macOS/Windows/Linux

### Commit Messages
- Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`
- Reference issues when applicable

---

## Velocitty Integration Path

### Current Velocitty VM Code (to be replaced)
- `src-tauri/src/integrations/vm_network.rs` (608 lines) — Lima orchestration
- `src-tauri/src/terminal/vm.rs` (178 lines) — VM terminal
- `vm/daemon.py` (434 lines) — Python daemon
- `vm/velocitty-network.yaml` — Lima config

### Migration Strategy
1. Add microvm-rs as dependency
2. Create feature flag: `microvm` vs `lima` (deprecated)
3. Implement `MicrovmNetworkManager` alongside `VmNetworkManager`
4. Port daemon from Python to Rust (runs in guest)
5. Test thoroughly
6. Remove Lima code path

### Required microvm-rs Features for Velocitty
- [x] VM creation/destruction
- [x] Memory allocation
- [x] vCPU execution
- [x] Serial console (debugging) - PL011 for ARM64, 8250 for x86
- [x] virtio-net (guest networking) - with backend trait
- [x] virtio-vsock (control channel) - with connection management
- [x] Linux kernel loader - ARM64 Image + x86 bzImage
- [ ] Boot Linux kernel (needs testing with real kernel)
- [ ] Mount rootfs

---

## References

### Documentation
- [KVM API](https://www.kernel.org/doc/html/latest/virt/kvm/api.html) — Best reference even for other platforms
- [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor)
- [WHP API](https://docs.microsoft.com/en-us/virtualization/api/)
- [virtio Spec](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html)
- [Linux Boot Protocol](https://www.kernel.org/doc/html/latest/x86/boot.html)

### Code References
- [Firecracker](https://github.com/firecracker-microvm/firecracker) — AWS microVM (Linux only)
- [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) — Intel microVM
- [rust-vmm](https://github.com/rust-vmm) — Reusable VMM components
- [uhyve](https://github.com/hermit-os/uhyve) — Simple hypervisor, good learning resource

### Learning
- [Writing a KVM hypervisor](https://www.codeproject.com/Articles/5306251/Writing-a-KVM-hypervisor-in-Rust)
- [virtio walkthrough](https://blogs.oracle.com/linux/post/introduction-to-virtio)

---

## Quick Commands

```bash
# Build (macOS)
cargo build

# Build (Windows) — run on Windows machine
cargo build --features whp

# Run tests
cargo test

# Run example
cargo run --example minimal

# Check all platforms compile (CI)
cargo check --all-features
```

---

## Contact / Context

- **Primary Developer:** Ankit Choudhary
- **Related Project:** Velocitty (~/Documents/velocitty)
- **Spec Document:** microvm-rs.md (in this repo)

---

*This file helps AI assistants understand the project context. Update it as the project evolves.*
