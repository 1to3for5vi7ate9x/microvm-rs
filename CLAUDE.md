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

Target flow with microvm-rs (macOS/Linux):
```
SSH Client → vsock (SOCKS5) → microvm → OpenVPN → Target
                    ↑
            Direct vsock channel (fast, reliable)
```

Target flow with microvm-rs (Windows):
```
SSH Client → localhost:1080 (SOCKS5) → WSL2 distro → OpenVPN → Target
                    ↑
            Shared network namespace (no port forwarding needed)
```

---

## Current Status

**Phase:** Active Development
**Platform Focus:** macOS (HVF) + Windows (WSL2) in parallel

### Development Order
1. **macOS (HVF)** — Primary development platform
2. **Windows (WSL2)** — Secondary platform (active development)
3. **Linux (KVM)** — Future, if needed (best documented, can add later)

> **Note:** Windows backend was changed from WHP (Windows Hypervisor Platform) to WSL2 in Feb 2026 due to unfixable MSR bugs in the WHP API. See `docs/current_state.md` for details.

### What's Done

**Core / macOS (HVF):**
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

**Windows (WSL2 backend):**
- [x] WSL2 backend replacing WHP (process-based, manages WSL distro lifecycle)
- [x] **MILESTONE: Alpine Linux boots in WSL2 with control daemon!**
- [x] Embedded Alpine minirootfs (3.5MB, compiled into binary)
- [x] Distro lifecycle management (import, provision, terminate, unregister)
- [x] Control daemon on TCP port 1025 (ping, status, pause, resume, shutdown)
- [x] Interactive shell access (spawn_shell, run_shell_interactive)
- [x] UTF-16LE output decoding for WSL management commands
- [x] TcpVsockBridge for host-guest communication via localhost
- [x] Auto-provisioning (socat install, init script deployment)
- [x] Cleanup utilities (distro unregister, data directory removal)

**Cross-platform:**
- [x] VsockClient/VsockHandler async API
- [x] ProxyConnectionManager (outbound TCP proxy protocol)
- [x] VmRuntime with platform-specific event loops

### Known Limitations

#### Windows: WHP Abandoned
The original WHP (Windows Hypervisor Platform) backend was abandoned due to unfixable MSR handling bugs — standard Linux kernels cannot fully boot because WHP doesn't properly report MSR numbers during exits. See `docs/current_state.md` for the full history.

#### Windows: WSL2 Backend Limitations
- **Not a true hypervisor** — WSL2 backend is a "process backend" that manages a WSL distro, not CPU emulation
- **No memory/CPU isolation** — WSL2 uses host resources directly
- **pause/resume are stubs** — daemon acknowledges commands but doesn't actually pause processes
- **No VPN integration yet** — SOCKS5 proxy and OpenVPN not deployed in guest

### What's Next
- [ ] Deploy SOCKS5 proxy server in WSL2 guest (for Velocitty VPN routing)
- [ ] Deploy OpenVPN client in WSL2 guest
- [ ] Add VPN lifecycle commands to daemon (vpn-start, vpn-stop, vpn-status)
- [ ] Boot real Linux kernel on macOS (HVF)
- [ ] Port KVM backend for Linux
- [ ] TAP backend for virtio-net

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
│  │  HVF Backend   │  │  WSL2 Backend  │  │  KVM Backend   │   │
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
│   │   ├── wsl/           # Windows WSL2 (process backend)
│   │   │   ├── mod.rs         # WslBackend + HypervisorBackend impl
│   │   │   ├── process.rs     # wsl.exe CLI wrapper + UTF-16LE decoding
│   │   │   ├── distro.rs      # WSL distro lifecycle management
│   │   │   └── rootfs.rs      # Embedded Alpine rootfs extraction
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
├── guest/
│   ├── kernel/            # Kernel configs
│   ├── rootfs/            # Rootfs building
│   └── wsl-rootfs/        # WSL2 guest files
│       ├── alpine-minirootfs.tar.gz  # Alpine 3.21.3 x86_64 (embedded)
│       ├── init-microvm.sh           # Control daemon entrypoint
│       └── setup.sh                  # Post-import provisioning (legacy)
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

### Windows (WSL2)

**Approach:** Process-based backend — manages a lightweight WSL2 Alpine Linux distro rather than CPU emulation. Communication uses localhost TCP (WSL2 shares host network namespace).

**Requirements:**
- Windows 10 version 2004+ or Windows 11
- WSL2 enabled (`wsl --install`)
- Virtualization enabled in BIOS

**Key Components:**
- `wsl.exe` CLI for distro management (import, exec, terminate)
- Embedded Alpine 3.21.3 minirootfs (3.5MB, compiled into binary via `include_bytes!`)
- Control daemon on `localhost:1025` (socat-based, supports concurrent connections)
- `TcpVsockBridge` maps vsock messages to TCP connections

**Why WSL2 instead of WHP:**
WHP (Windows Hypervisor Platform) was abandoned because its MSR exit handling is broken — it doesn't report which MSR is being accessed, making it impossible to boot standard Linux kernels. WSL2 sidesteps this entirely by using Microsoft's own Linux kernel.

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
3. **vsock for host-guest communication** — Cleaner than TCP port forwarding (macOS/Linux use vsock, Windows uses TCP via TcpVsockBridge)
4. **Async API** — Use tokio for non-blocking operations
5. **WSL2 over WHP for Windows** — WHP MSR bugs are unfixable, WSL2 is reliable
6. **Embedded rootfs for Windows** — Alpine minirootfs compiled into binary, zero external deps

### Open Questions

1. **Network backend on macOS?** — vmnet.framework vs userspace NAT
2. **SOCKS5 server for guest?** — microsocks vs dante vs custom Rust implementation
3. **VPN config delivery?** — How to pass OpenVPN config from host to guest

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
- [x] Windows: Boot Alpine Linux via WSL2 with control daemon
- [x] Windows: Interactive shell access
- [x] Windows: Host-guest TCP communication (TcpVsockBridge)
- [ ] Windows: SOCKS5 proxy in guest
- [ ] Windows: OpenVPN client in guest
- [ ] Windows: VPN lifecycle management (start/stop/status)
- [ ] macOS: Boot Linux kernel with HVF (needs testing with real kernel)
- [ ] Mount rootfs (macOS/Linux)

---

## References

### Documentation
- [KVM API](https://www.kernel.org/doc/html/latest/virt/kvm/api.html) — Best reference even for other platforms
- [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor)
- [WSL2 Documentation](https://learn.microsoft.com/en-us/windows/wsl/)
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
cargo build

# Run tests
cargo test

# Run example
cargo run --example minimal

# Run microvm CLI (Windows — boots WSL2 distro)
cargo run --bin microvm

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
