# MicroVM Implementation Plan

## Current Status (2025-01-25)

### ✅ macOS ARM64 - COMPLETE

The macOS implementation is production-ready:

| Component | Status | Notes |
|-----------|--------|-------|
| **VM Runtime** | ✅ Complete | Full event loop, device dispatch, timer interrupts |
| **Hypervisor.framework backend** | ✅ Complete | vCPU, memory mapping, MMIO handling |
| **VirtIO vsock** | ✅ Complete | Connection management, packet routing |
| **Host Proxy (ProxyConnectionManager)** | ✅ Complete | SOCKS5 relay via vsock |
| **Guest outbound-proxy** | ✅ Complete | SOCKS5→vsock bridge |
| **PL011 UART** | ✅ Complete | Console I/O with interrupts |
| **GIC (Interrupt Controller)** | ✅ Complete | IRQ delivery |
| **Linux Loader** | ✅ Complete | ARM64 Image format |
| **Device Tree Builder** | ✅ Complete | DTB generation |

**Working Features:**
- Boot Linux kernel with initramfs
- Interactive console (input/output)
- Host↔Guest vsock communication
- Guest internet access via SOCKS5 proxy
- VPN daemon integration ready

---

## 🚧 Next: Windows WHP Backend

### Strategy Update

Per `WINDOWS_SUPPORT_STRATEGY.md`, we'll use **Windows Hypervisor Platform (WHP)** for all Windows editions (including Home). No kernel driver needed.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     microvm-rs on Windows                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   microvm-rs (userspace .exe)                                   │
│     - Same VirtIO device layer as macOS                         │
│     - Same proxy infrastructure                                  │
│     - WHP API calls instead of HVF                              │
│                          │                                       │
│                          ▼                                       │
│   Windows Hypervisor (WinHvPlatform.dll)                        │
│     - Pre-signed by Microsoft                                   │
│     - x86_64 virtualization                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation Phases

#### Phase 1: WHP Backend Foundation
- [ ] Add `windows` crate dependency with WHP features
- [ ] Create `src/backend/whp/mod.rs` structure
- [ ] Implement `WHvCreatePartition` / `WHvDeletePartition`
- [ ] Implement `WHvMapGpaRange` for memory mapping
- [ ] Implement `WHvCreateVirtualProcessor`
- [ ] Implement `WHvSetVirtualProcessorRegisters` (set initial state)
- [ ] Implement basic `WHvRunVirtualProcessor` loop

#### Phase 2: x86_64 Boot Setup
- [ ] Set up x86_64 long mode (CR0, CR4, EFER)
- [ ] Configure GDT and segment registers
- [ ] Set up page tables (identity mapping)
- [ ] Linux boot protocol (bzImage loading)
- [ ] E820 memory map

#### Phase 3: Exit Handling
- [ ] `WHvRunVpExitReasonMemoryAccess` → MMIO to devices
- [ ] `WHvRunVpExitReasonX64IoPortAccess` → I/O ports (serial)
- [ ] `WHvRunVpExitReasonX64Halt` → HLT instruction
- [ ] `WHvRunVpExitReasonX64Cpuid` → CPUID emulation

#### Phase 4: x86_64 Devices
- [ ] 8250 Serial UART (already stubbed in `src/device/serial.rs`)
- [ ] Port VirtIO vsock to x86 (MMIO same, just different base address)
- [ ] Interrupt injection via `WHvRequestInterrupt`

#### Phase 5: Integration
- [ ] Wire up existing proxy infrastructure
- [ ] Test console output
- [ ] Test vsock communication
- [ ] Boot Linux kernel
- [ ] Test outbound-proxy

### File Structure

```
src/backend/
├── mod.rs              # Backend trait + selection
├── hvf/                # macOS (existing, complete)
│   ├── mod.rs
│   ├── bindings.rs
│   └── vcpu.rs
└── whp/                # Windows (NEW)
    ├── mod.rs          # WhpBackend implementation
    ├── partition.rs    # VM creation/destruction
    ├── vcpu.rs         # vCPU management
    ├── memory.rs       # Memory mapping
    └── x86_setup.rs    # Long mode, GDT, page tables
```

### Key WHP API Mapping

| macOS HVF | Windows WHP | Purpose |
|-----------|-------------|---------|
| `hv_vm_create()` | `WHvCreatePartition()` | Create VM |
| `hv_vm_map()` | `WHvMapGpaRange()` | Map memory |
| `hv_vcpu_create()` | `WHvCreateVirtualProcessor()` | Create vCPU |
| `hv_vcpu_run()` | `WHvRunVirtualProcessor()` | Run until exit |
| `hv_vcpu_read/write_register()` | `WHvGet/SetVirtualProcessorRegisters()` | Register access |
| Exit reason enum | `WHV_RUN_VP_EXIT_REASON` | Exit classification |

### Requirements

**Development Environment:**
- Windows 10/11 (any edition)
- "Windows Hypervisor Platform" feature enabled
- Visual Studio or rust-analyzer
- Hardware virtualization enabled in BIOS

**Dependencies:**
```toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = [
    "Win32_System_Hypervisor",
    "Win32_Foundation",
] }
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Host Application                            │
│                       (Velocitty)                                │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                        microvm-rs                                │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                     VmRuntime                               │ │
│  │  - Event loop (vCPU exits)                                 │ │
│  │  - Device MMIO dispatch                                    │ │
│  │  - Vsock packet routing                                    │ │
│  │  - ProxyConnectionManager                                  │ │
│  └────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                   Device Layer                              │ │
│  │  UART (PL011/8250) │ VirtioVsock │ GIC/APIC               │ │
│  └────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                  Backend Abstraction                        │ │
│  │  ┌──────────┐    ┌──────────┐    ┌──────────┐             │ │
│  │  │   HVF    │    │   WHP    │    │   KVM    │             │ │
│  │  │ (macOS)  │    │(Windows) │    │ (Linux)  │             │ │
│  │  │    ✅    │    │   🚧    │    │   📋    │             │ │
│  │  └──────────┘    └──────────┘    └──────────┘             │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

Legend: ✅ Complete  🚧 In Progress  📋 Planned
```

---

## Guest Components

| Component | Location | Status |
|-----------|----------|--------|
| outbound-proxy | `guest/outbound-proxy/` | ✅ Complete |
| vsock-client | `guest/vsock-client/` | ✅ Complete (test util) |
| vpn-daemon | (in Velocitty repo) | ✅ Working |

---

## Testing Plan

### Windows Development Testing

1. **Minimal VM Test**
   - Create partition, map memory, create vCPU
   - Load tiny x86_64 code (HLT loop)
   - Verify WHvRunVirtualProcessor returns HLT exit

2. **Serial Console Test**
   - Boot Linux kernel
   - Verify console output via 8250 UART
   - Test console input

3. **Vsock Test**
   - Verify vsock device enumeration in guest
   - Test host→guest ping
   - Test guest→host connection

4. **Proxy Test**
   - Start outbound-proxy in guest
   - `curl --socks5 127.0.0.1:1080 http://example.com`
   - Verify traffic flows through host proxy

---

## Notes

### Vsock Ports
- **1025**: vpn-daemon control (legacy)
- **1234**: HOST_PORT (daemon communication)
- **7601**: OUTBOUND_PROXY_PORT (internet proxy)

### CIDs
- **2**: Host (VMADDR_CID_HOST)
- **3**: Guest (default)

### Key Files
| File | Purpose |
|------|---------|
| `src/runtime.rs` | VM runtime, event loop, device coordination |
| `src/proxy.rs` | ProxyConnectionManager for guest internet |
| `src/device/virtio/vsock.rs` | VirtIO vsock device emulation |
| `src/backend/hvf/` | macOS Hypervisor.framework backend |
| `src/backend/whp/` | Windows WHP backend (TODO) |

---

*Last updated: 2025-01-25*
