# Windows Support Strategy for microvm-rs

## Overview

This document outlines the strategy for supporting Windows across all editions using the Windows Hypervisor Platform (WHP) API.

## Key Finding: WHP Works on Windows Home

**UPDATE (2025-01-25):** After investigation, we discovered that **WHP is available on Windows Home editions** as an optional Windows feature. This significantly simplifies our strategy.

Evidence:
- Windows Home shows "Windows Hypervisor Platform" in "Turn Windows features on or off"
- After enabling, System Information shows "A hypervisor has been detected"
- VirtualBox and QEMU successfully use WHP on Home editions
- WSL2 works on Home, which uses the same underlying virtualization technology

## Windows Edition Landscape

| Edition | WHP Feature | WHP API | Our Strategy |
|---------|-------------|---------|--------------|
| Windows 11/10 Home | ✅ Available (optional) | ✅ Works | WHP backend |
| Windows 11/10 Pro | ✅ Available (optional) | ✅ Works | WHP backend |
| Windows 11/10 Enterprise | ✅ Available (optional) | ✅ Works | WHP backend |
| Windows 11/10 Education | ✅ Available (optional) | ✅ Works | WHP backend |

### Requirements

- Windows 10 version 1803+ or Windows 11
- "Windows Hypervisor Platform" feature enabled
- Hardware virtualization enabled in BIOS/UEFI (Intel VT-x or AMD-V)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     microvm-rs on Windows                        │
│                         (All Editions)                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  microvm-rs (userspace .exe)                            │   │
│   │                                                          │   │
│   │    - VM configuration                                    │   │
│   │    - Device emulation (VirtIO)                          │   │
│   │    - Guest memory management                            │   │
│   │    - WHP API calls                                      │   │
│   └──────────────────────┬──────────────────────────────────┘   │
│                          │                                       │
│                          │ WHP User-Mode API                     │
│                          │ (WinHvPlatform.dll)                   │
│                          ▼                                       │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  Windows Hypervisor (kernel)                            │   │
│   │                                                          │   │
│   │    - Pre-signed by Microsoft                            │   │
│   │    - Handles VT-x/AMD-V operations                      │   │
│   │    - Memory virtualization (EPT/NPT)                    │   │
│   │    - VM exits routed to userspace                       │   │
│   └──────────────────────┬──────────────────────────────────┘   │
│                          │                                       │
│              [Intel VT-x / AMD-V CPU Hardware]                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Why WHP is the Right Choice

### Advantages

| Benefit | Description |
|---------|-------------|
| **No driver signing** | Standard user-mode application (.exe) |
| **Cross-edition support** | Works on Home, Pro, Enterprise, Education |
| **Microsoft-maintained** | Windows handles the kernel-mode complexity |
| **Hardware acceleration** | Full VT-x/AMD-V performance |
| **Simpler development** | No kernel debugging, no BSOD risk |
| **Future-proof** | Microsoft maintains compatibility |

### Comparison: WHP vs Custom Kernel Driver

| Aspect | WHP | Custom Kernel Driver |
|--------|-----|---------------------|
| Development complexity | Low | Very High |
| Driver signing | Not required | Required (~$400/year EV cert) |
| BSOD risk | None | High during development |
| Windows Home support | ✅ Yes | ✅ Yes |
| Maintenance burden | Microsoft handles | We maintain |
| Time to implement | Days | Months |

## WHP API Overview

### Core Functions

```c
// Partition (VM) Management
WHvCreatePartition()        // Create VM
WHvSetupPartition()         // Finalize VM configuration
WHvDeletePartition()        // Destroy VM

// Memory Management
WHvMapGpaRange()            // Map host memory to guest physical address
WHvUnmapGpaRange()          // Unmap memory

// Virtual Processor Management
WHvCreateVirtualProcessor() // Create vCPU
WHvDeleteVirtualProcessor() // Destroy vCPU
WHvGetVirtualProcessorRegisters()  // Read registers
WHvSetVirtualProcessorRegisters()  // Write registers

// Execution
WHvRunVirtualProcessor()    // Run vCPU until VM exit
WHvCancelRunVirtualProcessor()  // Interrupt execution
```

### Typical VM Loop

```rust
// Pseudocode for WHP-based VM loop
fn run_vm() -> Result<()> {
    // 1. Create partition
    let partition = WHvCreatePartition()?;

    // 2. Configure partition properties
    WHvSetPartitionProperty(partition, ProcessorCount, 1)?;
    WHvSetupPartition(partition)?;

    // 3. Map guest memory
    WHvMapGpaRange(partition, host_memory, guest_addr, size, flags)?;

    // 4. Create virtual processor
    WHvCreateVirtualProcessor(partition, 0)?;

    // 5. Set initial registers (RIP, RSP, etc.)
    WHvSetVirtualProcessorRegisters(partition, 0, &initial_regs)?;

    // 6. Run loop
    loop {
        let exit_context = WHvRunVirtualProcessor(partition, 0)?;

        match exit_context.ExitReason {
            WHvRunVpExitReasonMemoryAccess => handle_mmio(&exit_context),
            WHvRunVpExitReasonX64IoPortAccess => handle_io(&exit_context),
            WHvRunVpExitReasonX64Halt => break,
            // ... other exits
        }
    }

    Ok(())
}
```

## Implementation Plan

### Phase 1: WHP Backend Foundation
- [ ] Add WHP bindings using `windows` crate
- [ ] Implement partition creation/destruction
- [ ] Implement memory mapping
- [ ] Implement vCPU creation and register access
- [ ] Implement basic run loop

### Phase 2: Exit Handling
- [ ] Handle MMIO exits (route to device emulation)
- [ ] Handle I/O port exits
- [ ] Handle HLT instruction
- [ ] Handle CPUID (report hypervisor presence)

### Phase 3: Integration
- [ ] Wire up existing VirtIO device layer
- [ ] Test serial console output
- [ ] Test virtio-vsock communication
- [ ] Boot Linux kernel

### Phase 4: Testing & Polish
- [ ] Test on Windows 10 Home
- [ ] Test on Windows 11 Home
- [ ] Test on Windows Pro/Enterprise
- [ ] Handle edge cases and errors
- [ ] Performance profiling

## User Setup Requirements

Users need to enable the Windows Hypervisor Platform feature:

### GUI Method
1. Open "Turn Windows features on or off"
2. Check "Windows Hypervisor Platform"
3. Check "Virtual Machine Platform" (if not already enabled)
4. Click OK and restart

### PowerShell Method (Admin)
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
Restart-Computer
```

### Verification
After restart, check System Information:
- Should show "A hypervisor has been detected"

## Error Handling

### Common Issues

| Error | Cause | Solution |
|-------|-------|----------|
| `WHvCapabilityCodeHypervisorPresent = FALSE` | WHP feature not enabled | Enable in Windows Features |
| `E_ACCESSDENIED` | Need admin or specific capability | Run as admin or add app capability |
| `WHV_E_INSUFFICIENT_BUFFER` | Buffer too small | Increase buffer size |
| Virtualization disabled | VT-x/AMD-V off in BIOS | Enable in BIOS/UEFI settings |

### Graceful Degradation

```rust
pub fn create_backend(config: VmConfig) -> Result<Box<dyn HypervisorBackend>> {
    #[cfg(target_os = "windows")]
    {
        // Check if WHP is available
        if whp::is_available() {
            return Ok(Box::new(whp::WhpBackend::new(config)?));
        }

        // Provide helpful error message
        return Err(Error::HypervisorNotAvailable {
            message: "Windows Hypervisor Platform is not available. \
                      Please enable it in 'Turn Windows features on or off' \
                      and ensure virtualization is enabled in BIOS.".into()
        });
    }
}
```

## File Structure

```
microvm-rs/
├── src/
│   └── backend/
│       ├── mod.rs              # Backend selection logic
│       ├── hvf/                # macOS Hypervisor.framework
│       ├── whp/                # Windows Hypervisor Platform
│       │   ├── mod.rs          # WhpBackend implementation
│       │   ├── partition.rs    # VM (partition) management
│       │   ├── vcpu.rs         # Virtual processor management
│       │   ├── memory.rs       # Memory mapping
│       │   └── exits.rs        # Exit handling
│       └── kvm/                # Linux KVM (future)
```

## Resources

### Microsoft Documentation
- [Windows Hypervisor Platform API](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform)
- [WHP API Samples](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/whp-samples)
- [Hyper-V APIs Overview](https://learn.microsoft.com/en-us/virtualization/api/)

### Reference Implementations
- [WinVisor](https://github.com/x86matthew/WinVisor) - WHP-based x64 emulator
- [SimpleWhpDemo](https://github.com/Zero-Tang/SimpleWhpDemo) - Simple WHP demo

### Windows Crate
- [windows-rs](https://github.com/microsoft/windows-rs) - Official Rust bindings for Windows APIs
- WHP types are in `windows::Win32::System::Hypervisor`

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2025-01-21 | ~~Pursue kernel driver for Windows Home~~ | ~~WHP not available on Home~~ (incorrect assumption) |
| 2025-01-25 | **Use WHP for all Windows editions** | WHP IS available on Windows Home as optional feature |
| 2025-01-25 | Remove kernel driver approach | Unnecessary complexity; WHP provides everything we need |

---

## Archived: Kernel Driver Approach

> **Note:** This section is kept for reference only. The kernel driver approach is no longer planned since WHP works on all Windows editions.

<details>
<summary>Click to expand archived kernel driver documentation</summary>

The original plan was to write a custom kernel driver (microvm.sys) that directly uses Intel VT-x/AMD-V instructions for Windows Home, where we incorrectly believed WHP was unavailable.

This would have required:
- Windows Driver Kit (WDK) development
- EV code signing certificate (~$400/year)
- Microsoft attestation signing
- Extensive kernel debugging
- Custom EPT implementation
- VMCS management

Reference implementations studied:
- [SimpleVisor](https://github.com/ionescu007/SimpleVisor) - ~500 lines, educational
- [hvpp](https://github.com/wbenny/hvpp) - ~5000+ lines, production-quality

This approach is no longer necessary.

</details>

---

*Last updated: 2025-01-25*
