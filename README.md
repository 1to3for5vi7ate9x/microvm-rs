# microvm-rs

A cross-platform, embeddable microVM library for Rust.

[![Crates.io](https://img.shields.io/crates/v/microvm.svg)](https://crates.io/crates/microvm)
[![Documentation](https://docs.rs/microvm/badge.svg)](https://docs.rs/microvm)
[![License](https://img.shields.io/crates/l/microvm.svg)](LICENSE)

## Overview

microvm-rs enables applications to spawn lightweight, hardware-isolated virtual machines using platform-native hypervisors:

- **macOS**: Hypervisor.framework (Apple Silicon + Intel)
- **Windows**: Windows Hypervisor Platform (WHP)
- **Linux**: KVM

## Features

- **Zero external dependencies** - No QEMU, no Docker, just native hypervisor APIs
- **Fast boot times** - VMs start in <500ms
- **Small footprint** - <50MB memory for minimal VMs
- **VirtIO devices** - Console, block, network, and vsock support
- **Embeddable** - Ships as a Rust library, perfect for desktop apps

## Quick Start

```rust
use microvm::{MicroVM, VmConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if hypervisor is available
    if !microvm::is_supported() {
        eprintln!("Hypervisor not available");
        return Ok(());
    }

    // Create VM configuration
    let config = VmConfig {
        memory_mb: 512,
        vcpus: 1,
        kernel: Some("path/to/kernel".into()),
        initrd: Some("path/to/initrd".into()),
        ..Default::default()
    };

    // Boot the VM
    let vm = MicroVM::new(&config)?;
    vm.run()?;

    Ok(())
}
```

## CLI Tool

microvm-rs includes a CLI for testing:

```bash
# Build the CLI
cargo build --release

# Sign for macOS (required for Hypervisor.framework)
codesign --sign - --entitlements microvm.entitlements --force ./target/release/microvm

# Run a VM
./target/release/microvm run --kernel Image --initrd initramfs.cpio.gz --console
```

## VirtIO Devices

| Device | Status | Description |
|--------|--------|-------------|
| Console | ✅ | Interactive terminal via hvc0 |
| Block | ✅ | Disk image support |
| Vsock | ✅ | Host-guest socket communication |
| Network | 🚧 | Null backend (vmnet requires entitlements) |

## vsock Communication

vsock provides a direct communication channel between host and guest without network configuration:

```rust
// Guest listens on vsock port 1234
// Host connects to CID 3, port 1234
```

This is ideal for:
- Control plane communication
- SOCKS proxy tunneling
- File transfer
- RPC protocols

## Platform Requirements

### macOS
- macOS 10.15+ (Catalina)
- Hypervisor.framework entitlement required:

```xml
<!-- microvm.entitlements -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
```

### Windows
- Windows 10 version 1803+
- Hyper-V enabled in Windows Features

### Linux
- KVM support (`/dev/kvm`)
- User must have access to KVM device

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting PRs.
