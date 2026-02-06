//! Minimal example: Check if hypervisor is available.
//!
//! This example demonstrates the basic API and checks if the
//! hypervisor is available on the current platform.

use microvm::{backend_name, is_supported};

fn main() {
    println!("microvm-rs minimal example");
    println!("==========================\n");

    // Check if hypervisor is available
    if is_supported() {
        println!("Hypervisor is available!");
        if let Some(name) = backend_name() {
            println!("  Backend: {}", name);
        }
    } else {
        println!("Hypervisor is NOT available on this system.");
        println!();
        println!("Possible reasons:");

        #[cfg(target_os = "macos")]
        {
            println!("  - Missing com.apple.security.hypervisor entitlement");
            println!("  - Running in a VM without nested virtualization");
        }

        #[cfg(target_os = "windows")]
        {
            println!("  - WSL2 is not installed or enabled");
            println!("  - Run 'wsl --install' to set up WSL2");
        }

        #[cfg(target_os = "linux")]
        {
            println!("  - KVM module not loaded");
            println!("  - No access to /dev/kvm");
            println!("  - Virtualization not enabled in BIOS");
        }
    }

    println!();

    // Try to create a VM (will fail if hypervisor not available)
    println!("Attempting to create a VM...");

    match microvm::MicroVM::builder().memory_mb(64).build() {
        Ok(vm) => {
            println!("  VM created successfully!");
            println!("  Memory: {} bytes", vm.memory_size());
            println!("  vCPUs: {}", vm.vcpu_count());
            println!("  State: {:?}", vm.state());
        }
        Err(e) => {
            println!("  Failed to create VM: {}", e);
        }
    }
}
