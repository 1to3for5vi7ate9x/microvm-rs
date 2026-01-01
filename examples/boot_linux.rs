//! Example: Boot a Linux kernel.
//!
//! This example demonstrates booting a Linux kernel in the VM.
//! You need to provide a kernel image (vmlinuz or bzImage).
//!
//! Usage:
//!   cargo run --example boot_linux -- /path/to/vmlinuz

use microvm::MicroVM;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <kernel-path> [initrd-path]", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} /boot/vmlinuz-linux", args[0]);
        eprintln!("  {} /boot/vmlinuz-linux /boot/initramfs-linux.img", args[0]);
        std::process::exit(1);
    }

    let kernel_path = &args[1];
    let initrd_path = args.get(2);

    println!("microvm-rs Linux boot example");
    println!("==============================\n");

    // Check if hypervisor is available
    if !microvm::is_supported() {
        eprintln!("Error: Hypervisor not available on this system");
        std::process::exit(1);
    }

    println!("Kernel: {}", kernel_path);
    if let Some(initrd) = initrd_path {
        println!("Initrd: {}", initrd);
    }
    println!();

    // Build the VM
    let mut builder = MicroVM::builder()
        .memory_mb(256)
        .vcpus(1)
        .kernel(kernel_path)
        .cmdline("console=ttyS0 earlyprintk=serial panic=1");

    if let Some(initrd) = initrd_path {
        builder = builder.initrd(initrd);
    }

    let mut vm = match builder.build() {
        Ok(vm) => {
            println!("VM created successfully!");
            println!("  Memory: {} MB", vm.memory_size() / 1024 / 1024);
            println!("  vCPUs: {}", vm.vcpu_count());
            vm
        }
        Err(e) => {
            eprintln!("Failed to create VM: {}", e);
            std::process::exit(1);
        }
    };

    println!("\nBooting kernel...\n");
    println!("--- Serial output ---");

    // Boot the VM
    match vm.boot() {
        Ok(()) => {
            println!("\n--- VM exited normally ---");
        }
        Err(e) => {
            eprintln!("\n--- VM error: {} ---", e);
        }
    }
}
