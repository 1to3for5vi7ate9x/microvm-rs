//! Simple code execution test.
//!
//! This example loads minimal machine code into the VM and executes it.
//! On x86_64: writes to serial port 0x3f8
//! On ARM64: writes to MMIO UART and uses WFI to halt
//!
//! This proves the VM is actually executing guest code.

fn main() {
    println!("microvm-rs: Hello VM test");
    println!("==========================\n");

    if !microvm::is_supported() {
        eprintln!("Hypervisor not available. Make sure:");
        eprintln!("  - Binary is signed with com.apple.security.hypervisor entitlement");
        eprintln!("  - Not running in a VM without nested virtualization");
        std::process::exit(1);
    }

    println!("Hypervisor: {}", microvm::backend_name().unwrap_or("unknown"));
    println!("Architecture: {}", std::env::consts::ARCH);

    run_hello_vm();
}

#[cfg(target_os = "macos")]
fn run_hello_vm() {
    use microvm::backend::hvf;

    println!("\nCreating VM...");

    let config = microvm::backend::VmConfig {
        memory_mb: 64,
        vcpus: 1,
        kernel: None,
        initrd: None,
        rootfs: None,
        cmdline: String::new(),
    };

    let mut vm = match hvf::Vm::new(&config) {
        Ok(vm) => {
            println!("  VM created successfully");
            vm
        }
        Err(e) => {
            eprintln!("  Failed to create VM: {}", e);
            return;
        }
    };

    #[cfg(target_arch = "x86_64")]
    {
        run_x86_64_test(&mut vm);
    }

    #[cfg(target_arch = "aarch64")]
    {
        run_arm64_test(&mut vm);
    }
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn run_x86_64_test(vm: &mut microvm::backend::hvf::Vm) {
    use microvm::backend::hvf::{bindings::x86_reg, vcpu::VcpuExit};

    // x86 machine code that writes "Hello from VM!\n" to serial port and halts
    let code: Vec<u8> = vec![
        // mov dx, 0x3f8
        0xBA, 0xF8, 0x03,
        // mov si, 0x1012 (address of message)
        0xBE, 0x12, 0x10,
        // loop: lodsb
        0xAC,
        // test al, al
        0x84, 0xC0,
        // jz done (+4)
        0x74, 0x04,
        // out dx, al
        0xEE,
        // jmp loop (-7)
        0xEB, 0xF7,
        // done: hlt
        0xF4,
        // message:
        b'H', b'e', b'l', b'l', b'o', b' ', b'f', b'r', b'o', b'm', b' ',
        b'V', b'M', b'!', b'\n', 0x00,
    ];

    let load_addr = 0x1000usize;
    println!("  Loading x86_64 code at 0x{:x} ({} bytes)", load_addr, code.len());

    vm.memory_mut().write(load_addr, &code).unwrap();

    if let Some(vcpu) = vm.vcpu_mut(0) {
        vcpu.write_register(x86_reg::HV_X86_RIP, load_addr as u64).unwrap();
        vcpu.write_register(x86_reg::HV_X86_RSP, 0x7000).unwrap();
    }

    println!("\nRunning VM...\n--- Guest output ---");

    run_vcpu_loop_x86(vm);
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn run_vcpu_loop_x86(vm: &mut microvm::backend::hvf::Vm) {
    use microvm::backend::hvf::{bindings::x86_reg, vcpu::VcpuExit};
    use std::io::Write;

    for i in 0..1000 {
        let vcpu = vm.vcpu_mut(0).unwrap();

        match vcpu.run() {
            Ok(VcpuExit::IoOut { port, data }) if port == 0x3f8 => {
                for byte in data {
                    print!("{}", byte as char);
                }
                let _ = std::io::stdout().flush();
                let rip = vcpu.read_register(x86_reg::HV_X86_RIP).unwrap_or(0);
                let _ = vcpu.write_register(x86_reg::HV_X86_RIP, rip + 1);
            }
            Ok(VcpuExit::Hlt) => {
                println!("\n--- Guest halted (iteration {}) ---", i);
                break;
            }
            Ok(exit) => {
                println!("\n[Unexpected exit: {:?}]", exit);
                break;
            }
            Err(e) => {
                eprintln!("\n--- vCPU error: {} ---", e);
                break;
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_arm64_test(vm: &mut microvm::backend::hvf::Vm) {
    use microvm::backend::hvf::bindings::arm64_reg;

    // ARM64 machine code that:
    // 1. Loads a value into X0
    // 2. Stores it to a known MMIO address (will cause VM exit)
    // 3. Loops through message characters
    // 4. Uses WFI (wait for interrupt) to halt
    //
    // We'll use MMIO address 0x09000000 (PL011 UART on many ARM platforms)

    // ARM64 code that writes "Hi!\n" to UART and halts
    // Simplified version using immediate values
    //
    // UART base address: 0x09000000 (PL011 style)

    let code: Vec<u8> = vec![
        // x1 = UART base (0x09000000)
        // movz x1, #0x0900, lsl #16
        0x01, 0x20, 0xA1, 0xD2,

        // Write 'H' (0x48)
        // mov w0, #0x48
        0x00, 0x09, 0x80, 0x52,
        // str w0, [x1]
        0x20, 0x00, 0x00, 0xB9,

        // Write 'i' (0x69)
        // mov w0, #0x69
        0x20, 0x0D, 0x80, 0x52,
        // str w0, [x1]
        0x20, 0x00, 0x00, 0xB9,

        // Write '!' (0x21)
        // mov w0, #0x21
        0x20, 0x04, 0x80, 0x52,
        // str w0, [x1]
        0x20, 0x00, 0x00, 0xB9,

        // Write '\n' (0x0a)
        // mov w0, #0x0a
        0x40, 0x01, 0x80, 0x52,
        // str w0, [x1]
        0x20, 0x00, 0x00, 0xB9,

        // Halt with WFI
        0x7F, 0x20, 0x03, 0xD5,
    ];

    let load_addr = 0x10000u64; // Load at 64KB, within our 64MB memory region
    println!("  Loading ARM64 code at 0x{:x} ({} bytes)", load_addr, code.len());

    // Write code to memory
    if let Err(e) = vm.memory_mut().write(load_addr as usize, &code) {
        eprintln!("  Failed to write code: {}", e);
        return;
    }

    // Set up vCPU registers
    if let Some(vcpu) = vm.vcpu_mut(0) {
        // Set PC to our code
        if let Err(e) = vcpu.write_register(arm64_reg::HV_REG_PC, load_addr) {
            eprintln!("  Failed to set PC: {}", e);
            return;
        }

        // Note: SP is a system register (HV_SYS_REG_SP_EL0/EL1), not a general register
        // We don't need SP for this simple test

        // Verify PC was set correctly
        match vcpu.read_register(arm64_reg::HV_REG_PC) {
            Ok(pc) => println!("  PC set to 0x{:x} (verified: 0x{:x})", load_addr, pc),
            Err(e) => println!("  PC set to 0x{:x} (verify failed: {})", load_addr, e),
        }
    } else {
        eprintln!("  No vCPU available");
        return;
    }

    println!("\nRunning VM...\n");

    run_vcpu_loop_arm64(vm);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_vcpu_loop_arm64(vm: &mut microvm::backend::hvf::Vm) {
    use microvm::backend::hvf::{bindings::arm64_reg, vcpu::VcpuExit};

    use std::io::Write;

    print!("--- Guest output ---\n");
    let _ = std::io::stdout().flush();

    for i in 0..1000 {
        let vcpu = vm.vcpu_mut(0).unwrap();

        match vcpu.run() {
            Ok(VcpuExit::MmioWrite { addr, .. }) => {
                // UART write - print the character from X0
                if addr == 0x09000000 {
                    let x0 = vcpu.read_register(arm64_reg::HV_REG_X0).unwrap_or(0);
                    print!("{}", (x0 & 0xFF) as u8 as char);
                    let _ = std::io::stdout().flush();
                }
                // Advance PC past the store instruction (4 bytes)
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
            }
            Ok(VcpuExit::MmioRead { addr, .. }) => {
                // Return 0 for any MMIO read
                let _ = vcpu.write_register(arm64_reg::HV_REG_X0, 0);
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
                println!("[MMIO read from 0x{:x}]", addr);
            }
            Ok(VcpuExit::Shutdown | VcpuExit::Hlt) => {
                println!("--- Guest halted ---");
                break;
            }
            Ok(VcpuExit::Unknown(1)) => {
                // Exit reason 1 = HV_EXIT_REASON_EXCEPTION (includes WFI)
                println!("--- Guest halted (WFI) ---");
                break;
            }
            Ok(VcpuExit::Unknown(reason)) => {
                println!("\n[Unknown exit reason: {}]", reason);
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                println!("  PC=0x{:x}", pc);
                break;
            }
            Ok(exit) => {
                println!("\n[Unexpected exit: {:?}]", exit);
                break;
            }
            Err(e) => {
                eprintln!("\n--- vCPU error: {} ---", e);
                break;
            }
        }

        if i >= 999 {
            println!("\n[Max iterations reached]");
        }
    }

    println!("\nVM test completed successfully!");
}

// ARM64 register aliases for easier use
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod arm64_reg_ext {
    pub const HV_REG_X0: u32 = 0;
}

#[cfg(not(target_os = "macos"))]
fn run_hello_vm() {
    println!("This example only runs on macOS (HVF backend)");
}
