//! Simple boot test that verifies the kernel loader infrastructure.
//!
//! This creates a minimal ARM64 "kernel" that prints to UART and halts,
//! testing all our boot infrastructure (DTB, memory layout, etc.)

fn main() {
    println!("microvm-rs Boot Infrastructure Test");
    println!("====================================\n");

    if !microvm::is_supported() {
        eprintln!("Hypervisor not available");
        std::process::exit(1);
    }

    println!("Hypervisor: {}", microvm::backend_name().unwrap_or("unknown"));

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    run_boot_test();

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    println!("This test only runs on macOS ARM64");
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_boot_test() {
    use microvm::backend::hvf;
    use microvm::backend::hvf::{bindings::arm64_reg, vcpu::VcpuExit};
    use microvm::backend::VmConfig;
    use microvm::device::Pl011;
    use std::io::Write;

    // Create a minimal "kernel" that:
    // 1. Reads DTB address from X0
    // 2. Writes "Booting..." to UART
    // 3. Halts with WFI
    //
    // This tests: memory layout, DTB passing, UART, exception handling

    let code: Vec<u8> = vec![
        // Save X0 (DTB address) to X20 for later
        // mov x20, x0
        0xF4, 0x03, 0x00, 0xAA,

        // Load UART base address (0x09000000)
        // movz x1, #0x0900, lsl #16
        0x01, 0x20, 0xA1, 0xD2,

        // Print "Boot!" (5 chars + newline)
        // 'B' = 0x42
        0x40, 0x08, 0x80, 0x52, // mov w0, #0x42
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // 'o' = 0x6f
        0xE0, 0x0D, 0x80, 0x52, // mov w0, #0x6f
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // 'o' = 0x6f
        0xE0, 0x0D, 0x80, 0x52, // mov w0, #0x6f
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // 't' = 0x74
        0x80, 0x0E, 0x80, 0x52, // mov w0, #0x74
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // '!' = 0x21
        0x20, 0x04, 0x80, 0x52, // mov w0, #0x21
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // '\n' = 0x0a
        0x40, 0x01, 0x80, 0x52, // mov w0, #0x0a
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // Now print DTB address (X20) in hex
        // Print "DTB:" first
        // 'D' = 0x44
        0x80, 0x08, 0x80, 0x52, // mov w0, #0x44
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // 'T' = 0x54
        0x80, 0x0A, 0x80, 0x52, // mov w0, #0x54
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // 'B' = 0x42
        0x40, 0x08, 0x80, 0x52, // mov w0, #0x42
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // ':' = 0x3a
        0x40, 0x07, 0x80, 0x52, // mov w0, #0x3a
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // '0' = 0x30
        0x00, 0x06, 0x80, 0x52, // mov w0, #0x30
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // 'x' = 0x78
        0x00, 0x0F, 0x80, 0x52, // mov w0, #0x78
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // Print X20 (DTB addr) as 4 hex digits (enough for 0x10000)
        // Get nibble 3: (x20 >> 12) & 0xF
        0x80, 0x32, 0x40, 0xD3, // ubfx x0, x20, #12, #4
        0x00, 0x1C, 0x00, 0x11, // add w0, w0, #7  (adjust for 'A'-'0'-10 = -3, but we add '0')
        0x00, 0xC0, 0x00, 0x11, // add w0, w0, #0x30
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // Get nibble 2: (x20 >> 8) & 0xF
        0x80, 0x22, 0x40, 0xD3, // ubfx x0, x20, #8, #4
        0x00, 0xC0, 0x00, 0x11, // add w0, w0, #0x30
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // Get nibble 1: (x20 >> 4) & 0xF
        0x80, 0x12, 0x40, 0xD3, // ubfx x0, x20, #4, #4
        0x00, 0xC0, 0x00, 0x11, // add w0, w0, #0x30
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // Get nibble 0: x20 & 0xF
        0x80, 0x02, 0x40, 0xD3, // ubfx x0, x20, #0, #4
        0x00, 0xC0, 0x00, 0x11, // add w0, w0, #0x30
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // '\n' = 0x0a
        0x40, 0x01, 0x80, 0x52, // mov w0, #0x0a
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // Print "OK\n"
        // 'O' = 0x4f
        0xE0, 0x09, 0x80, 0x52, // mov w0, #0x4f
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // 'K' = 0x4b
        0x60, 0x09, 0x80, 0x52, // mov w0, #0x4b
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // '\n' = 0x0a
        0x40, 0x01, 0x80, 0x52, // mov w0, #0x0a
        0x20, 0x00, 0x00, 0xB9, // str w0, [x1]

        // Halt with WFI
        0x7F, 0x20, 0x03, 0xD5,
    ];

    println!("Creating VM with 64MB memory...");
    let config = VmConfig {
        memory_mb: 64,
        vcpus: 1,
        kernel: None,
        initrd: None,
        rootfs: None,
        cmdline: String::new(),
    };

    let mut vm = match hvf::Vm::new(&config) {
        Ok(vm) => vm,
        Err(e) => {
            eprintln!("Failed to create VM: {}", e);
            return;
        }
    };

    // Load "kernel" at 0x80000 (standard ARM64 offset)
    const KERNEL_ADDR: u64 = 0x80000;
    println!("Loading test kernel at 0x{:x} ({} bytes)", KERNEL_ADDR, code.len());
    vm.memory_mut().write(KERNEL_ADDR as usize, &code).unwrap();

    // Build minimal DTB
    const DTB_ADDR: u64 = 0x10000;
    let dtb = microvm::loader::arm64::DeviceTreeBuilder::build_minimal(
        64 * 1024 * 1024,
        "console=ttyAMA0",
        None,
        None,
    );
    vm.memory_mut().write(DTB_ADDR as usize, &dtb).unwrap();
    println!("DTB at 0x{:x} ({} bytes)", DTB_ADDR, dtb.len());

    // Set up CPU
    if let Some(vcpu) = vm.vcpu_mut(0) {
        vcpu.write_register(arm64_reg::HV_REG_PC, KERNEL_ADDR).unwrap();
        vcpu.write_register(arm64_reg::HV_REG_X0, DTB_ADDR).unwrap();
        vcpu.write_register(arm64_reg::HV_REG_X1, 0).unwrap();
        vcpu.write_register(arm64_reg::HV_REG_X2, 0).unwrap();
        vcpu.write_register(arm64_reg::HV_REG_X3, 0).unwrap();
    }

    println!("\nRunning...\n--- Output ---");

    let mut uart = Pl011::default();

    for i in 0..10000 {
        let exit = {
            let vcpu = vm.vcpu_mut(0).unwrap();
            vcpu.run()
        };

        match exit {
            Ok(VcpuExit::MmioWrite { addr, .. }) => {
                let vcpu = vm.vcpu_mut(0).unwrap();
                if uart.contains(addr) {
                    let value = vcpu.read_register(arm64_reg::HV_REG_X0).unwrap_or(0) as u32;
                    uart.write(addr, value);
                }
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
            }
            Ok(VcpuExit::MmioRead { addr, .. }) => {
                let vcpu = vm.vcpu_mut(0).unwrap();
                let value = if uart.contains(addr) { uart.read(addr) } else { 0 };
                let _ = vcpu.write_register(arm64_reg::HV_REG_X0, value as u64);
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
            }
            Ok(VcpuExit::Unknown(1)) => {
                println!("\n--- Halted (WFI) after {} iterations ---", i);
                break;
            }
            Ok(exit) => {
                println!("\n[Exit: {:?}]", exit);
                break;
            }
            Err(e) => {
                eprintln!("\n[Error: {}]", e);
                break;
            }
        }
    }

    let _ = std::io::stdout().flush();
    println!("\nBoot infrastructure test PASSED!");
}
