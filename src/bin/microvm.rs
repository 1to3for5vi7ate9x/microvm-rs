//! microvm CLI tool
//!
//! A command-line interface for running microVMs.

use std::path::PathBuf;
use std::process;

use microvm::backend::VmConfig;

#[cfg(target_arch = "aarch64")]
use microvm::backend::hvf::{bindings::arm64_reg, Vm, VcpuExit};

#[cfg(target_arch = "x86_64")]
use microvm::backend::hvf::{Vm, VcpuExit};

use microvm::loader::LinuxLoader;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "run" => cmd_run(&args[2..])?,
        "info" => cmd_info()?,
        "help" | "--help" | "-h" => print_usage(&args[0]),
        "version" | "--version" | "-V" => print_version(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage(&args[0]);
            process::exit(1);
        }
    }

    Ok(())
}

fn print_usage(program: &str) {
    println!(
        r#"microvm - A cross-platform microVM

USAGE:
    {} <COMMAND> [OPTIONS]

COMMANDS:
    run     Run a virtual machine
    info    Show hypervisor information
    help    Show this help message
    version Show version information

RUN OPTIONS:
    --kernel <PATH>     Path to kernel image (required)
    --initrd <PATH>     Path to initrd/initramfs
    --cmdline <STRING>  Kernel command line
    --memory <MB>       Memory size in MB (default: 512)
    --cpus <N>          Number of vCPUs (default: 1)
    --disk <PATH>       Path to disk image (virtio-blk)

EXAMPLES:
    {} run --kernel vmlinuz --initrd initrd.img --memory 1024
    {} run --kernel Image --cmdline "console=ttyAMA0"
"#,
        program, program, program
    );
}

fn print_version() {
    println!("microvm {}", env!("CARGO_PKG_VERSION"));
    let rust_version = option_env!("CARGO_PKG_RUST_VERSION")
        .filter(|v| !v.is_empty())
        .unwrap_or("unknown");
    println!("Built with Rust {}", rust_version);

    #[cfg(target_arch = "aarch64")]
    println!("Architecture: aarch64");
    #[cfg(target_arch = "x86_64")]
    println!("Architecture: x86_64");

    if let Some(backend) = microvm::backend_name() {
        println!("Hypervisor: {}", backend);
    }
}

fn cmd_info() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hypervisor Information");
    println!("======================");

    if microvm::is_supported() {
        println!("Status: Available");
        if let Some(name) = microvm::backend_name() {
            println!("Backend: {}", name);
        }
    } else {
        println!("Status: Not available");
        println!("Note: Hardware virtualization may be disabled or unsupported.");
    }

    #[cfg(target_arch = "aarch64")]
    println!("Architecture: ARM64 (aarch64)");
    #[cfg(target_arch = "x86_64")]
    println!("Architecture: x86-64");

    #[cfg(target_os = "macos")]
    println!("Platform: macOS (Hypervisor.framework)");
    #[cfg(target_os = "windows")]
    println!("Platform: Windows (WHP)");
    #[cfg(target_os = "linux")]
    println!("Platform: Linux (KVM)");

    Ok(())
}

fn cmd_run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let mut kernel_path: Option<PathBuf> = None;
    let mut initrd_path: Option<PathBuf> = None;
    let mut cmdline = String::new();
    let mut memory_mb = 512u32;
    let mut cpus = 1u32;
    let mut disk_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--kernel" | "-k" => {
                i += 1;
                if i >= args.len() {
                    return Err("--kernel requires a path".into());
                }
                kernel_path = Some(PathBuf::from(&args[i]));
            }
            "--initrd" | "-i" => {
                i += 1;
                if i >= args.len() {
                    return Err("--initrd requires a path".into());
                }
                initrd_path = Some(PathBuf::from(&args[i]));
            }
            "--cmdline" | "-c" => {
                i += 1;
                if i >= args.len() {
                    return Err("--cmdline requires a string".into());
                }
                cmdline = args[i].clone();
            }
            "--memory" | "-m" => {
                i += 1;
                if i >= args.len() {
                    return Err("--memory requires a number".into());
                }
                memory_mb = args[i].parse()?;
            }
            "--cpus" | "-n" => {
                i += 1;
                if i >= args.len() {
                    return Err("--cpus requires a number".into());
                }
                cpus = args[i].parse()?;
            }
            "--disk" | "-d" => {
                i += 1;
                if i >= args.len() {
                    return Err("--disk requires a path".into());
                }
                disk_path = Some(PathBuf::from(&args[i]));
            }
            _ => {
                // Assume it's the kernel path if no flag
                if kernel_path.is_none() {
                    kernel_path = Some(PathBuf::from(&args[i]));
                } else {
                    return Err(format!("Unknown argument: {}", args[i]).into());
                }
            }
        }
        i += 1;
    }

    let kernel_path = kernel_path.ok_or("Kernel path is required")?;

    // Check hypervisor availability
    if !microvm::is_supported() {
        return Err("Hypervisor is not available on this system".into());
    }

    println!("microvm - Starting VM");
    println!("=====================");
    println!("Kernel: {}", kernel_path.display());
    if let Some(ref initrd) = initrd_path {
        println!("Initrd: {}", initrd.display());
    }
    if let Some(ref disk) = disk_path {
        println!("Disk: {}", disk.display());
    }
    println!("Memory: {} MB", memory_mb);
    println!("vCPUs: {}", cpus);
    if !cmdline.is_empty() {
        println!("Cmdline: {}", cmdline);
    }
    println!();

    // Load kernel
    let mut loader = LinuxLoader::new(&kernel_path)?;

    if let Some(ref initrd) = initrd_path {
        loader = loader.with_initrd(initrd)?;
    }

    // Set default command line if not specified
    if cmdline.is_empty() {
        #[cfg(target_arch = "aarch64")]
        {
            cmdline = "console=ttyAMA0 earlycon=pl011,0x09000000 panic=1".to_string();
        }
        #[cfg(target_arch = "x86_64")]
        {
            cmdline = "console=ttyS0 earlyprintk=serial panic=1".to_string();
        }
    }

    if initrd_path.is_some() {
        cmdline.push_str(" rdinit=/bin/sh");
    }

    loader = loader.with_cmdline(&cmdline);

    // Create VM
    let config = VmConfig {
        memory_mb,
        vcpus: cpus,
        kernel: Some(kernel_path),
        initrd: initrd_path,
        rootfs: disk_path,
        cmdline: cmdline.clone(),
    };

    let mut vm = Vm::new(&config)?;

    // Load kernel into memory
    println!("Loading kernel...");
    let kernel_info = loader.load(vm.memory_mut())?;
    println!("  Entry: 0x{:x}", kernel_info.entry);
    println!("  Format: {:?}", kernel_info.format);

    #[cfg(target_arch = "aarch64")]
    {
        // Build device tree
        let memory_size = (memory_mb as u64) * 1024 * 1024;
        let dtb = microvm::loader::arm64::DeviceTreeBuilder::build_minimal(
            memory_size,
            loader.cmdline(),
            None, // TODO: initrd addresses
            None,
        );

        const RAM_BASE: u64 = 0x4000_0000;
        const DTB_OFFSET: usize = 0x1_0000;

        // Write DTB
        let memory = vm.memory_mut().as_mut_slice();
        memory[DTB_OFFSET..DTB_OFFSET + dtb.len()].copy_from_slice(&dtb);

        // Set up vCPU
        let vcpu = vm.vcpu_mut(0).ok_or("No vCPU available")?;
        vcpu.write_register(arm64_reg::HV_REG_PC, kernel_info.entry)?;
        vcpu.write_register(arm64_reg::HV_REG_X0, RAM_BASE + DTB_OFFSET as u64)?;
        vcpu.write_register(arm64_reg::HV_REG_X1, 0)?;
        vcpu.write_register(arm64_reg::HV_REG_X2, 0)?;
        vcpu.write_register(arm64_reg::HV_REG_X3, 0)?;
    }

    println!("\nBooting VM...");
    println!("Press Ctrl+C to exit\n");

    // Run VM loop
    run_vm_loop(&mut vm)?;

    println!("\nVM stopped.");
    Ok(())
}

/// Translate a kernel virtual address to physical address by walking page tables.
#[cfg(target_arch = "aarch64")]
fn translate_va_to_pa(memory: &[u8], ttbr: u64, va: u64) -> Option<u64> {
    const RAM_BASE: u64 = 0x4000_0000;

    let pa_to_offset = |pa: u64| -> Option<usize> {
        if pa >= RAM_BASE && (pa - RAM_BASE) < memory.len() as u64 {
            Some((pa - RAM_BASE) as usize)
        } else {
            None
        }
    };

    // 4KB granule, 4-level page tables (48-bit VA)
    let table_base = ttbr & 0x0000_FFFF_FFFF_F000;
    let va_masked = va & 0x0000_FFFF_FFFF_FFFF;

    let l0_idx = ((va_masked >> 39) & 0x1FF) as usize;
    let l1_idx = ((va_masked >> 30) & 0x1FF) as usize;
    let l2_idx = ((va_masked >> 21) & 0x1FF) as usize;
    let l3_idx = ((va_masked >> 12) & 0x1FF) as usize;
    let page_offset = (va_masked & 0xFFF) as u64;

    // L0
    let l0_offset = pa_to_offset(table_base)? + (l0_idx * 8);
    if l0_offset + 8 > memory.len() { return None; }
    let l0_desc = u64::from_le_bytes(memory[l0_offset..l0_offset+8].try_into().ok()?);
    if (l0_desc & 0x3) != 0x3 { return None; }
    let l1_table = l0_desc & 0x0000_FFFF_FFFF_F000;

    // L1
    let l1_offset = pa_to_offset(l1_table)? + (l1_idx * 8);
    if l1_offset + 8 > memory.len() { return None; }
    let l1_desc = u64::from_le_bytes(memory[l1_offset..l1_offset+8].try_into().ok()?);
    if (l1_desc & 0x3) == 0x1 {
        return Some((l1_desc & 0x0000_FFFF_C000_0000) | (va_masked & 0x3FFF_FFFF));
    }
    if (l1_desc & 0x3) != 0x3 { return None; }
    let l2_table = l1_desc & 0x0000_FFFF_FFFF_F000;

    // L2
    let l2_offset = pa_to_offset(l2_table)? + (l2_idx * 8);
    if l2_offset + 8 > memory.len() { return None; }
    let l2_desc = u64::from_le_bytes(memory[l2_offset..l2_offset+8].try_into().ok()?);
    if (l2_desc & 0x3) == 0x1 {
        return Some((l2_desc & 0x0000_FFFF_FFE0_0000) | (va_masked & 0x001F_FFFF));
    }
    if (l2_desc & 0x3) != 0x3 { return None; }
    let l3_table = l2_desc & 0x0000_FFFF_FFFF_F000;

    // L3
    let l3_offset = pa_to_offset(l3_table)? + (l3_idx * 8);
    if l3_offset + 8 > memory.len() { return None; }
    let l3_desc = u64::from_le_bytes(memory[l3_offset..l3_offset+8].try_into().ok()?);
    if (l3_desc & 0x3) != 0x3 { return None; }

    Some((l3_desc & 0x0000_FFFF_FFFF_F000) | page_offset)
}

/// Handle PSCI/SMCCC calls.
#[cfg(target_arch = "aarch64")]
fn handle_psci_call(function_id: u64) -> u64 {
    const PSCI_SUCCESS: u64 = 0;
    const PSCI_NOT_SUPPORTED: u64 = !0u64;

    match function_id {
        // SMCCC
        0x80000000 => 0x00010001,  // SMCCC_VERSION -> 1.1
        0x80000001 => PSCI_NOT_SUPPORTED,  // SMCCC_ARCH_FEATURES
        0x80000002 => PSCI_NOT_SUPPORTED,  // SMCCC_ARCH_SOC_ID
        0x80008000 | 0x80007FFF | 0x80003FFF => PSCI_NOT_SUPPORTED,  // Workarounds

        // PSCI
        0x84000000 => 0x00010000,  // PSCI_VERSION -> 1.0
        0x84000001 | 0xC4000001 => PSCI_SUCCESS,  // CPU_SUSPEND
        0x84000002 => PSCI_SUCCESS,  // CPU_OFF
        0x84000003 | 0xC4000003 => PSCI_NOT_SUPPORTED,  // CPU_ON (single CPU)
        0x84000004 | 0xC4000004 => 0,  // AFFINITY_INFO -> ON
        0x84000006 => 2,  // MIGRATE_INFO_TYPE -> no migration
        0x84000008 => PSCI_SUCCESS,  // SYSTEM_OFF
        0x84000009 => PSCI_SUCCESS,  // SYSTEM_RESET
        0x8400000A => PSCI_SUCCESS,  // PSCI_FEATURES

        // Unknown
        _ => PSCI_NOT_SUPPORTED,
    }
}

#[cfg(target_arch = "aarch64")]
fn run_vm_loop(vm: &mut Vm) -> Result<(), Box<dyn std::error::Error>> {
    use microvm::backend::hvf::bindings::{arm64_reg, arm64_sys_reg};

    const RAM_BASE: u64 = 0x4000_0000;

    loop {
        let exit = {
            let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
            vcpu.run()?
        };

        match exit {
            VcpuExit::MmioWrite { addr, syndrome, .. } => {
                let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                // Handle UART writes
                if addr >= 0x0900_0000 && addr < 0x0900_1000 {
                    let offset = addr - 0x0900_0000;
                    if offset == 0 {
                        let srt = ((syndrome >> 16) & 0x1f) as u32;
                        let value = if srt < 31 {
                            vcpu.read_register(arm64_reg::HV_REG_X0 + srt).unwrap_or(0) as u8
                        } else {
                            0
                        };
                        print!("{}", value as char);
                        use std::io::Write;
                        std::io::stdout().flush().ok();
                    }
                }
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC)?;
                vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
            }
            VcpuExit::MmioRead { addr, syndrome, .. } => {
                let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                let value = if addr >= 0x0900_0000 && addr < 0x0900_1000 {
                    match addr - 0x0900_0000 {
                        0x18 => 0x00, // UART flag register - TX empty
                        _ => 0,
                    }
                } else {
                    0
                };

                let srt = ((syndrome >> 16) & 0x1f) as u32;
                if srt < 31 {
                    vcpu.write_register(arm64_reg::HV_REG_X0 + srt, value)?;
                }
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC)?;
                vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
            }
            VcpuExit::Hvc { .. } | VcpuExit::Smc { .. } => {
                // Read registers needed for PSCI handling
                let (x0, x8, x30, pc, ttbr1) = {
                    let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                    (
                        vcpu.read_register(arm64_reg::HV_REG_X0).unwrap_or(0),
                        vcpu.read_register(arm64_reg::HV_REG_X8).unwrap_or(0),
                        vcpu.read_register(arm64_reg::HV_REG_X30).unwrap_or(0),
                        vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0),
                        vcpu.read_sys_register(arm64_sys_reg::HV_SYS_REG_TTBR1_EL1).unwrap_or(0),
                    )
                };

                let result = handle_psci_call(x0);

                // Set return value
                {
                    let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                    vcpu.write_register(arm64_reg::HV_REG_X0, result)?;
                }

                // WORKAROUND: HVF has a cache coherency issue where LDR X4, [SP]
                // returns 0 after HVC. We bypass the kernel's SMCCC wrapper by:
                // 1. Writing results directly to the result struct in guest memory
                // 2. Jumping to LR to return to the caller
                if x8 != 0 && (x8 & 0xffff_0000_0000_0000) == 0xffff_0000_0000_0000 {
                    let memory = vm.memory_mut().as_mut_slice();
                    if let Some(res_pa) = translate_va_to_pa(memory, ttbr1, x8) {
                        let offset = if res_pa >= RAM_BASE {
                            (res_pa - RAM_BASE) as usize
                        } else {
                            usize::MAX
                        };

                        if offset != usize::MAX && (offset + 32) <= memory.len() {
                            // Write SMCCC result struct: x0, x1, x2, x3
                            memory[offset..offset + 8].copy_from_slice(&result.to_le_bytes());
                            memory[offset + 8..offset + 16].copy_from_slice(&0u64.to_le_bytes());
                            memory[offset + 16..offset + 24].copy_from_slice(&0u64.to_le_bytes());
                            memory[offset + 24..offset + 32].copy_from_slice(&0u64.to_le_bytes());

                            // Skip SMCCC wrapper by jumping to LR
                            let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                            vcpu.write_register(arm64_reg::HV_REG_PC, x30)?;
                        } else {
                            let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                            vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
                        }
                    } else {
                        let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                        vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
                    }
                } else {
                    let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                    vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
                }
            }
            VcpuExit::Wfi => {
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
            VcpuExit::VTimer => {
                let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                vcpu.set_vtimer_mask(true)?;
            }
            VcpuExit::SystemRegAccess { is_write, rt, .. } => {
                // Handle system register access - skip the instruction
                let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                if !is_write {
                    // Read: return 0 for unknown registers
                    vcpu.write_register(arm64_reg::HV_REG_X0 + rt as u32, 0)?;
                }
                // Advance PC past the MSR/MRS instruction
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC)?;
                vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
            }
            VcpuExit::Breakpoint { .. } => {
                let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC)?;
                eprintln!("Breakpoint at PC=0x{:x}", pc);
                break;
            }
            VcpuExit::Exception { ec, syndrome } => {
                let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC)?;
                eprintln!("Exception EC=0x{:02x} syndrome=0x{:08x} at PC=0x{:x}", ec, syndrome, pc);
                break;
            }
            VcpuExit::Shutdown => {
                break;
            }
            VcpuExit::Hlt => {
                break;
            }
            _ => {
                eprintln!("Unhandled exit: {:?}", exit);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn run_vm_loop(vm: &mut Vm) -> Result<(), Box<dyn std::error::Error>> {
    let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;

    loop {
        let exit = vcpu.run()?;

        match exit {
            VcpuExit::IoOut { port, data } => {
                // Handle serial output
                if port == 0x3f8 && !data.is_empty() {
                    print!("{}", data[0] as char);
                    use std::io::Write;
                    std::io::stdout().flush().ok();
                }
            }
            VcpuExit::IoIn { port, size } => {
                // Handle serial input
                use microvm::backend::hvf::bindings::x86_reg;
                if port == 0x3fd {
                    // Line status register - transmitter empty
                    vcpu.write_register(x86_reg::HV_X86_RAX, 0x20)?;
                }
            }
            VcpuExit::Hlt => {
                break;
            }
            VcpuExit::Shutdown => {
                break;
            }
            _ => {
                eprintln!("Unhandled exit: {:?}", exit);
                break;
            }
        }
    }

    Ok(())
}
