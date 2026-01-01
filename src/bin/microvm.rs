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

#[cfg(target_arch = "aarch64")]
fn run_vm_loop(vm: &mut Vm) -> Result<(), Box<dyn std::error::Error>> {
    use microvm::backend::hvf::bindings::arm64_reg;

    let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;

    loop {
        let exit = vcpu.run()?;

        match exit {
            VcpuExit::MmioWrite { addr, syndrome, .. } => {
                // Handle UART writes
                if addr >= 0x0900_0000 && addr < 0x0900_1000 {
                    let offset = addr - 0x0900_0000;
                    if offset == 0 {
                        // UART data register
                        let srt = ((syndrome >> 16) & 0x1f) as u32;
                        let value = if srt < 31 {
                            let reg = arm64_reg::HV_REG_X0 + srt;
                            vcpu.read_register(reg).unwrap_or(0) as u8
                        } else {
                            0
                        };
                        print!("{}", value as char);
                        use std::io::Write;
                        std::io::stdout().flush().ok();
                    }
                }
                // Advance PC
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC)?;
                vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
            }
            VcpuExit::MmioRead { addr, syndrome, .. } => {
                // Handle UART reads
                let value = if addr >= 0x0900_0000 && addr < 0x0900_1000 {
                    let offset = addr - 0x0900_0000;
                    match offset {
                        0x18 => 0x00, // UART flag register - TX empty
                        _ => 0,
                    }
                } else {
                    0
                };

                // Write value to destination register
                let srt = ((syndrome >> 16) & 0x1f) as u32;
                if srt < 31 {
                    let reg = arm64_reg::HV_REG_X0 + srt;
                    vcpu.write_register(reg, value)?;
                }

                // Advance PC
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC)?;
                vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
            }
            VcpuExit::Hvc { .. } => {
                // Handle PSCI calls
                let x0 = vcpu.read_register(arm64_reg::HV_REG_X0)?;
                let result = match x0 as u32 {
                    0x84000000 => 0x00010001u64, // PSCI_VERSION -> 1.1
                    0x84000001 => 0u64,           // CPU_SUSPEND
                    0x84000009 => 0u64,           // SYSTEM_RESET
                    0x84000008 => 0u64,           // SYSTEM_OFF
                    0xC4000001 => 0u64,           // CPU_ON
                    _ => !0u64,                   // NOT_SUPPORTED
                };
                vcpu.write_register(arm64_reg::HV_REG_X0, result)?;

                // Advance PC
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC)?;
                vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
            }
            VcpuExit::Wfi => {
                // Wait for interrupt - just continue
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
            VcpuExit::VTimer => {
                // Timer interrupt
                vcpu.set_vtimer_mask(true)?;
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
