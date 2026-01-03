//! microvm CLI tool
//!
//! A command-line interface for running microVMs.

use std::io::Write;
use std::path::PathBuf;
use std::process;

use microvm::backend::VmConfig;

#[cfg(target_arch = "aarch64")]
use microvm::backend::hvf::{bindings::arm64_reg, Vm, VcpuExit};
#[cfg(target_arch = "aarch64")]
use microvm::device::virtio::{VirtioBlk, VirtioConsole, VirtioMmioTransport, VirtioVsock, VirtioNet, NullBackend};

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
    --console           Enable VirtIO console for interactive shell
    --net               Enable VirtIO network (null backend, vmnet disabled)

EXAMPLES:
    {} run --kernel vmlinuz --initrd initrd.img --memory 1024
    {} run --kernel Image --cmdline "console=hvc0" --console
    {} run --kernel Image --net --console
"#,
        program, program, program, program
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
    let mut enable_console = false;
    let mut enable_net = false;

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
            "--console" => {
                enable_console = true;
            }
            "--net" | "--network" => {
                enable_net = true;
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
    if enable_console {
        println!("Console: VirtIO console (hvc0)");
    }
    if enable_net {
        println!("Network: VirtIO net (null backend - vmnet disabled)");
    }
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
            // Always use PL011 (ttyAMA0) as initial console so init can output
            // The init script will switch to hvc0 after loading virtio modules
            cmdline = "console=ttyAMA0 earlycon=pl011,0x09000000 rdinit=/init panic=1".to_string();
        }
        #[cfg(target_arch = "x86_64")]
        {
            cmdline = "console=ttyS0 earlyprintk=serial panic=1".to_string();
        }
    }

    // Note: The initrd's /init will run by default.
    // To force an interactive shell, use: --cmdline "... rdinit=/bin/sh"

    loader = loader.with_cmdline(&cmdline);

    // Create VM
    let config = VmConfig {
        memory_mb,
        vcpus: cpus,
        kernel: Some(kernel_path),
        initrd: initrd_path,
        rootfs: disk_path.clone(),
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
        // Build device tree with initrd addresses and VirtIO devices
        let memory_size = (memory_mb as u64) * 1024 * 1024;
        let has_block = disk_path.is_some();
        let has_vsock = true;  // vsock always enabled for host-guest communication
        let dtb = microvm::loader::arm64::DeviceTreeBuilder::build_with_devices(
            memory_size,
            loader.cmdline(),
            kernel_info.initrd_start,
            kernel_info.initrd_end,
            enable_console,
            has_block,
            has_vsock,
            enable_net,
        );

        if let (Some(start), Some(end)) = (kernel_info.initrd_start, kernel_info.initrd_end) {
            println!("  Initrd: 0x{:x} - 0x{:x} ({} bytes)", start, end, end - start);
        }

        const RAM_BASE: u64 = 0x4000_0000;
        const DTB_OFFSET: usize = 0x1_0000;

        // Write DTB (and save to file for debugging)
        let memory = vm.memory_mut().as_mut_slice();
        memory[DTB_OFFSET..DTB_OFFSET + dtb.len()].copy_from_slice(&dtb);

        // Debug: save DTB to file
        if let Err(e) = std::fs::write("/tmp/microvm.dtb", &dtb) {
            eprintln!("Warning: Could not save DTB: {}", e);
        } else {
            eprintln!("DTB saved to /tmp/microvm.dtb ({} bytes)", dtb.len());
        }

        // Set up vCPU
        let vcpu = vm.vcpu_mut(0).ok_or("No vCPU available")?;
        vcpu.write_register(arm64_reg::HV_REG_PC, kernel_info.entry)?;
        vcpu.write_register(arm64_reg::HV_REG_X0, RAM_BASE + DTB_OFFSET as u64)?;
        vcpu.write_register(arm64_reg::HV_REG_X1, 0)?;
        vcpu.write_register(arm64_reg::HV_REG_X2, 0)?;
        vcpu.write_register(arm64_reg::HV_REG_X3, 0)?;
    }

    println!("\nBooting VM...");
    if enable_console {
        println!("Interactive VirtIO console enabled. Type to send input.\n");
    } else {
        println!("Press Ctrl+C to exit\n");
    }

    // Run VM loop
    run_vm_loop(&mut vm, enable_console, enable_net, disk_path)?;

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

// Terminal handling for interactive console
#[cfg(unix)]
static ORIGINAL_TERMIOS: std::sync::Mutex<Option<libc::termios>> = std::sync::Mutex::new(None);

#[cfg(unix)]
fn setup_raw_terminal() -> Result<bool, Box<dyn std::error::Error>> {
    use std::os::unix::io::AsRawFd;

    unsafe {
        let fd = std::io::stdin().as_raw_fd();

        // Check if stdin is a TTY
        if libc::isatty(fd) == 0 {
            // Not a TTY - console output will still work, but no input
            eprintln!("Note: stdin is not a TTY, console input disabled");
            return Ok(false);
        }

        let mut termios: libc::termios = std::mem::zeroed();

        if libc::tcgetattr(fd, &mut termios) != 0 {
            eprintln!("Warning: Failed to get terminal attributes, console input disabled");
            return Ok(false);
        }

        // Save original settings
        *ORIGINAL_TERMIOS.lock().unwrap() = Some(termios);

        // Set raw mode
        termios.c_lflag &= !(libc::ICANON | libc::ECHO);
        termios.c_cc[libc::VMIN] = 0;
        termios.c_cc[libc::VTIME] = 0;

        if libc::tcsetattr(fd, libc::TCSANOW, &termios) != 0 {
            eprintln!("Warning: Failed to set terminal attributes, console input disabled");
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(unix)]
fn restore_terminal() {
    use std::os::unix::io::AsRawFd;

    if let Some(termios) = ORIGINAL_TERMIOS.lock().unwrap().take() {
        unsafe {
            let fd = std::io::stdin().as_raw_fd();
            libc::tcsetattr(fd, libc::TCSANOW, &termios);
        }
    }
}

#[cfg(unix)]
fn read_stdin_nonblocking() -> Option<Vec<u8>> {
    use std::os::unix::io::AsRawFd;

    let mut buf = [0u8; 64];
    let fd = std::io::stdin().as_raw_fd();

    unsafe {
        let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        if n > 0 {
            return Some(buf[..n as usize].to_vec());
        }
    }

    None
}

#[cfg(not(unix))]
fn setup_raw_terminal() -> Result<bool, Box<dyn std::error::Error>> {
    Ok(false)
}

#[cfg(not(unix))]
fn restore_terminal() {}

#[cfg(not(unix))]
fn read_stdin_nonblocking() -> Option<Vec<u8>> {
    None
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
fn run_vm_loop(
    vm: &mut Vm,
    enable_console: bool,
    enable_net: bool,
    disk_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use microvm::backend::hvf::bindings::{arm64_reg, arm64_sys_reg};
    use microvm::device::virtio::mmio;

    const RAM_BASE: u64 = 0x4000_0000;
    const UART_BASE: u64 = 0x0900_0000;
    const VIRTIO_CONSOLE_BASE: u64 = 0x0a00_0000;
    const VIRTIO_BLK_BASE: u64 = 0x0a00_0200;  // Next VirtIO device slot
    const VIRTIO_VSOCK_BASE: u64 = 0x0a00_0400;  // Next VirtIO device slot
    const VIRTIO_NET_BASE: u64 = 0x0a00_0600;   // Network device slot
    const VIRTIO_SIZE: u64 = 0x200;

    // GIC (Generic Interrupt Controller) addresses
    const GIC_DIST_BASE: u64 = 0x0800_0000;  // Distributor
    const GIC_CPU_BASE: u64 = 0x0801_0000;   // CPU interface
    const GIC_SIZE: u64 = 0x1_0000;

    // PL011 UART registers
    const UART_DR: u64 = 0x00;     // Data register
    const UART_FR: u64 = 0x18;     // Flag register
    const UART_IBRD: u64 = 0x24;   // Integer baud rate
    const UART_FBRD: u64 = 0x28;   // Fractional baud rate
    const UART_LCR_H: u64 = 0x2C;  // Line control
    const UART_CR: u64 = 0x30;     // Control register
    const UART_IMSC: u64 = 0x38;   // Interrupt mask

    // Flag register bits
    const FR_RXFE: u32 = 1 << 4;   // RX FIFO empty

    // GIC Distributor registers
    const GICD_CTLR: u64 = 0x000;    // Control register
    const GICD_TYPER: u64 = 0x004;   // Type register
    const GICD_IIDR: u64 = 0x008;    // Implementer ID

    // GIC CPU interface registers
    const GICC_CTLR: u64 = 0x000;    // Control register
    const GICC_PMR: u64 = 0x004;     // Priority mask
    const GICC_IAR: u64 = 0x00C;     // Interrupt acknowledge
    const GICC_EOIR: u64 = 0x010;    // End of interrupt

    // GIC state
    let mut gic_dist_ctrl: u32 = 0;
    let mut gic_cpu_ctrl: u32 = 0;
    let mut gic_pmr: u32 = 0xFF;  // All priorities enabled

    // Pending interrupt tracking
    let mut virtio_irq_pending: bool = false;  // Track pending VirtIO interrupt
    let mut timer_irq_pending: bool = false;   // Track pending timer interrupt
    const VIRTIO_IRQ: u32 = 32 + 16;  // SPI 16 = IRQ 48
    const VTIMER_IRQ: u32 = 16 + 11;  // PPI 11 = IRQ 27 (virtual timer)

    // Create VirtIO console transport if enabled
    let mut virtio_console = if enable_console {
        Some(VirtioMmioTransport::new(VirtioConsole::new(), VIRTIO_CONSOLE_BASE))
    } else {
        None
    };

    // Create VirtIO block transport if disk is specified
    let mut virtio_blk = if let Some(ref path) = disk_path {
        match VirtioBlk::from_file(path) {
            Ok(blk) => {
                println!("Block device: {} ({} bytes)", path.display(), blk.capacity());
                Some(VirtioMmioTransport::new(blk, VIRTIO_BLK_BASE))
            }
            Err(e) => {
                eprintln!("Warning: Failed to open disk image: {}", e);
                None
            }
        }
    } else {
        None
    };
    let mut blk_irq_pending: bool = false;  // Track pending block interrupt
    let mut vsock_irq_pending: bool = false;  // Track pending vsock interrupt
    let mut net_irq_pending: bool = false;   // Track pending network interrupt
    const BLK_IRQ: u32 = 32 + 17;  // SPI 17 = IRQ 49
    const VSOCK_IRQ: u32 = 32 + 18;  // SPI 18 = IRQ 50
    const NET_IRQ: u32 = 32 + 19;  // SPI 19 = IRQ 51

    // Create VirtIO vsock device (always enabled for host-guest communication)
    const GUEST_CID: u64 = 3;  // Guest CID (first available after host=2)
    let mut virtio_vsock = Some(VirtioMmioTransport::new(VirtioVsock::new(GUEST_CID), VIRTIO_VSOCK_BASE));
    println!("Vsock: CID {} at 0x{:x}", GUEST_CID, VIRTIO_VSOCK_BASE);

    // Create VirtIO network device if enabled
    // Note: vmnet backend is disabled due to entitlement issues with ad-hoc signing.
    // Using NullBackend as a placeholder until proper code signing is implemented.
    let mut virtio_net = if enable_net {
        let backend = NullBackend;
        let net = VirtioNet::with_backend(Box::new(backend));
        println!("Network: at 0x{:x} (null backend - vmnet disabled)", VIRTIO_NET_BASE);
        Some(VirtioMmioTransport::new(net, VIRTIO_NET_BASE))
    } else {
        None
    };

    // Set up non-blocking stdin for console input
    let stdin_enabled = if enable_console {
        setup_raw_terminal()?
    } else {
        false
    };

    // Cleanup guard for terminal settings
    struct TerminalGuard;
    impl Drop for TerminalGuard {
        fn drop(&mut self) {
            restore_terminal();
        }
    }
    let _guard = if stdin_enabled {
        Some(TerminalGuard)
    } else {
        None
    };

    loop {
        // Check for stdin input if console is enabled
        if stdin_enabled {
            if let Some(input) = read_stdin_nonblocking() {
                if let Some(ref mut transport) = virtio_console {
                    transport.device_mut().queue_input(&input);
                }
            }
        }

        // Process VirtIO console RX (deliver input to guest)
        let mut need_irq = false;
        if let Some(ref mut transport) = virtio_console {
            if transport.device().has_pending_input() {
                // Clone queue config from transport to device
                if let Some(rx_queue) = transport.queue(0).cloned() {
                    transport.device_mut().sync_rx_queue(&rx_queue);
                }
                let memory = vm.memory_mut().as_mut_slice();
                if transport.device_mut().process_rx(memory) {
                    transport.signal_interrupt();
                    virtio_irq_pending = true;  // Set GIC pending flag
                    need_irq = true;
                }
            }
        }

        // Inject IRQ to wake guest if we have pending VirtIO interrupt
        if need_irq {
            if let Some(vcpu) = vm.vcpu_mut(0) {
                use microvm::backend::hvf::bindings::arm64_interrupt::HV_INTERRUPT_TYPE_IRQ;
                let _ = vcpu.set_pending_interrupt(HV_INTERRUPT_TYPE_IRQ, true);
            }
        }

        let exit = {
            let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
            vcpu.run()?
        };

        match exit {
            VcpuExit::MmioWrite { addr, syndrome, .. } => {
                // Read register value from vCPU
                let (value, pc) = {
                    let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                    let srt = ((syndrome >> 16) & 0x1f) as u32;
                    let value = if srt < 31 {
                        vcpu.read_register(arm64_reg::HV_REG_X0 + srt).unwrap_or(0) as u32
                    } else {
                        0
                    };
                    let pc = vcpu.read_register(arm64_reg::HV_REG_PC)?;
                    (value, pc)
                };

                // Handle VirtIO Console MMIO writes
                if addr >= VIRTIO_CONSOLE_BASE && addr < VIRTIO_CONSOLE_BASE + VIRTIO_SIZE {
                    if let Some(ref mut transport) = virtio_console {
                        let offset = addr - VIRTIO_CONSOLE_BASE;

                        transport.write(addr, value);

                        // Handle queue notify - process queues
                        if offset == mmio::QUEUE_NOTIFY as u64 {
                            let notified_queue = value;

                            // Process RX queue (queue 0) - guest posted buffers for input
                            if notified_queue == 0 {
                                // Sync queue config and process any pending input
                                if let Some(rx_queue) = transport.queue(0).cloned() {
                                    transport.device_mut().sync_rx_queue(&rx_queue);
                                }
                                if transport.device().has_pending_input() {
                                    let memory = vm.memory_mut().as_mut_slice();
                                    if transport.device_mut().process_rx(memory) {
                                        transport.signal_interrupt();
                                    }
                                }
                            }

                            // Process TX queue (queue 1) for output
                            if notified_queue == 1 {
                                // Clone queue config from transport to device
                                if let Some(tx_queue) = transport.queue(1).cloned() {
                                    transport.device_mut().sync_tx_queue(&tx_queue);
                                }
                                let memory = vm.memory_mut().as_mut_slice();
                                let output = transport.device_mut().process_tx(memory);
                                if !output.is_empty() {
                                    let _ = std::io::stdout().write_all(&output);
                                    let _ = std::io::stdout().flush();
                                    transport.signal_interrupt();
                                }
                            }
                        }
                    }
                }
                // Handle VirtIO Block MMIO writes
                else if addr >= VIRTIO_BLK_BASE && addr < VIRTIO_BLK_BASE + VIRTIO_SIZE {
                    if let Some(ref mut transport) = virtio_blk {
                        let offset = addr - VIRTIO_BLK_BASE;

                        transport.write(addr, value);

                        // Handle queue notify - process block requests
                        if offset == mmio::QUEUE_NOTIFY as u64 {
                            // Clone queue config first to avoid borrow conflict
                            let queue_config = transport.queue(0).cloned();

                            // Sync queue config from transport to device
                            if let Some(queue) = queue_config {
                                let dev_queue = transport.device_mut().queue_mut();
                                dev_queue.desc_table = queue.desc_table;
                                dev_queue.avail_ring = queue.avail_ring;
                                dev_queue.used_ring = queue.used_ring;
                                dev_queue.size = queue.size;
                                dev_queue.ready = queue.ready;
                            }
                            // Process all pending block requests
                            let memory = vm.memory_mut().as_mut_slice();
                            if transport.device_mut().process_queue(memory) {
                                transport.signal_interrupt();
                                blk_irq_pending = true;
                            }
                        }
                    }
                }
                // Handle VirtIO Vsock MMIO writes
                else if addr >= VIRTIO_VSOCK_BASE && addr < VIRTIO_VSOCK_BASE + VIRTIO_SIZE {
                    if let Some(ref mut transport) = virtio_vsock {
                        let offset = addr - VIRTIO_VSOCK_BASE;

                        transport.write(addr, value);

                        // Handle queue notify
                        if offset == mmio::QUEUE_NOTIFY as u64 {
                            let notified_queue = value;

                            // Clone queue configs first to avoid borrow conflict
                            let rx_queue_config = transport.queue(0).cloned();
                            let tx_queue_config = transport.queue(1).cloned();
                            let event_queue_config = transport.queue(2).cloned();

                            // Sync queue configs from transport to device
                            if let Some(queue) = rx_queue_config {
                                transport.device_mut().sync_rx_queue(&queue);
                            }
                            if let Some(queue) = tx_queue_config {
                                transport.device_mut().sync_tx_queue(&queue);
                            }
                            if let Some(queue) = event_queue_config {
                                transport.device_mut().sync_event_queue(&queue);
                            }

                            // Process RX queue (queue 0) - send pending packets to guest
                            if notified_queue == 0 {
                                if transport.device().has_rx_data() {
                                    let memory = vm.memory_mut().as_mut_slice();
                                    if transport.device_mut().process_rx(memory) {
                                        transport.signal_interrupt();
                                        vsock_irq_pending = true;
                                    }
                                }
                            }

                            // Process TX queue (queue 1) - receive packets from guest
                            if notified_queue == 1 {
                                let memory = vm.memory_mut().as_mut_slice();
                                let packets = transport.device_mut().process_tx(memory);
                                if !packets.is_empty() {
                                    // Packets received from guest - could process here
                                    // For now, just signal interrupt
                                    transport.signal_interrupt();
                                    vsock_irq_pending = true;
                                }
                            }
                        }
                    }
                }
                // Handle VirtIO Network MMIO writes
                else if addr >= VIRTIO_NET_BASE && addr < VIRTIO_NET_BASE + VIRTIO_SIZE {
                    if let Some(ref mut transport) = virtio_net {
                        let offset = addr - VIRTIO_NET_BASE;

                        transport.write(addr, value);

                        // Handle queue notify
                        if offset == mmio::QUEUE_NOTIFY as u64 {
                            let notified_queue = value;

                            // RX queue (queue 0) - send pending packets to guest
                            if notified_queue == 0 {
                                if transport.device().has_rx_data() {
                                    let memory = vm.memory_mut().as_mut_slice();
                                    // TODO: Implement proper RX processing
                                    transport.signal_interrupt();
                                    net_irq_pending = true;
                                }
                            }

                            // TX queue (queue 1) - receive packets from guest
                            if notified_queue == 1 {
                                // TODO: Implement proper TX processing
                                transport.signal_interrupt();
                                net_irq_pending = true;
                            }
                        }
                    }
                }
                // Handle PL011 UART writes (for earlycon)
                else if addr >= UART_BASE && addr < UART_BASE + 0x1000 {
                    let offset = addr - UART_BASE;
                    match offset {
                        UART_DR => {
                            // TX data - write character to stdout
                            let ch = (value & 0xFF) as u8;
                            let _ = std::io::stdout().write_all(&[ch]);
                            let _ = std::io::stdout().flush();
                        }
                        UART_IBRD | UART_FBRD | UART_LCR_H | UART_CR | UART_IMSC => {
                            // Ignore configuration writes for now
                        }
                        _ => {}
                    }
                }
                // Handle GIC Distributor writes
                else if addr >= GIC_DIST_BASE && addr < GIC_DIST_BASE + GIC_SIZE {
                    let offset = addr - GIC_DIST_BASE;
                    match offset {
                        GICD_CTLR => {
                            gic_dist_ctrl = value;
                        }
                        _ => {
                            // Accept all other GIC distributor writes (interrupt config, enables, etc.)
                            // This allows the kernel to configure interrupts without errors
                        }
                    }
                }
                // Handle GIC CPU interface writes
                else if addr >= GIC_CPU_BASE && addr < GIC_CPU_BASE + GIC_SIZE {
                    let offset = addr - GIC_CPU_BASE;
                    match offset {
                        GICC_CTLR => {
                            gic_cpu_ctrl = value;
                        }
                        GICC_PMR => {
                            gic_pmr = value;
                        }
                        GICC_EOIR => {
                            // End of interrupt - unmask timer if it was the timer IRQ
                            if value == VTIMER_IRQ {
                                // Unmask the vtimer so we can get the next timer interrupt
                                if let Some(vcpu) = vm.vcpu_mut(0) {
                                    let _ = vcpu.set_vtimer_mask(false);
                                }
                            }
                        }
                        _ => {
                            // Accept all other GIC CPU interface writes
                        }
                    }
                }

                // Advance PC
                let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
            }
            VcpuExit::MmioRead { addr, syndrome, .. } => {
                // Track if we need to reassert IRQ after handling this read
                let mut reassert_irq = false;

                // Handle VirtIO Console MMIO reads
                let value = if addr >= VIRTIO_CONSOLE_BASE && addr < VIRTIO_CONSOLE_BASE + VIRTIO_SIZE {
                    if let Some(ref transport) = virtio_console {
                        transport.read(addr) as u64
                    } else {
                        0
                    }
                }
                // Handle VirtIO Block MMIO reads
                else if addr >= VIRTIO_BLK_BASE && addr < VIRTIO_BLK_BASE + VIRTIO_SIZE {
                    if let Some(ref transport) = virtio_blk {
                        transport.read(addr) as u64
                    } else {
                        0
                    }
                }
                // Handle VirtIO Vsock MMIO reads
                else if addr >= VIRTIO_VSOCK_BASE && addr < VIRTIO_VSOCK_BASE + VIRTIO_SIZE {
                    if let Some(ref transport) = virtio_vsock {
                        transport.read(addr) as u64
                    } else {
                        0
                    }
                }
                // Handle VirtIO Network MMIO reads
                else if addr >= VIRTIO_NET_BASE && addr < VIRTIO_NET_BASE + VIRTIO_SIZE {
                    if let Some(ref transport) = virtio_net {
                        transport.read(addr) as u64
                    } else {
                        0
                    }
                }
                // Handle PL011 UART reads (for earlycon)
                else if addr >= UART_BASE && addr < UART_BASE + 0x1000 {
                    let offset = addr - UART_BASE;
                    match offset {
                        UART_DR => 0, // No input from PL011 when using VirtIO
                        UART_FR => FR_RXFE as u64, // RX FIFO always empty
                        _ => 0,
                    }
                }
                // Handle GIC Distributor reads
                else if addr >= GIC_DIST_BASE && addr < GIC_DIST_BASE + GIC_SIZE {
                    let offset = addr - GIC_DIST_BASE;
                    match offset {
                        GICD_CTLR => gic_dist_ctrl as u64,
                        GICD_TYPER => {
                            // Type register: ITLinesNumber=2 (96 interrupts), CPUNumber=0 (1 CPU)
                            0x0000_0002
                        }
                        GICD_IIDR => {
                            // Implementer ID: ARM (0x43B), revision 2
                            0x0200_043B
                        }
                        _ => {
                            // Default: return 0 for other registers
                            0
                        }
                    }
                }
                // Handle GIC CPU interface reads
                else if addr >= GIC_CPU_BASE && addr < GIC_CPU_BASE + GIC_SIZE {
                    let offset = addr - GIC_CPU_BASE;
                    match offset {
                        GICC_CTLR => gic_cpu_ctrl as u64,
                        GICC_PMR => gic_pmr as u64,
                        GICC_IAR => {
                            // Return highest priority pending interrupt
                            // Priority: timer > console > block > vsock
                            let irq = if timer_irq_pending {
                                timer_irq_pending = false;  // Clear on acknowledge
                                VTIMER_IRQ
                            } else if virtio_irq_pending {
                                virtio_irq_pending = false;  // Clear on acknowledge
                                VIRTIO_IRQ
                            } else if blk_irq_pending {
                                blk_irq_pending = false;  // Clear on acknowledge
                                BLK_IRQ
                            } else if vsock_irq_pending {
                                vsock_irq_pending = false;  // Clear on acknowledge
                                VSOCK_IRQ
                            } else if net_irq_pending {
                                net_irq_pending = false;  // Clear on acknowledge
                                NET_IRQ
                            } else {
                                1023  // Spurious interrupt
                            };

                            // If there are still pending interrupts, keep IRQ asserted
                            if timer_irq_pending || virtio_irq_pending || blk_irq_pending || vsock_irq_pending || net_irq_pending {
                                reassert_irq = true;
                            }

                            irq as u64
                        }
                        _ => 0,
                    }
                } else {
                    0
                };

                // Now we can safely borrow vcpu
                let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;

                // Reassert IRQ if there are still pending interrupts
                if reassert_irq {
                    use microvm::backend::hvf::bindings::arm64_interrupt::HV_INTERRUPT_TYPE_IRQ;
                    let _ = vcpu.set_pending_interrupt(HV_INTERRUPT_TYPE_IRQ, true);
                }

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
                // Only sleep if no interrupts pending - otherwise wake immediately
                if !timer_irq_pending && !virtio_irq_pending && !blk_irq_pending && !vsock_irq_pending && !net_irq_pending {
                    std::thread::sleep(std::time::Duration::from_micros(100));
                }
            }
            VcpuExit::VTimer => {
                // Timer fired - inject IRQ to guest and mask until acknowledged
                timer_irq_pending = true;
                let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                vcpu.set_vtimer_mask(true)?;  // Mask timer until guest acknowledges
                // Inject IRQ to wake the guest
                use microvm::backend::hvf::bindings::arm64_interrupt::HV_INTERRUPT_TYPE_IRQ;
                vcpu.set_pending_interrupt(HV_INTERRUPT_TYPE_IRQ, true)?;
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
fn run_vm_loop(
    vm: &mut Vm,
    _enable_console: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;

    loop {
        let exit = vcpu.run()?;

        match exit {
            VcpuExit::IoOut { port, data } => {
                // Handle serial output
                if port == 0x3f8 && !data.is_empty() {
                    print!("{}", data[0] as char);
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
