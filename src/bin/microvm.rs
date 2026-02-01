//! microvm CLI tool
//!
//! A command-line interface for running microVMs.

use std::io::Write;
use std::path::PathBuf;
use std::process;

use microvm::backend::VmConfig;

// macOS ARM64 (Apple Silicon)
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use microvm::backend::hvf::{bindings::arm64_reg, Vm, VcpuExit};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use microvm::device::virtio::{VirtioBlk, VirtioConsole, VirtioMmioTransport, VirtioVsock, VirtioNet, NullBackend};

// macOS x86_64 (Intel)
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
use microvm::backend::hvf::{Vm, VcpuExit};

// Windows
#[cfg(target_os = "windows")]
use microvm::backend::whp::{Vm, VcpuExit};
#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::*;

use microvm::loader::LinuxLoader;
use microvm::proxy::{ProxyConnectionManager, OUTBOUND_PROXY_PORT};

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
    let mut loader = LinuxLoader::new(&kernel_path)?
        .with_memory_mb(memory_mb);

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

    // x86_64 vCPU setup (Windows WHP or macOS Intel)
    #[cfg(target_arch = "x86_64")]
    {
        if let (Some(start), Some(end)) = (kernel_info.initrd_start, kernel_info.initrd_end) {
            println!("  Initrd: 0x{:x} - 0x{:x} ({} bytes)", start, end, end - start);
        }

        // Set up page tables for 64-bit long mode
        // We create identity-mapped page tables at physical address 0x1000
        setup_page_tables(vm.memory_mut().as_mut_slice())?;

        // Set up GDT at 0x500
        setup_gdt(vm.memory_mut().as_mut_slice())?;

        // Initialize vCPU for long mode
        const BOOT_PARAMS_ADDR: u64 = 0x10000;
        let vcpu = vm.vcpu_mut(0).ok_or("No vCPU available")?;
        vcpu.init_long_mode(kernel_info.entry, BOOT_PARAMS_ADDR)?;
        println!("  vCPU initialized for 64-bit long mode");
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

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
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
    const UART_IMSC: u64 = 0x38;   // Interrupt mask set/clear
    const UART_RIS: u64 = 0x3C;    // Raw interrupt status
    const UART_MIS: u64 = 0x40;    // Masked interrupt status
    const UART_ICR: u64 = 0x44;    // Interrupt clear

    // Flag register bits
    const FR_RXFE: u32 = 1 << 4;   // RX FIFO empty

    // Interrupt bits (for RIS, MIS, IMSC, ICR)
    const INT_RXIS: u32 = 1 << 4;  // Receive interrupt
    const INT_TXIS: u32 = 1 << 5;  // Transmit interrupt

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
    let mut uart_irq_pending: bool = false;    // Track pending UART RX interrupt
    const VIRTIO_IRQ: u32 = 32 + 16;  // SPI 16 = IRQ 48
    const VTIMER_IRQ: u32 = 16 + 11;  // PPI 11 = IRQ 27 (virtual timer)
    const UART_IRQ: u32 = 32 + 1;     // SPI 1 = IRQ 33 (PL011 UART)

    // UART RX buffer for stdin input (when not using VirtIO console)
    let mut uart_rx_buffer: std::collections::VecDeque<u8> = std::collections::VecDeque::new();
    // UART interrupt mask (IMSC) - controls which interrupts are enabled
    // The kernel will set this to enable RX interrupts
    let mut uart_imsc: u32 = 0;

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
    const VSOCK_ECHO_PORT: u32 = 1234;  // Echo server port for testing
    let mut vsock_device = VirtioVsock::new(GUEST_CID);
    vsock_device.listen(VSOCK_ECHO_PORT);  // Enable echo server on port 1234
    vsock_device.listen(OUTBOUND_PROXY_PORT);  // Enable outbound proxy on port 7601
    let mut virtio_vsock = Some(VirtioMmioTransport::new(vsock_device, VIRTIO_VSOCK_BASE));
    println!("Vsock: CID {} at 0x{:x} (echo:{}, proxy:{})", GUEST_CID, VIRTIO_VSOCK_BASE, VSOCK_ECHO_PORT, OUTBOUND_PROXY_PORT);

    // Create proxy connection manager for outbound internet access
    let mut proxy_manager = ProxyConnectionManager::new();

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

    // Set up non-blocking stdin for console input (UART or VirtIO console)
    // Always enable stdin for interactive use
    let stdin_enabled = setup_raw_terminal()?;

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
        // Check for stdin input
        if stdin_enabled {
            if let Some(input) = read_stdin_nonblocking() {
                if let Some(ref mut transport) = virtio_console {
                    // VirtIO console mode: send to hvc0
                    transport.device_mut().queue_input(&input);
                } else {
                    // UART mode: send to PL011 (ttyAMA0)
                    for byte in input {
                        if uart_rx_buffer.len() < 16 {
                            uart_rx_buffer.push_back(byte);
                        }
                    }
                    // Signal UART RX interrupt
                    if !uart_rx_buffer.is_empty() {
                        uart_irq_pending = true;
                    }
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

        // Poll TCP connections for incoming data (outbound proxy)
        if proxy_manager.has_connections() {
            let tcp_data = proxy_manager.poll_tcp();
            for (_conn_key, data) in tcp_data {
                if let Some(ref mut transport) = virtio_vsock {
                    // Find the guest's port that connected to us on 7601
                    let target_conn = transport.device_mut().connections()
                        .find(|(key, _)| key.local_port == OUTBOUND_PROXY_PORT)
                        .map(|(_, conn)| (conn.peer_cid, conn.peer_port));

                    if let Some((_peer_cid, peer_port)) = target_conn {
                        eprintln!("[PROXY] Sending {} bytes to guest port {}", data.len(), peer_port);
                        transport.device_mut().queue_data_packet(
                            GUEST_CID,
                            peer_port,
                            OUTBOUND_PROXY_PORT,
                            &data,
                        );

                        // Deliver the data immediately
                        let memory = vm.memory_mut().as_mut_slice();
                        if transport.device_mut().process_rx(memory) {
                            transport.signal_interrupt();
                            vsock_irq_pending = true;
                        }
                    }
                }
            }
        }

        // PROACTIVE: Poll vsock TX queue to catch packets without QUEUE_NOTIFY
        // This handles cases where the kernel queues packets but doesn't notify immediately
        if let Some(ref mut transport) = virtio_vsock {
            // Only poll if TX queue is ready
            if transport.device().tx_queue_ready() {
                // Sync queue configs
                if let Some(queue) = transport.queue(1).cloned() {
                    transport.device_mut().sync_tx_queue(&queue);
                }

                // Try to process TX queue
                let memory = vm.memory_mut().as_mut_slice();
                let packets = transport.device_mut().process_tx(memory);
                if !packets.is_empty() {
                    eprintln!("[VSOCK-POLL] Proactive TX poll found {} packets!", packets.len());
                    transport.signal_interrupt();
                    vsock_irq_pending = true;

                    // Process packets - route to proxy or echo based on port
                    for pkt in &packets {
                        if pkt.len() >= 44 {
                            let op = u16::from_le_bytes([pkt[30], pkt[31]]);
                            let src_port = u32::from_le_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
                            let dst_port = u32::from_le_bytes([pkt[20], pkt[21], pkt[22], pkt[23]]);

                            eprintln!("[VSOCK-POLL] Packet: op={} src_port={} dst_port={}", op, src_port, dst_port);

                            if op == 5 { // RW (data packet)
                                let payload = &pkt[44..];
                                if !payload.is_empty() && dst_port == OUTBOUND_PROXY_PORT {
                                    eprintln!("[PROXY-POLL] Received {} bytes from guest port {}", payload.len(), src_port);
                                    let responses = proxy_manager.process_incoming(payload);
                                    for resp in responses {
                                        transport.device_mut().queue_data_packet(
                                            GUEST_CID,
                                            src_port,
                                            OUTBOUND_PROXY_PORT,
                                            &resp,
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Process echo server for non-proxy ports
                    transport.device_mut().process_echo();

                    // Deliver any pending RX packets
                    if transport.device().has_rx_data() {
                        let memory = vm.memory_mut().as_mut_slice();
                        if transport.device_mut().process_rx(memory) {
                            transport.signal_interrupt();
                            vsock_irq_pending = true;
                        }
                    }
                }
            }
        }

        // Inject IRQ to wake guest if we have any pending interrupt
        // This covers both pre-loop processing (need_irq) and interrupts set during MMIO handling
        if need_irq || timer_irq_pending || virtio_irq_pending || blk_irq_pending || vsock_irq_pending || net_irq_pending || uart_irq_pending {
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
                                        virtio_irq_pending = true;
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
                                    virtio_irq_pending = true;
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
                            eprintln!("[VSOCK-CLI] QUEUE_NOTIFY for queue {}", notified_queue);

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
                                eprintln!("[VSOCK-CLI] Processing TX queue");
                                let memory = vm.memory_mut().as_mut_slice();
                                let packets = transport.device_mut().process_tx(memory);
                                eprintln!("[VSOCK-CLI] TX processed, {} packets", packets.len());
                                if !packets.is_empty() {
                                    transport.signal_interrupt();
                                    vsock_irq_pending = true;

                                    // Process packets - route to proxy or echo based on port
                                    for pkt in &packets {
                                        if pkt.len() >= 44 {
                                            let op = u16::from_le_bytes([pkt[30], pkt[31]]);
                                            let src_port = u32::from_le_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
                                            let dst_port = u32::from_le_bytes([pkt[20], pkt[21], pkt[22], pkt[23]]);

                                            if op == 5 { // RW (data packet)
                                                let payload = &pkt[44..];
                                                if !payload.is_empty() && dst_port == OUTBOUND_PROXY_PORT {
                                                    // Proxy protocol traffic
                                                    eprintln!("[PROXY] Received {} bytes from guest port {}", payload.len(), src_port);
                                                    let responses = proxy_manager.process_incoming(payload);
                                                    for resp in responses {
                                                        // Send response back to guest
                                                        transport.device_mut().queue_data_packet(
                                                            GUEST_CID,
                                                            src_port,
                                                            OUTBOUND_PROXY_PORT,
                                                            &resp,
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Process echo server for non-proxy ports
                                    transport.device_mut().process_echo();
                                }

                                // Deliver any pending RX packets (RESPONSE, echo data, etc.)
                                if transport.device().has_rx_data() {
                                    let memory = vm.memory_mut().as_mut_slice();
                                    if transport.device_mut().process_rx(memory) {
                                        transport.signal_interrupt();
                                        vsock_irq_pending = true;
                                    }
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
                        UART_IBRD | UART_FBRD | UART_LCR_H | UART_CR => {
                            // Ignore configuration writes for now
                        }
                        UART_IMSC => {
                            // Store interrupt mask - kernel enables RX interrupts here
                            uart_imsc = value & 0x7FF;
                        }
                        UART_ICR => {
                            // Interrupt clear register - clear pending interrupts
                            // Clear uart_irq_pending if RXIS is being cleared
                            if (value & INT_RXIS) != 0 && uart_rx_buffer.is_empty() {
                                uart_irq_pending = false;
                            }
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
                // Handle PL011 UART reads
                else if addr >= UART_BASE && addr < UART_BASE + 0x1000 {
                    let offset = addr - UART_BASE;
                    match offset {
                        UART_DR => {
                            // Read from UART RX buffer
                            if let Some(byte) = uart_rx_buffer.pop_front() {
                                // Clear interrupt when buffer is empty
                                if uart_rx_buffer.is_empty() {
                                    uart_irq_pending = false;
                                }
                                byte as u64
                            } else {
                                0
                            }
                        }
                        UART_FR => {
                            // Flag register: RXFE=1 if RX FIFO is empty, TXFE=1 (TX always ready)
                            let mut flags = 1 << 7; // TXFE - TX FIFO empty (always ready)
                            if uart_rx_buffer.is_empty() {
                                flags |= FR_RXFE; // RX FIFO empty
                            }
                            flags as u64
                        }
                        UART_IMSC => {
                            // Interrupt mask register
                            uart_imsc as u64
                        }
                        UART_RIS => {
                            // Raw interrupt status - RXIS set when data available
                            let mut ris = INT_TXIS; // TX interrupt always set (TX always ready)
                            if !uart_rx_buffer.is_empty() {
                                ris |= INT_RXIS;
                            }
                            ris as u64
                        }
                        UART_MIS => {
                            // Masked interrupt status = RIS & IMSC
                            let mut ris = INT_TXIS;
                            if !uart_rx_buffer.is_empty() {
                                ris |= INT_RXIS;
                            }
                            (ris & uart_imsc) as u64
                        }
                        // PrimeCell ID registers (needed for AMBA driver)
                        0xFE0 => 0x11, // PID0
                        0xFE4 => 0x10, // PID1
                        0xFE8 => 0x14, // PID2
                        0xFEC => 0x00, // PID3
                        0xFF0 => 0x0D, // CID0
                        0xFF4 => 0xF0, // CID1
                        0xFF8 => 0x05, // CID2
                        0xFFC => 0xB1, // CID3
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
                            // Priority: timer > uart > console > block > vsock > net
                            let irq = if timer_irq_pending {
                                timer_irq_pending = false;  // Clear on acknowledge
                                VTIMER_IRQ
                            } else if uart_irq_pending {
                                uart_irq_pending = false;  // Clear on acknowledge
                                UART_IRQ
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
                            if timer_irq_pending || uart_irq_pending || virtio_irq_pending || blk_irq_pending || vsock_irq_pending || net_irq_pending {
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
                if !timer_irq_pending && !uart_irq_pending && !virtio_irq_pending && !blk_irq_pending && !vsock_irq_pending && !net_irq_pending {
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

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn run_vm_loop(
    vm: &mut Vm,
    _enable_console: bool,
    _enable_net: bool,
    _disk_path: Option<PathBuf>,
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
            VcpuExit::IoIn { port, size: _ } => {
                // Handle serial input
                #[cfg(target_os = "macos")]
                {
                    use microvm::backend::hvf::bindings::x86_reg;
                    if port == 0x3fd {
                        // Line status register - transmitter empty
                        vcpu.write_register(x86_reg::HV_X86_RAX, 0x20)?;
                    }
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

// Windows WHP backend
#[cfg(target_os = "windows")]
fn run_vm_loop(
    vm: &mut Vm,
    _enable_console: bool,
    _enable_net: bool,
    _disk_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    // Serial port constants (8250 UART)
    const COM1_DATA: u16 = 0x3f8;        // Data register
    const COM1_IER: u16 = 0x3f9;         // Interrupt Enable Register
    const COM1_FCR: u16 = 0x3fa;         // FIFO Control Register / IIR
    const COM1_LCR: u16 = 0x3fb;         // Line Control Register
    const COM1_MCR: u16 = 0x3fc;         // Modem Control Register
    const COM1_LSR: u16 = 0x3fd;         // Line Status Register
    const COM1_MSR: u16 = 0x3fe;         // Modem Status Register

    // PIT (Programmable Interval Timer) ports
    const PIT_CH0: u16 = 0x40;           // Channel 0 counter
    const PIT_CH1: u16 = 0x41;           // Channel 1 counter
    const PIT_CH2: u16 = 0x42;           // Channel 2 counter (PC speaker)
    const PIT_CMD: u16 = 0x43;           // Command register

    // PCI Configuration ports
    const PCI_CONFIG_ADDR: u16 = 0xCF8;  // PCI config address
    const PCI_CONFIG_DATA: u16 = 0xCFC;  // PCI config data (also 0xCFD, 0xCFE, 0xCFF)

    // Simple PIT state for timer calibration
    // The kernel reads the counter repeatedly to measure time
    let mut pit_counter: u16 = 0xFFFF;

    println!("Starting WHP VM execution...");
    let mut exit_count = 0;
    let verbose_debug = false; // Disable verbose debugging for now

    loop {
        // Run vcpu and get exit reason
        let exit = {
            let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
            vcpu.run()?
        };
        exit_count += 1;

        // Verbose debug for first 30 exits only
        if verbose_debug && exit_count <= 30 {
            eprintln!("[Exit {}] {:?}", exit_count, exit);
        }

        // Print periodic status every 1000 exits
        if exit_count % 1000 == 0 {
            let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
            if let Ok(rip) = vcpu.read_register(WHvX64RegisterRip) {
                eprintln!("[Status] {} exits, RIP=0x{:x}", exit_count, rip);
            }
        }

        // Handle MSR exits specially
        // NOTE: WHP has a known bug where it doesn't report the MSR number being accessed.
        // We can't reliably determine which MSR is being accessed, so we:
        // - Return 0 for all MSR reads
        // - Ignore all MSR writes
        // This follows QEMU's WHPX approach and allows the kernel to make progress.
        match &exit {
            VcpuExit::MsrRead { msr, instruction_len } if *msr == 0 => {
                // WHP bug: MSR number is 0 - return incrementing value to break timing loops
                static MSR_READ_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                static MSR_VALUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let count = MSR_READ_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Simulate TSC-like behavior - increment by ~10000 "cycles" per read
                // This helps the kernel timing loops make progress
                let value = MSR_VALUE.fetch_add(10000, std::sync::atomic::Ordering::SeqCst);
                let len = *instruction_len;

                if count < 3 {
                    let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                    let rip = vcpu.read_register(WHvX64RegisterRip).unwrap_or(0);
                    eprintln!("[MSR READ] RIP=0x{:x} (MSR unknown, returning incrementing value 0x{:x}, len={})", rip, value, len);
                }

                let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                vcpu.set_msr_result(value)?;
                vcpu.advance_rip(len as u64)?;
                continue;
            }
            VcpuExit::MsrWrite { msr, value, instruction_len } if *msr == 0 => {
                // WHP bug: MSR number is 0 - just ignore the write and advance
                static MSR_WRITE_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                let count = MSR_WRITE_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let len = *instruction_len;
                if count < 3 {
                    let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                    let rip = vcpu.read_register(WHvX64RegisterRip).unwrap_or(0);
                    eprintln!("[MSR WRITE] RIP=0x{:x}, value=0x{:x} (MSR unknown, ignoring, len={})", rip, value, len);
                }

                let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;
                vcpu.advance_rip(len as u64)?;
                continue;
            }
            _ => {}
        }

        // Get vcpu for main match handling
        let vcpu = vm.vcpu_mut(0).ok_or("No vCPU")?;

        match exit {
            VcpuExit::IoOut { port, data, instruction_len } => {
                match port {
                    COM1_DATA => {
                        // Serial output
                        if !data.is_empty() {
                            print!("{}", data[0] as char);
                            std::io::stdout().flush().ok();
                        }
                    }
                    COM1_IER | COM1_FCR | COM1_LCR | COM1_MCR => {
                        // Ignore configuration writes for now
                    }
                    0x80 => {
                        // Debug port - commonly used for POST codes
                    }
                    PIT_CMD => {
                        // PIT command - just ignore, we don't fully emulate the PIT
                    }
                    PIT_CH0 | PIT_CH1 | PIT_CH2 => {
                        // PIT counter write - reset counter or set reload value
                        pit_counter = 0xFFFF;
                    }
                    PCI_CONFIG_ADDR => {
                        // PCI config address write - ignore for now
                    }
                    PCI_CONFIG_DATA..=0xCFF => {
                        // PCI config data write - ignore
                    }
                    _ => {
                        // Unknown I/O port write
                    }
                }
                // Advance RIP past the OUT instruction
                vcpu.advance_rip(instruction_len as u64)?;
            }
            VcpuExit::IoIn { port, size, instruction_len } => {
                match port {
                    COM1_LSR => {
                        // Line Status Register
                        // Bit 5: Transmitter Holding Register Empty
                        // Bit 6: Transmitter Empty
                        vcpu.set_rax(0x60)?; // THR empty, transmitter empty
                    }
                    COM1_DATA => {
                        // No input available
                        vcpu.set_rax(0)?;
                    }
                    COM1_IER | COM1_FCR | COM1_LCR | COM1_MCR | COM1_MSR => {
                        // Return 0 for other registers
                        vcpu.set_rax(0)?;
                    }
                    PIT_CH0 | PIT_CH1 | PIT_CH2 => {
                        // PIT counter read - return decreasing value for timer calibration
                        // Decrement counter by a reasonable amount to simulate time passing
                        pit_counter = pit_counter.wrapping_sub(100);
                        if size == 1 {
                            // 8-bit read (depends on latch state, simplified)
                            vcpu.set_rax((pit_counter & 0xFF) as u64)?;
                        } else {
                            // 16-bit read
                            vcpu.set_rax(pit_counter as u64)?;
                        }
                    }
                    PCI_CONFIG_ADDR => {
                        // Return 0 for PCI config address read
                        vcpu.set_rax(0)?;
                    }
                    PCI_CONFIG_DATA..=0xCFF => {
                        // PCI config data read - return 0xFFFFFFFF (no device)
                        vcpu.set_rax(0xFFFFFFFF)?;
                    }
                    _ => {
                        // Unknown I/O port read - return 0xFF (all bits set)
                        vcpu.set_rax(0xFF)?;
                    }
                }
                // Advance RIP past the IN instruction
                vcpu.advance_rip(instruction_len as u64)?;
            }
            VcpuExit::Cpuid { rax, rcx, instruction_len } => {
                // Handle CPUID instruction
                let (eax, ebx, ecx, edx) = handle_cpuid(rax as u32, rcx as u32);
                // Log important CPUID queries
                static CPUID_LOG_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                let count = CPUID_LOG_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if count < 30 {
                    if rax >= 0x40000000 && rax <= 0x400000FF {
                        eprintln!("[CPUID] Hyper-V leaf 0x{:x} -> EAX=0x{:x} EBX=0x{:x}", rax, eax, ebx);
                    } else if rax == 1 {
                        eprintln!("[CPUID] Leaf 1 -> ECX=0x{:x} (hypervisor={})", ecx, (ecx >> 31) & 1);
                    } else if rax == 0 {
                        eprintln!("[CPUID] Leaf 0 -> max_leaf=0x{:x}", eax);
                    }
                }
                vcpu.set_cpuid_result(eax, ebx, ecx, edx)?;
                vcpu.advance_rip(instruction_len as u64)?;
            }
            VcpuExit::MmioRead { addr, size: _ } => {
                eprintln!("MMIO read at 0x{:x}", addr);
            }
            VcpuExit::MmioWrite { addr, data: _ } => {
                eprintln!("MMIO write at 0x{:x}", addr);
            }
            VcpuExit::Hlt => {
                println!("\nVM halted (HLT instruction)");
                break;
            }
            VcpuExit::Shutdown => {
                println!("\nVM shutdown");
                break;
            }
            VcpuExit::Canceled => {
                println!("\nVM execution canceled");
                break;
            }
            VcpuExit::MsrRead { msr, instruction_len } => {
                // msr==0 case is handled above before the main match
                // This handles the case where WHP properly reported the MSR number

                // First try special MSRs that map to WHP registers (FS_BASE, GS_BASE, etc.)
                if let Ok(Some(value)) = vcpu.handle_msr_read(msr) {
                    // Log reads of important MSRs
                    if msr >= 0xC0000100 && msr <= 0xC0000102 {
                        static MSR_LOG: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                        if MSR_LOG.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 20 {
                            eprintln!("[MSR READ] 0x{:x} ({}) -> 0x{:x}",
                                msr,
                                match msr { 0xC0000100 => "FS_BASE", 0xC0000101 => "GS_BASE", 0xC0000102 => "KERNEL_GS_BASE", _ => "?" },
                                value);
                        }
                    }
                    vcpu.set_msr_result(value)?;
                } else {
                    // Fall back to software emulation
                    let value = handle_msr_read(msr);
                    vcpu.set_msr_result(value)?;
                }
                vcpu.advance_rip(instruction_len as u64)?;
            }
            VcpuExit::MsrWrite { msr, value, instruction_len } => {
                // msr==0 case is handled above before the main match
                // This handles the case where WHP properly reported the MSR number

                // Log writes to important MSRs
                if msr >= 0xC0000100 && msr <= 0xC0000102 {
                    static MSR_LOG: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                    if MSR_LOG.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 20 {
                        eprintln!("[MSR WRITE] 0x{:x} ({}) <- 0x{:x}",
                            msr,
                            match msr { 0xC0000100 => "FS_BASE", 0xC0000101 => "GS_BASE", 0xC0000102 => "KERNEL_GS_BASE", _ => "?" },
                            value);
                    }
                }

                // First try special MSRs that map to WHP registers (FS_BASE, GS_BASE, etc.)
                if let Ok(handled) = vcpu.handle_msr_write(msr, value) {
                    if !handled {
                        // Fall back to software emulation
                        handle_msr_write(msr, value);
                    }
                } else {
                    // Error in handle_msr_write, fall back
                    handle_msr_write(msr, value);
                }
                vcpu.advance_rip(instruction_len as u64)?;
            }
            VcpuExit::Rdtsc { instruction_len } => {
                // Return an increasing TSC value to simulate time passing
                static TSC_VALUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let tsc = TSC_VALUE.fetch_add(1_000_000, std::sync::atomic::Ordering::SeqCst);
                // RDTSC returns result in EDX:EAX
                vcpu.write_register(WHvX64RegisterRax, tsc & 0xFFFFFFFF)?;
                vcpu.write_register(WHvX64RegisterRdx, tsc >> 32)?;
                vcpu.advance_rip(instruction_len as u64)?;
            }
            VcpuExit::Exception { exception_type, error_code, rip } => {
                // x86 exception types:
                // 0=DE (Divide Error), 6=UD (Invalid Opcode), 8=DF (Double Fault)
                // 13=GP (General Protection), 14=PF (Page Fault)
                let exception_name = match exception_type {
                    0 => "Divide Error (#DE)",
                    1 => "Debug (#DB)",
                    3 => "Breakpoint (#BP)",
                    4 => "Overflow (#OF)",
                    5 => "BOUND Range Exceeded (#BR)",
                    6 => "Invalid Opcode (#UD)",
                    7 => "Device Not Available (#NM)",
                    8 => "Double Fault (#DF)",
                    10 => "Invalid TSS (#TS)",
                    11 => "Segment Not Present (#NP)",
                    12 => "Stack-Segment Fault (#SS)",
                    13 => "General Protection (#GP)",
                    14 => "Page Fault (#PF)",
                    16 => "x87 FPU Error (#MF)",
                    17 => "Alignment Check (#AC)",
                    18 => "Machine Check (#MC)",
                    19 => "SIMD Exception (#XM)",
                    _ => "Unknown Exception",
                };
                eprintln!("\nException: {} (type={}, error_code=0x{:x})", exception_name, exception_type, error_code);
                eprintln!("  RIP at fault: 0x{:016x}", rip);
                // Dump additional CPU state
                if let Ok(rsp) = vcpu.read_register(WHvX64RegisterRsp) {
                    eprintln!("  RSP: 0x{:016x}", rsp);
                }
                if let Ok(cr2) = vcpu.read_register(WHvX64RegisterCr2) {
                    eprintln!("  CR2 (page fault addr): 0x{:016x}", cr2);
                }
                break;
            }
            VcpuExit::InterceptedException { exception_type, error_code, rip, parameter } => {
                // Intercepted exception (from exception bitmap)
                let exception_name = match exception_type {
                    0 => "Divide Error (#DE)",
                    13 => "General Protection (#GP)",
                    14 => "Page Fault (#PF)",
                    _ => "Other",
                };
                // For #GP, we need to decide whether to re-inject or handle
                if exception_type == 13 {
                    // #GP - this might be from an invalid MSR access
                    // Print debug info but continue execution
                    eprintln!("[Intercepted #GP] error_code=0x{:x}, RIP=0x{:x}, param=0x{:x}",
                        error_code, rip, parameter);
                    // Re-inject the exception to the guest so it can handle it
                    // For now, just print and break to understand what's happening
                    eprintln!("  (Breaking to analyze - #GP at guest RIP 0x{:x})", rip);
                    break;
                } else {
                    eprintln!("Intercepted exception: {} (type={}, error=0x{:x}) at RIP=0x{:x}",
                        exception_name, exception_type, error_code, rip);
                    break;
                }
            }
            VcpuExit::Unknown(reason) => {
                eprintln!("Unknown exit reason: {}", reason);
                // Debug: dump CPU state
                if let Ok(rip) = vcpu.read_register(WHvX64RegisterRip) {
                    eprintln!("  RIP: 0x{:016x}", rip);
                }
                if let Ok(rsp) = vcpu.read_register(WHvX64RegisterRsp) {
                    eprintln!("  RSP: 0x{:016x}", rsp);
                }
                if let Ok(cr0) = vcpu.read_register(WHvX64RegisterCr0) {
                    eprintln!("  CR0: 0x{:016x}", cr0);
                }
                if let Ok(cr3) = vcpu.read_register(WHvX64RegisterCr3) {
                    eprintln!("  CR3: 0x{:016x}", cr3);
                }
                if let Ok(cr4) = vcpu.read_register(WHvX64RegisterCr4) {
                    eprintln!("  CR4: 0x{:016x}", cr4);
                }
                if let Ok(efer) = vcpu.read_register(WHvX64RegisterEfer) {
                    eprintln!("  EFER: 0x{:016x}", efer);
                }
                break;
            }
        }
    }

    Ok(())
}

/// Handle MSR read for WHP.
#[cfg(target_os = "windows")]
fn handle_msr_read(msr: u32) -> u64 {
    // Counters for time-sensitive MSRs
    static MSR0_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static TIME_REF_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static VP_RUNTIME: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    match msr {
        // ============================================================
        // Hyper-V Synthetic MSRs (0x40000xxx)
        // These are properly handled because we KNOW their numbers!
        // ============================================================

        // HV_X64_MSR_GUEST_OS_ID (0x40000000) - Guest OS identification
        0x40000000 => 0,

        // HV_X64_MSR_HYPERCALL (0x40000001) - Hypercall page MSR
        // Return 0 to indicate hypercall page is not enabled
        0x40000001 => 0,

        // HV_X64_MSR_VP_INDEX (0x40000002) - Virtual processor index
        // Return 0 for the first (and only) vCPU
        0x40000002 => 0,

        // HV_X64_MSR_RESET (0x40000003) - System reset MSR
        0x40000003 => 0,

        // HV_X64_MSR_VP_RUNTIME (0x40000010) - VP runtime in 100ns units
        // Return an increasing value to simulate time passing
        0x40000010 => {
            VP_RUNTIME.fetch_add(10000, std::sync::atomic::Ordering::SeqCst)
        }

        // HV_X64_MSR_TIME_REF_COUNT (0x40000020) - Reference time counter
        // Returns time in 100ns units since VM start - CRITICAL for timing!
        0x40000020 => {
            TIME_REF_COUNT.fetch_add(100000, std::sync::atomic::Ordering::SeqCst)
        }

        // HV_X64_MSR_REFERENCE_TSC (0x40000021) - Reference TSC page
        // Return 0 to indicate TSC page is not set up (kernel will use MSR instead)
        0x40000021 => 0,

        // HV_X64_MSR_APIC_FREQUENCY (0x40000023) - APIC frequency in Hz
        // Report 1GHz APIC frequency
        0x40000023 => 1000000000,

        // HV_X64_MSR_TSC_FREQUENCY (0x40000022) - TSC frequency in Hz
        // Report 2GHz TSC frequency
        0x40000022 => 2000000000,

        // HV_X64_MSR_SCONTROL (0x40000080) - SynIC control
        0x40000080 => 0,

        // HV_X64_MSR_SIEFP (0x40000082) - SynIC event flags page
        0x40000082 => 0,

        // HV_X64_MSR_SIMP (0x40000083) - SynIC message page
        0x40000083 => 0,

        // HV_X64_MSR_EOM (0x40000084) - End of message
        0x40000084 => 0,

        // HV_X64_MSR_SINT0-SINT15 (0x40000090-0x4000009F) - Synthetic interrupt sources
        0x40000090..=0x4000009F => 0,

        // HV_X64_MSR_STIMER0_CONFIG - STIMER3_COUNT (0x400000B0-0x400000B7)
        // Synthetic timer MSRs
        0x400000B0..=0x400000B7 => 0,

        // HV_X64_MSR_CRASH_P0-P4, CRASH_CTL (0x40000100-0x40000105)
        0x40000100..=0x40000105 => 0,

        // ============================================================
        // Standard x86 MSRs (fallback, but synthetic MSRs are preferred)
        // ============================================================

        // IA32_P5_MC_ADDR / probing MSR - or unknown MSR being probed
        // Return an increasing value to simulate time passing
        0x0 => {
            MSR0_COUNTER.fetch_add(0x100000, std::sync::atomic::Ordering::SeqCst)
        }
        // IA32_APIC_BASE
        0x1B => 0xFEE00900,
        // IA32_MTRRCAP
        0xFE => 0x0000000000000508,
        // IA32_MISC_ENABLE
        0x1A0 => 0x00000001,
        // IA32_EFER (already set by init_long_mode, but reading is fine)
        0xC0000080 => 0x500,
        // IA32_FS_BASE
        0xC0000100 => 0,
        // IA32_GS_BASE
        0xC0000101 => 0,
        // IA32_KERNEL_GS_BASE
        0xC0000102 => 0,
        // IA32_TSC_AUX
        0xC0000103 => 0,
        // IA32_STAR - for syscall/sysret
        0xC0000081 => 0,
        // IA32_LSTAR - syscall entry point
        0xC0000082 => 0,
        // IA32_CSTAR - compat mode syscall entry
        0xC0000083 => 0,
        // IA32_FMASK - syscall flags mask
        0xC0000084 => 0,
        // Return 0 for unknown MSRs (silently, don't flood logs)
        _ => 0,
    }
}

/// Handle MSR write for WHP.
#[cfg(target_os = "windows")]
fn handle_msr_write(msr: u32, value: u64) {
    // Track writes to important MSRs (for debugging)
    static GUEST_OS_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    match msr {
        // ============================================================
        // Hyper-V Synthetic MSRs (0x40000xxx)
        // Accept writes to these - kernel sets them during init
        // ============================================================

        // HV_X64_MSR_GUEST_OS_ID - Guest registers its OS type
        0x40000000 => {
            GUEST_OS_ID.store(value, std::sync::atomic::Ordering::SeqCst);
            // Log this as it indicates the guest detected Hyper-V!
            eprintln!("[Hyper-V] Guest OS ID set to 0x{:x}", value);
        }

        // HV_X64_MSR_HYPERCALL - Guest sets up hypercall page
        0x40000001 => {
            // We don't support hypercalls, but accept the write
            if value != 0 {
                eprintln!("[Hyper-V] Hypercall page setup: 0x{:x} (ignored)", value);
            }
        }

        // HV_X64_MSR_VP_INDEX - read-only, but accept writes silently
        0x40000002 => {}

        // HV_X64_MSR_RESET - system reset request
        0x40000003 => {
            eprintln!("[Hyper-V] Reset requested via MSR");
        }

        // HV_X64_MSR_REFERENCE_TSC - TSC page setup
        0x40000021 => {}

        // SynIC MSRs - accept but don't implement
        0x40000080..=0x400000B7 => {}

        // Crash MSRs - log crash info
        0x40000100..=0x40000105 => {
            eprintln!("[Hyper-V] Crash MSR 0x{:x} = 0x{:x}", msr, value);
        }

        // ============================================================
        // Standard x86 MSRs
        // ============================================================

        0x0 | 0xC0000080 | 0xC0000100 | 0xC0000101 | 0xC0000102 => {}
        0xC0000081 | 0xC0000082 | 0xC0000083 | 0xC0000084 | 0x1B => {}
        _ => {}
    }
}

/// Handle CPUID instruction for WHP.
#[cfg(target_os = "windows")]
fn handle_cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    match leaf {
        0 => {
            // Vendor ID: "GenuineIntel"
            // EAX = max standard leaf (we support up to 0xD)
            // EBX:EDX:ECX = "GenuineIntel"
            (0xD, 0x756E6547, 0x6C65746E, 0x49656E69) // "Genu" "ineI" "ntel"
        }
        1 => {
            // Processor info and features
            let eax = 0x000506E3; // Family 6, Model 94 (Skylake-like)
            let ebx = 0x00100800; // CLFLUSH=8, APIC ID=0, 1 logical processor
            // ECX features: SSE3 + HYPERVISOR bit (bit 31)
            // Bit 31 (0x80000000) = Hypervisor present - tells guest it's in a VM
            let ecx = 0x80000201; // SSE3 + Hypervisor present
            // EDX features: FPU, VME, DE, PSE, TSC, MSR, PAE, MCE, CX8, APIC, SEP, MTRR, PGE, MCA, CMOV, PAT, PSE36, CLFSH, MMX, FXSR, SSE, SSE2
            let edx = 0x178BFBFF;
            (eax, ebx, ecx, edx)
        }
        2 => {
            // Cache and TLB info (return null descriptors)
            (0x00000001, 0, 0, 0)
        }
        4 => {
            // Deterministic cache parameters
            (0, 0, 0, 0) // No cache info
        }
        6 => {
            // Thermal and power management
            (0, 0, 0, 0)
        }
        7 => {
            // Structured extended feature flags
            if subleaf == 0 {
                (0, 0, 0, 0) // No advanced features
            } else {
                (0, 0, 0, 0)
            }
        }
        0xB => {
            // Extended topology enumeration
            (0, 0, 0, 0)
        }
        0xD => {
            // Processor extended state enumeration
            (0, 0, 0, 0)
        }
        0x80000000 => {
            // Extended function info - max extended leaf
            (0x80000008, 0, 0, 0)
        }
        0x80000001 => {
            // Extended processor features
            // EDX bit 29 = LM (long mode), bit 20 = NX
            (0, 0, 0x00000001, 0x2C100800) // LAHF, NX, LM, SYSCALL
        }
        0x80000002..=0x80000004 => {
            // Processor brand string "microvm"
            match leaf {
                0x80000002 => (0x7263696D, 0x6D766F72, 0x00000000, 0x00000000), // "micr" "ovm\0"
                0x80000003 => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
                0x80000004 => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
                _ => (0, 0, 0, 0),
            }
        }
        0x80000008 => {
            // Virtual/physical address sizes
            // EAX: bits 7:0 = physical address bits (48), bits 15:8 = virtual address bits (48)
            (0x00003030, 0, 0, 0)
        }

        // ============================================================
        // Hyper-V Enlightenment CPUID leaves (0x40000000 - 0x4000000A)
        // These make Linux detect Hyper-V and use synthetic MSRs
        // instead of standard MSRs that WHP can't properly report.
        // ============================================================

        0x40000000 => {
            // Hypervisor CPUID leaf range and vendor signature
            // EAX = Maximum hypervisor CPUID leaf
            // EBX:ECX:EDX = "Microsoft Hv" signature
            let eax = 0x40000006; // Max leaf we support
            let ebx = 0x7263694D; // "Micr"
            let ecx = 0x666F736F; // "osof"
            let edx = 0x76482074; // "t Hv"
            (eax, ebx, ecx, edx)
        }
        0x40000001 => {
            // Hypervisor vendor-neutral interface identification
            // EAX = "Hv#1" interface signature
            (0x31237648, 0, 0, 0) // "Hv#1"
        }
        0x40000002 => {
            // Hypervisor system identity (build number, version)
            // We report as a recent Hyper-V build
            let eax = 0x00003FFE; // Build number
            let ebx = 0x000A0000; // Major.Minor version (10.0)
            let ecx = 0;          // Service pack
            let edx = 0;          // Service branch
            (eax, ebx, ecx, edx)
        }
        0x40000003 => {
            // Hypervisor feature identification
            // EAX = Partition privileges (what MSRs/features guest can use)
            // EBX = Flags
            // ECX = Power management features
            // EDX = Misc features

            // Privileges (EAX):
            // Bit 0: AccessVpRunTimeReg - HV_X64_MSR_VP_RUNTIME
            // Bit 1: AccessPartitionReferenceCounter - HV_X64_MSR_TIME_REF_COUNT
            // Bit 2: AccessSynicRegs - Synthetic interrupt controller MSRs
            // Bit 3: AccessSyntheticTimerRegs - Synthetic timer MSRs
            // Bit 4: AccessIntrCtrlRegs - APIC MSRs
            // Bit 5: AccessHypercallMsrs - Hypercall MSRs
            // Bit 6: AccessVpIndex - HV_X64_MSR_VP_INDEX
            // Bit 9: AccessPartitionReferenceTsc - Reference TSC page
            let eax = 0x00000263; // VP_RUNTIME, TIME_REF_COUNT, VP_INDEX, AccessPartitionReferenceTsc, AccessHypercallMsrs

            // Flags (EBX):
            // Bit 0: CreatePartitions
            // Bit 1: AccessPartitionId
            // Bit 2: AccessMemoryPool
            // Bit 4: PostMessages
            // Bit 5: SignalEvents
            let ebx = 0x00000000;

            let ecx = 0; // Power management (none)
            let edx = 0; // Misc features
            (eax, ebx, ecx, edx)
        }
        0x40000004 => {
            // Implementation recommendations
            // EAX = Recommendations for optimal performance
            // Bit 0: Hypercall for address space switches (not TLB flush)
            // Bit 1: Hypercall for local TLB flushes
            // Bit 2: Hypercall for remote TLB flushes
            // Bit 3: MSRs for APIC access (EOI, ICR, TPR)
            // Bit 4: MSR for system RESET
            // Bit 5: Relaxed timing - don't need strict timers
            // Bit 6: Use DMA remapping
            // Bit 7: Use interrupt remapping
            // Bit 8: Use x2APIC MSRs
            // Bit 12: Use hypercall for APIC EOI
            let eax = 0x00000020; // Relaxed timing (bit 5) - key for MSR workaround!
            let ebx = 0;
            let ecx = 0;
            let edx = 0;
            (eax, ebx, ecx, edx)
        }
        0x40000005 => {
            // Hypervisor implementation limits
            // EAX = Max virtual processors
            // EBX = Max logical processors
            // ECX = Max physical interrupt vectors for remapping
            (64, 64, 0, 0)
        }
        0x40000006 => {
            // Hypervisor hardware features exposed
            // EAX = Hardware features
            (0, 0, 0, 0)
        }

        _ => (0, 0, 0, 0),
    }
}

/// Set up identity-mapped page tables for 64-bit long mode.
/// Creates PML4 -> PDPT -> PD entries that identity map the first 1GB.
#[cfg(target_arch = "x86_64")]
fn setup_page_tables(memory: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Page table layout at physical addresses:
    // 0x1000: PML4 (Page Map Level 4)
    // 0x2000: PDPT (Page Directory Pointer Table)
    // 0x3000: PD (Page Directory) - maps first 1GB with 2MB pages

    const PML4_ADDR: usize = 0x1000;
    const PDPT_ADDR: usize = 0x2000;
    const PD_ADDR: usize = 0x3000;

    // Clear the page table area
    for i in 0..(4 * 4096) {
        if PML4_ADDR + i < memory.len() {
            memory[PML4_ADDR + i] = 0;
        }
    }

    // PML4[0] -> PDPT at 0x2000
    // Flags: Present (1) | Writable (2) = 0x3
    let pml4_entry: u64 = PDPT_ADDR as u64 | 0x3;
    memory[PML4_ADDR..PML4_ADDR + 8].copy_from_slice(&pml4_entry.to_le_bytes());

    // PDPT[0] -> PD at 0x3000
    let pdpt_entry: u64 = PD_ADDR as u64 | 0x3;
    memory[PDPT_ADDR..PDPT_ADDR + 8].copy_from_slice(&pdpt_entry.to_le_bytes());

    // PD entries: Map first 1GB using 2MB pages (512 entries * 2MB = 1GB)
    // Flags: Present (1) | Writable (2) | Page Size (0x80 for 2MB pages) = 0x83
    for i in 0..512 {
        let pd_entry: u64 = (i as u64 * 0x200000) | 0x83; // 2MB page, present, writable
        let offset = PD_ADDR + i * 8;
        if offset + 8 <= memory.len() {
            memory[offset..offset + 8].copy_from_slice(&pd_entry.to_le_bytes());
        }
    }

    Ok(())
}

/// Set up GDT (Global Descriptor Table) for 64-bit long mode.
#[cfg(target_arch = "x86_64")]
fn setup_gdt(memory: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    use microvm::loader::x86_64::{GdtEntry, build_gdt};

    const GDT_ADDR: usize = 0x500;

    // Build GDT: null, code64, data64
    let gdt = build_gdt();

    // Write GDT to memory
    if GDT_ADDR + gdt.len() <= memory.len() {
        memory[GDT_ADDR..GDT_ADDR + gdt.len()].copy_from_slice(&gdt);
    }

    // GDT descriptor (GDTR) at 0x500 - 10 (i.e., 0x4F6)
    // Note: The CPU will load this via LGDT instruction or we set GDTR register directly
    // For WHP, we typically set the GDT base register directly in init_long_mode

    Ok(())
}
