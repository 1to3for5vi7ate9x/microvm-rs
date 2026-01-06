//! Example: Boot a Linux kernel.
//!
//! This example demonstrates booting a Linux kernel in the VM.
//! You need to provide a kernel image (vmlinuz or Image).
//!
//! Usage:
//!   cargo run --example boot_linux -- /path/to/kernel [/path/to/initrd]
//!
//! Download a test kernel:
//!   ./scripts/download_test_kernel.sh

use std::env;
use std::io::Write;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <kernel-path> [initrd-path]", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} test-assets/vmlinuz-lts-arm64", args[0]);
        eprintln!("  {} test-assets/vmlinuz-lts-arm64 test-assets/initramfs-lts-arm64", args[0]);
        eprintln!();
        eprintln!("Download a test kernel first:");
        eprintln!("  chmod +x scripts/download_test_kernel.sh");
        eprintln!("  ./scripts/download_test_kernel.sh");
        std::process::exit(1);
    }

    let kernel_path = &args[1];
    let initrd_path = args.get(2).map(|s| s.as_str());

    println!("microvm-rs Linux boot example");
    println!("==============================\n");

    // Check if hypervisor is available
    if !microvm::is_supported() {
        eprintln!("Error: Hypervisor not available on this system");
        eprintln!("Make sure:");
        eprintln!("  - Binary is signed with hypervisor entitlement");
        eprintln!("  - Not running in a VM without nested virtualization");
        std::process::exit(1);
    }

    println!("Hypervisor: {}", microvm::backend_name().unwrap_or("unknown"));
    println!("Architecture: {}", std::env::consts::ARCH);
    println!("Kernel: {}", kernel_path);
    if let Some(initrd) = initrd_path {
        println!("Initrd: {}", initrd);
    }
    println!();

    #[cfg(target_os = "macos")]
    run_linux_boot(kernel_path, initrd_path);

    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("Linux boot only supported on macOS currently");
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_linux_boot(kernel_path: &str, initrd_path: Option<&str>) {
    use microvm::backend::hvf;
    use microvm::backend::VmConfig;
    use microvm::loader::LinuxLoader;

    // Load kernel
    println!("Loading kernel...");
    let mut loader = match LinuxLoader::new(kernel_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to load kernel: {}", e);
            return;
        }
    };

    // Detect format
    let format = loader.detect_format();
    println!("  Format: {:?}", format);
    println!("  Size: {} bytes", loader.kernel_data().len());

    // Add initrd if provided
    if let Some(initrd) = initrd_path {
        loader = match loader.with_initrd(initrd) {
            Ok(l) => {
                println!("  Initrd: {} bytes", l.initrd_data().map(|d| d.len()).unwrap_or(0));
                l
            }
            Err(e) => {
                eprintln!("Failed to load initrd: {}", e);
                return;
            }
        };
    }

    // Set command line - use init=/init to run our init script
    let loader = loader.with_cmdline("console=ttyAMA0 earlycon=pl011,0x09000000 panic=1 init=/init");

    // Create VM with enough memory for the kernel and initrd
    println!("\nCreating VM...");
    let config = VmConfig {
        memory_mb: 1024, // 1GB to accommodate kernel + large initrd + userspace
        vcpus: 1,
        kernel: Some(kernel_path.into()),
        initrd: initrd_path.map(|s| s.into()),
        rootfs: None,
        cmdline: loader.cmdline().to_string(),
    };

    let mut vm = match hvf::Vm::new(&config) {
        Ok(vm) => {
            println!("  Memory: {} MB", config.memory_mb);
            println!("  vCPUs: {}", config.vcpus);
            vm
        }
        Err(e) => {
            eprintln!("Failed to create VM: {}", e);
            return;
        }
    };

    // Load kernel into memory
    println!("\nLoading kernel into guest memory...");
    let kernel_info = {
        let memory = vm.memory_mut();
        match loader.load(memory) {
            Ok(info) => {
                println!("  Entry point: 0x{:x}", info.entry);
                println!("  Load address: 0x{:x}", info.load_addr);
                println!("  Loaded size: {} bytes", info.size);
                info
            }
            Err(e) => {
                eprintln!("Failed to load kernel: {}", e);
                return;
            }
        }
    };

    // Build device tree
    println!("\nBuilding device tree...");

    // ARM64 RAM starts at 0x40000000 (see vm.rs and arm64.rs)
    const RAM_BASE: u64 = 0x4000_0000;

    // Place initrd after kernel with some padding
    // Kernel is at RAM_BASE + 2MB, and can be up to ~40MB
    // So place initrd at RAM_BASE + 64MB to be safe
    let initrd_info = if let Some(initrd_data) = loader.initrd_data() {
        let initrd_gpa = RAM_BASE + 0x400_0000; // RAM_BASE + 64MB
        let initrd_end = initrd_gpa + initrd_data.len() as u64;
        let initrd_offset = (initrd_gpa - RAM_BASE) as usize;
        vm.memory_mut().write(initrd_offset, initrd_data).unwrap();
        println!("  Initrd at 0x{:x} - 0x{:x}", initrd_gpa, initrd_end);
        Some((initrd_gpa, initrd_end))
    } else {
        None
    };

    let dtb = microvm::loader::arm64::DeviceTreeBuilder::build_with_devices(
        1024 * 1024 * 1024, // 1GB
        loader.cmdline(),
        initrd_info.map(|(s, _)| s),
        initrd_info.map(|(_, e)| e),
        false, // console (using PL011 instead)
        false, // block
        true,  // vsock - for host-guest communication
        false, // net
    );

    // Write DTB to memory (at RAM_BASE + 64KB, before kernel at RAM_BASE + 2MB)
    const DTB_GPA: u64 = RAM_BASE + 0x1_0000; // RAM_BASE + 64KB
    let dtb_offset = (DTB_GPA - RAM_BASE) as usize;
    vm.memory_mut().write(dtb_offset, &dtb).unwrap();
    println!("  DTB at 0x{:x} ({} bytes)", DTB_GPA, dtb.len());

    // Set up CPU registers
    println!("\nSetting up CPU...");
    if let Some(vcpu) = vm.vcpu_mut(0) {
        use microvm::backend::hvf::bindings::arm64_reg;

        // PC = kernel entry
        vcpu.write_register(arm64_reg::HV_REG_PC, kernel_info.entry).unwrap();

        // X0 = DTB address (required by Linux boot protocol)
        vcpu.write_register(arm64_reg::HV_REG_X0, DTB_GPA).unwrap();

        // X1, X2, X3 = 0 (reserved)
        vcpu.write_register(arm64_reg::HV_REG_X1, 0).unwrap();
        vcpu.write_register(arm64_reg::HV_REG_X2, 0).unwrap();
        vcpu.write_register(arm64_reg::HV_REG_X3, 0).unwrap();

        println!("  PC = 0x{:x}", kernel_info.entry);
        println!("  X0 (DTB) = 0x{:x}", DTB_GPA);
    }

    println!("\nBooting kernel...");
    println!("=====================================");
    println!("--- Serial output (ctrl+c to exit) ---\n");

    run_vcpu_loop(&mut vm);
}

/// Decode common ARM64 instructions
fn decode_arm64(instr: u32) -> &'static str {
    if instr == 0xD503207F { return "WFI"; }
    if instr == 0xD503203F { return "YIELD"; }
    if instr == 0xD5033FDF { return "ISB"; }
    if (instr & 0xFFFFFFE0) == 0xD503205F { return "WFE/SEVL"; }
    if (instr & 0xFC000000) == 0x14000000 { return "B"; }
    if (instr & 0xFF000000) == 0x54000000 { return "B.cond"; }
    if (instr & 0xFC000000) == 0x94000000 { return "BL"; }
    if (instr & 0xFFFFFC1F) == 0xD61F0000 { return "BR"; }
    if (instr & 0xFFFFFC1F) == 0xD63F0000 { return "BLR"; }
    if (instr & 0xFFFFFC1F) == 0xD65F0000 { return "RET"; }
    if (instr & 0x7FE00000) == 0x3A400000 { return "CCMP"; }
    if (instr & 0x7F800000) == 0x12800000 { return "MOVN"; }
    if (instr & 0x7F800000) == 0x52800000 { return "MOVZ"; }
    if (instr & 0x7F800000) == 0x72800000 { return "MOVK"; }
    if (instr & 0x3B000000) == 0x39000000 { return "LDR/STR"; }
    if (instr & 0xFFE0FC00) == 0xD4000001 { return "SVC"; }
    if (instr & 0xFFE0FC00) == 0xD4000002 { return "HVC"; }
    if (instr & 0xFFE0FC00) == 0xD4000003 { return "SMC"; }
    if (instr & 0xFFC00000) == 0xD5000000 { return "MSR/MRS"; }
    ""
}

/// Walk ARM64 page tables to translate virtual address to physical.
/// Returns None if translation fails.
/// Note: RAM starts at RAM_BASE (0x40000000), so we need to convert PA to buffer offset.
fn translate_va_to_pa(memory: &[u8], ttbr: u64, va: u64) -> Option<u64> {
    const RAM_BASE: u64 = 0x4000_0000;

    // Helper to convert guest PA to buffer offset
    let pa_to_offset = |pa: u64| -> Option<usize> {
        if pa >= RAM_BASE && (pa - RAM_BASE) < memory.len() as u64 {
            Some((pa - RAM_BASE) as usize)
        } else {
            None
        }
    };

    // Assuming 4KB granule with 4-level page tables (48-bit VA)
    // TTBR format: bits 47:1 contain the table base address
    let table_base = ttbr & 0x0000_FFFF_FFFF_F000;

    // For TTBR1 (kernel addresses), strip the high bits
    // VA bits: [47:39] = L0, [38:30] = L1, [29:21] = L2, [20:12] = L3, [11:0] = offset
    let va_masked = va & 0x0000_FFFF_FFFF_FFFF; // Mask to 48 bits

    let l0_idx = ((va_masked >> 39) & 0x1FF) as usize;
    let l1_idx = ((va_masked >> 30) & 0x1FF) as usize;
    let l2_idx = ((va_masked >> 21) & 0x1FF) as usize;
    let l3_idx = ((va_masked >> 12) & 0x1FF) as usize;
    let page_offset = (va_masked & 0xFFF) as u64;

    // Read L0 descriptor
    let l0_offset = pa_to_offset(table_base)? + (l0_idx * 8);
    if l0_offset + 8 > memory.len() { return None; }
    let l0_desc = u64::from_le_bytes(memory[l0_offset..l0_offset+8].try_into().ok()?);

    // Check if valid (bit 0) and table (bit 1)
    if (l0_desc & 0x3) != 0x3 { return None; } // Not a valid table descriptor
    let l1_table = l0_desc & 0x0000_FFFF_FFFF_F000;

    // Read L1 descriptor
    let l1_offset = pa_to_offset(l1_table)? + (l1_idx * 8);
    if l1_offset + 8 > memory.len() { return None; }
    let l1_desc = u64::from_le_bytes(memory[l1_offset..l1_offset+8].try_into().ok()?);

    // Check for block (1GB) or table
    if (l1_desc & 0x3) == 0x1 {
        // Block descriptor (1GB page)
        let pa = (l1_desc & 0x0000_FFFF_C000_0000) | (va_masked & 0x3FFF_FFFF);
        return Some(pa);
    }
    if (l1_desc & 0x3) != 0x3 { return None; }
    let l2_table = l1_desc & 0x0000_FFFF_FFFF_F000;

    // Read L2 descriptor
    let l2_offset = pa_to_offset(l2_table)? + (l2_idx * 8);
    if l2_offset + 8 > memory.len() { return None; }
    let l2_desc = u64::from_le_bytes(memory[l2_offset..l2_offset+8].try_into().ok()?);

    // Check for block (2MB) or table
    if (l2_desc & 0x3) == 0x1 {
        // Block descriptor (2MB page)
        let pa = (l2_desc & 0x0000_FFFF_FFE0_0000) | (va_masked & 0x001F_FFFF);
        return Some(pa);
    }
    if (l2_desc & 0x3) != 0x3 { return None; }
    let l3_table = l2_desc & 0x0000_FFFF_FFFF_F000;

    // Read L3 descriptor
    let l3_offset = pa_to_offset(l3_table)? + (l3_idx * 8);
    if l3_offset + 8 > memory.len() { return None; }
    let l3_desc = u64::from_le_bytes(memory[l3_offset..l3_offset+8].try_into().ok()?);

    // Check for page
    if (l3_desc & 0x3) != 0x3 { return None; }
    let pa = (l3_desc & 0x0000_FFFF_FFFF_F000) | page_offset;

    Some(pa)
}

/// Handle PSCI calls (Power State Coordination Interface)
fn handle_psci_call(function_id: u64) -> u64 {
    // PSCI function IDs (32-bit and 64-bit variants)
    const PSCI_VERSION: u64 = 0x84000000;
    const PSCI_CPU_SUSPEND_32: u64 = 0x84000001;
    const PSCI_CPU_SUSPEND_64: u64 = 0xC4000001;
    const PSCI_CPU_OFF: u64 = 0x84000002;
    const PSCI_CPU_ON_32: u64 = 0x84000003;
    const PSCI_CPU_ON_64: u64 = 0xC4000003;
    const PSCI_AFFINITY_INFO_32: u64 = 0x84000004;
    const PSCI_AFFINITY_INFO_64: u64 = 0xC4000004;
    const PSCI_MIGRATE_INFO_TYPE: u64 = 0x84000006;
    const PSCI_SYSTEM_OFF: u64 = 0x84000008;
    const PSCI_SYSTEM_RESET: u64 = 0x84000009;
    const PSCI_FEATURES: u64 = 0x8400000A;
    const SMCCC_VERSION: u64 = 0x80000000;
    const SMCCC_ARCH_FEATURES: u64 = 0x80000001;
    const SMCCC_ARCH_SOC_ID: u64 = 0x80000002;
    const SMCCC_ARCH_WORKAROUND_1: u64 = 0x80008000;
    const SMCCC_ARCH_WORKAROUND_2: u64 = 0x80007FFF;
    const SMCCC_ARCH_WORKAROUND_3: u64 = 0x80003FFF;

    // PSCI return codes
    const PSCI_SUCCESS: u64 = 0;
    const PSCI_NOT_SUPPORTED: u64 = 0xFFFFFFFF_FFFFFFFF; // -1 as u64

    let result = match function_id {
        PSCI_VERSION => {
            // Return PSCI v1.0
            // Note: returning version means PSCI is present
            0x00010000
        }
        // Quick workaround function IDs that might be checked (mask upper bits)
        0x95000000..=0x9500FFFF => {
            // SMCCC conduit check - return success
            PSCI_SUCCESS
        }
        SMCCC_VERSION => {
            // Return SMCCC v1.1
            0x00010001
        }
        PSCI_FEATURES => {
            // Query if a feature is supported - always return success
            PSCI_SUCCESS
        }
        SMCCC_ARCH_FEATURES => {
            // Return that SMCCC_ARCH_SOC_ID is not implemented
            PSCI_NOT_SUPPORTED
        }
        SMCCC_ARCH_SOC_ID => {
            PSCI_NOT_SUPPORTED
        }
        SMCCC_ARCH_WORKAROUND_1 | SMCCC_ARCH_WORKAROUND_2 | SMCCC_ARCH_WORKAROUND_3 => {
            // Workarounds not needed
            PSCI_NOT_SUPPORTED
        }
        PSCI_CPU_SUSPEND_32 | PSCI_CPU_SUSPEND_64 | PSCI_CPU_OFF => {
            PSCI_SUCCESS
        }
        PSCI_CPU_ON_32 | PSCI_CPU_ON_64 => {
            // We only have one CPU
            PSCI_NOT_SUPPORTED
        }
        PSCI_AFFINITY_INFO_32 | PSCI_AFFINITY_INFO_64 => {
            // Return CPU is on (0)
            0
        }
        PSCI_MIGRATE_INFO_TYPE => {
            // TOS is not present or does not require migration
            2
        }
        PSCI_SYSTEM_OFF => {
            eprintln!("\n[PSCI: System off requested]");
            PSCI_SUCCESS
        }
        PSCI_SYSTEM_RESET => {
            eprintln!("\n[PSCI: System reset requested]");
            PSCI_SUCCESS
        }
        _ => {
            // Unknown function - return not supported
            PSCI_NOT_SUPPORTED
        }
    };

    // Debug: show PSCI calls (uncomment to debug)
    // eprintln!("[PSCI: 0x{:08x} -> 0x{:x}]", function_id as u32, result);

    result
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_vcpu_loop(vm: &mut microvm::backend::hvf::Vm) {
    use microvm::backend::hvf::{bindings::{arm64_reg, arm64_interrupt}, vcpu::VcpuExit};
    use microvm::device::{Gic, Pl011, gic::VTIMER_IRQ};
    use microvm::device::virtio::{VirtioMmioTransport, VirtioVsock};
    use microvm::loader::arm64::DeviceTreeBuilder;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    // Create devices
    let mut uart = Pl011::default();
    let mut gic = Gic::new();

    // Create vsock device - guest CID is 3 (host is 2)
    const GUEST_CID: u64 = 3;
    const VSOCK_PORT: u32 = 7600; // Port where velocitty-daemon listens
    const HOST_PORT: u32 = 1234;  // Our local port for the connection
    const PROXY_PORT: u32 = 7601; // Port for outbound proxy
    let vsock = VirtioVsock::new(GUEST_CID);
    let vsock_base = DeviceTreeBuilder::VIRTIO_MMIO_BASE + 2 * DeviceTreeBuilder::VIRTIO_MMIO_SIZE;
    let mut vsock_transport = VirtioMmioTransport::new(vsock, vsock_base);

    // Host listens on port 1234 for responses from guest
    vsock_transport.device_mut().listen(HOST_PORT);
    // Host listens on port 7601 for outbound proxy connections
    vsock_transport.device_mut().listen(PROXY_PORT);

    // Create outbound proxy for guest networking
    let mut outbound_proxy = microvm::proxy::VsockOutboundProxy::new();

    // Track mapping from proxy conn_key to guest vsock port (src_port)
    // This is needed because when TCP data comes back, we need to know which vsock port to send it to
    let mut conn_key_to_guest_port: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();

    // Vsock connection state
    let mut vsock_connected = false;
    let mut vsock_connection_sent = false;
    let mut vsock_test_sent = false;
    let mut boot_complete = false;
    let boot_start = std::time::Instant::now();

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);
    let timer_ticks = Arc::new(AtomicU64::new(0));
    let timer_ticks_clone = Arc::clone(&timer_ticks);

    // Get vCPU handle for timer interrupt injection
    let _vcpu_handle = vm.vcpu_mut(0).map(|v| v.handle()).unwrap_or(0);

    // Counters for exit types
    let mut mmio_read_count = 0u64;
    let mut mmio_write_count = 0u64;
    let mut exception_count = 0u64;
    let mut shutdown_count = 0u64;
    let mut vtimer_count = 0u64;

    // Timer thread - force periodic exits
    std::thread::spawn(move || {
        let interval = std::time::Duration::from_millis(10);
        loop {
            std::thread::sleep(interval);
            if !running_clone.load(Ordering::Relaxed) {
                break;
            }
            timer_ticks_clone.fetch_add(1, Ordering::Relaxed);
            unsafe {
                microvm::backend::hvf::bindings::hv_vcpus_exit(&_vcpu_handle, 1);
            }
        }
    });

    let max_iterations = 100_000_000;
    let mut last_tick = 0u64;
    let start_time = std::time::Instant::now();
    let max_runtime = std::time::Duration::from_secs(300); // 5 minute timeout

    for i in 0..max_iterations {
        // Check for timeout
        if start_time.elapsed() > max_runtime {
            eprintln!("\n[Timeout after {:?}]", start_time.elapsed());
            eprintln!("[Exit counts: MMIO_R={}, MMIO_W={}, Shutdown={}, VTimer={}]",
                mmio_read_count, mmio_write_count, shutdown_count, vtimer_count);
            running.store(false, Ordering::Relaxed);
            break;
        }

        // Run vCPU and capture the exit reason
        let exit = {
            let vcpu = vm.vcpu_mut(0).unwrap();
            vcpu.run()
        };

        // Poll vsock RX queue on every vCPU exit to deliver pending responses
        // Note: TX processing is handled by MMIO QUEUE_NOTIFY handler
        {
            // Check if we have pending RX packets to deliver
            if vsock_transport.device_mut().has_rx_data() {
                // Sync RX queue and deliver responses
                if let Some(queue) = vsock_transport.queue(0).cloned() {
                    vsock_transport.device_mut().sync_rx_queue(&queue);
                }
                {
                    let memory = vm.memory_mut().as_mut_slice();
                    if vsock_transport.device_mut().process_rx(memory) {
                        vsock_transport.signal_interrupt();
                        gic.set_pending(32 + DeviceTreeBuilder::VIRTIO_VSOCK_IRQ);
                        // Inject IRQ to wake up vCPU
                        let vcpu = vm.vcpu_mut(0).unwrap();
                        let _ = vcpu.set_pending_interrupt(arm64_interrupt::HV_INTERRUPT_TYPE_IRQ, true);
                        println!("\n[VSOCK] Interrupt injected to vCPU");
                    }
                }
            }
        }

        // Check if we need to inject timer interrupt
        let current_tick = timer_ticks.load(Ordering::Relaxed);
        if current_tick > last_tick {
            last_tick = current_tick;
            // Set timer IRQ pending in GIC
            gic.set_pending(VTIMER_IRQ);
            // Inject IRQ signal to vCPU
            let vcpu = vm.vcpu_mut(0).unwrap();
            let _ = vcpu.set_pending_interrupt(arm64_interrupt::HV_INTERRUPT_TYPE_IRQ, true);

            // Periodically check for pending vsock RX packets (every timer tick ~ 10ms)
            {
                if vsock_transport.device_mut().has_rx_data() {
                    if let Some(queue) = vsock_transport.queue(0).cloned() {
                        vsock_transport.device_mut().sync_rx_queue(&queue);
                    }
                    {
                        let memory = vm.memory_mut().as_mut_slice();
                        if vsock_transport.device_mut().process_rx(memory) {
                            vsock_transport.signal_interrupt();
                            gic.set_pending(32 + DeviceTreeBuilder::VIRTIO_VSOCK_IRQ);
                            // Inject IRQ to wake up vCPU
                            let vcpu = vm.vcpu_mut(0).unwrap();
                            let _ = vcpu.set_pending_interrupt(arm64_interrupt::HV_INTERRUPT_TYPE_IRQ, true);
                        }
                    }
                }
            }
        }

        // Vsock connection logic - attempt after boot complete
        if boot_complete && !vsock_connection_sent {
            // Wait a bit more after boot complete for daemon to be ready
            if boot_start.elapsed() > std::time::Duration::from_secs(2) {
                println!("\n[HOST] Initiating vsock connection to guest port {}...", VSOCK_PORT);

                // Build and send CONNECTION REQUEST packet
                // vsock header: src_cid(8) + dst_cid(8) + src_port(4) + dst_port(4) + len(4) + type(2) + op(2) + flags(4) + buf_alloc(4) + fwd_cnt(4) = 44 bytes
                let mut pkt = vec![0u8; 44];
                // src_cid = HOST (2)
                pkt[0..8].copy_from_slice(&2u64.to_le_bytes());
                // dst_cid = GUEST (3)
                pkt[8..16].copy_from_slice(&GUEST_CID.to_le_bytes());
                // src_port = HOST_PORT
                pkt[16..20].copy_from_slice(&HOST_PORT.to_le_bytes());
                // dst_port = VSOCK_PORT (7600)
                pkt[20..24].copy_from_slice(&VSOCK_PORT.to_le_bytes());
                // len = 0 (no payload)
                pkt[24..28].copy_from_slice(&0u32.to_le_bytes());
                // type = STREAM (1)
                pkt[28..30].copy_from_slice(&1u16.to_le_bytes());
                // op = REQUEST (1)
                pkt[30..32].copy_from_slice(&1u16.to_le_bytes());
                // flags = 0
                pkt[32..36].copy_from_slice(&0u32.to_le_bytes());
                // buf_alloc = 64KB
                pkt[36..40].copy_from_slice(&(64 * 1024u32).to_le_bytes());
                // fwd_cnt = 0
                pkt[40..44].copy_from_slice(&0u32.to_le_bytes());

                // Queue packet to RX (host->guest)
                vsock_transport.device_mut().queue_raw_packet(pkt);

                // Sync all queues from transport to device (copy queue data first to avoid borrow issues)
                let queues: Vec<_> = (0..3).filter_map(|i| vsock_transport.queue(i).cloned()).collect();
                for (i, queue) in queues.iter().enumerate() {
                    match i {
                        0 => vsock_transport.device_mut().sync_rx_queue(queue),
                        1 => vsock_transport.device_mut().sync_tx_queue(queue),
                        2 => vsock_transport.device_mut().sync_event_queue(queue),
                        _ => {}
                    }
                }

                // Try to deliver the packet
                {
                    let memory = vm.memory_mut().as_mut_slice();
                    if vsock_transport.device_mut().process_rx(memory) {
                        vsock_transport.signal_interrupt();
                        gic.set_pending(32 + DeviceTreeBuilder::VIRTIO_VSOCK_IRQ);
                        println!("[HOST] CONNECTION REQUEST sent to guest");
                    } else {
                        println!("[HOST] Could not deliver REQUEST - RX queue not ready");
                    }
                }

                vsock_connection_sent = true;
            }
        }

        // Send test data after connection is established
        if vsock_connected && !vsock_test_sent {
            println!("\n[HOST] Sending JSON ping command to guest daemon...");

            // Build RW (data) packet with JSON command
            // The daemon expects: {"command": "ping"}\n
            let test_data = b"{\"command\": \"ping\"}\n";
            let mut pkt = vec![0u8; 44 + test_data.len()];
            // src_cid = HOST (2)
            pkt[0..8].copy_from_slice(&2u64.to_le_bytes());
            // dst_cid = GUEST (3)
            pkt[8..16].copy_from_slice(&GUEST_CID.to_le_bytes());
            // src_port = HOST_PORT
            pkt[16..20].copy_from_slice(&HOST_PORT.to_le_bytes());
            // dst_port = VSOCK_PORT (7600)
            pkt[20..24].copy_from_slice(&VSOCK_PORT.to_le_bytes());
            // len = payload length
            pkt[24..28].copy_from_slice(&(test_data.len() as u32).to_le_bytes());
            // type = STREAM (1)
            pkt[28..30].copy_from_slice(&1u16.to_le_bytes());
            // op = RW (5)
            pkt[30..32].copy_from_slice(&5u16.to_le_bytes());
            // flags = 0
            pkt[32..36].copy_from_slice(&0u32.to_le_bytes());
            // buf_alloc = 64KB
            pkt[36..40].copy_from_slice(&(64 * 1024u32).to_le_bytes());
            // fwd_cnt = 0
            pkt[40..44].copy_from_slice(&0u32.to_le_bytes());
            // payload
            pkt[44..].copy_from_slice(test_data);

            vsock_transport.device_mut().queue_raw_packet(pkt);

            // Sync RX queue and deliver
            if let Some(queue) = vsock_transport.queue(0).cloned() {
                vsock_transport.device_mut().sync_rx_queue(&queue);
            }

            {
                let memory = vm.memory_mut().as_mut_slice();
                if vsock_transport.device_mut().process_rx(memory) {
                    vsock_transport.signal_interrupt();
                    gic.set_pending(32 + DeviceTreeBuilder::VIRTIO_VSOCK_IRQ);
                    println!("[HOST] Test message sent to guest!");
                }
            }

            vsock_test_sent = true;
        }

        // Note: TX polling is now handled exclusively in QUEUE_NOTIFY to avoid consuming packets early

        match exit {
            Ok(VcpuExit::MmioWrite { addr, syndrome, .. }) => {
                mmio_write_count += 1;

                // Extract register from syndrome SRT field (bits 20:16)
                // ISV (bit 24) indicates if SRT is valid
                let isv = (syndrome >> 24) & 1;
                let srt = if isv == 1 {
                    ((syndrome >> 16) & 0x1F) as u32
                } else {
                    0 // Fallback to X0 if ISV not set
                };

                // Read registers first, then drop vcpu borrow
                let (pc, value) = {
                    let vcpu = vm.vcpu_mut(0).unwrap();
                    let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                    let value = vcpu.read_register(arm64_reg::HV_REG_X0 + srt).unwrap_or(0) as u32;
                    (pc, value)
                };

                if uart.contains(addr) {
                    // uart.write() already outputs to stdout, no need to print again
                    uart.write(addr, value);

                    // Check for boot complete signal (daemon listening)
                    // This is a simple heuristic - look for 'L' followed by 'i' (Listening)
                    if !boot_complete && value as u8 == b'L' {
                        // Check boot time - if > 0.5s, likely the daemon message
                        if boot_start.elapsed() > std::time::Duration::from_millis(500) {
                            boot_complete = true;
                            println!("\n[HOST] Boot complete detected, will attempt vsock connection...");
                        }
                    }
                } else if gic.contains(addr) {
                    gic.write(addr, value);
                } else if vsock_transport.contains(addr) {
                    let offset = addr - vsock_transport.base_addr();

                    // Debug: Track device activation timing
                    if offset == 0x70 {
                        // STATUS register write
                        let elapsed = boot_start.elapsed();
                        if value & 4 != 0 { // DRIVER_OK
                            println!("\n[VSOCK-INIT] DRIVER_OK set at {:?} (status=0x{:x})", elapsed, value);
                        }
                    }
                    if offset == 0x44 && value != 0 {
                        // QUEUE_READY set to 1
                        let queue_idx = vsock_transport.queue_sel();
                        let elapsed = boot_start.elapsed();
                        let queue_name = match queue_idx {
                            0 => "RX",
                            1 => "TX",
                            2 => "EVENT",
                            _ => "UNKNOWN",
                        };
                        println!("\n[VSOCK-INIT] {} queue ready at {:?}", queue_name, elapsed);
                    }

                    vsock_transport.write(addr, value);

                    // Check if this is a queue notify (offset 0x50)
                    if offset == 0x50 {
                        // Queue notification - the VALUE written contains the queue index being notified
                        // Note: This is different from queue_sel which is used for queue configuration
                        let queue_idx = value as usize;
                        if let Some(queue) = vsock_transport.queue(queue_idx).cloned() {
                            match queue_idx {
                                0 => vsock_transport.device_mut().sync_rx_queue(&queue),
                                1 => vsock_transport.device_mut().sync_tx_queue(&queue),
                                2 => vsock_transport.device_mut().sync_event_queue(&queue),
                                _ => {}
                            }
                        }

                        // Process TX queue (guest -> host)
                        let packets = {
                            let memory = vm.memory_mut().as_mut_slice();
                            vsock_transport.device_mut().process_tx(memory)
                        };
                        // Let the device handle connection management (REQUEST -> RESPONSE)
                        // and immediately deliver any responses to avoid timeout
                        for pkt in &packets {
                            vsock_transport.device_mut().process_tx_packet(pkt);
                            // Check if device queued a response - deliver immediately
                            {
                                let memory = vm.memory_mut().as_mut_slice();
                                if vsock_transport.device_mut().process_rx(memory) {
                                    vsock_transport.signal_interrupt();
                                    gic.set_pending(32 + DeviceTreeBuilder::VIRTIO_VSOCK_IRQ);
                                }
                            }
                        }
                        for pkt in &packets {
                            if pkt.len() >= 44 {
                                let op = u16::from_le_bytes([pkt[30], pkt[31]]);
                                let src_port = u32::from_le_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
                                let dst_port = u32::from_le_bytes([pkt[20], pkt[21], pkt[22], pkt[23]]);
                                let payload_len = pkt.len() - 44;

                                // Check if this is a proxy connection (port 7601)
                                if dst_port == PROXY_PORT && op == 5 && payload_len > 0 {
                                    // Handle proxy packet
                                    let payload = &pkt[44..];
                                    if payload.len() >= 13 {
                                        let pkt_type = payload[0];
                                        let conn_key = u64::from_le_bytes([
                                            payload[1], payload[2], payload[3], payload[4],
                                            payload[5], payload[6], payload[7], payload[8],
                                        ]);
                                        let proxy_payload_len = u32::from_le_bytes([
                                            payload[9], payload[10], payload[11], payload[12],
                                        ]) as usize;

                                        match pkt_type {
                                            0x01 => {
                                                // CONNECT request
                                                if payload.len() >= 13 + proxy_payload_len {
                                                    let connect_data = &payload[13..13 + proxy_payload_len];
                                                    if let Ok(request) = parse_connect_request(connect_data) {
                                                        let (response, conn_id_opt) = outbound_proxy.handle_connect(
                                                            &microvm::proxy::ConnectRequest::domain(&request.0, request.1),
                                                            conn_key,
                                                        );
                                                        // Store the mapping from conn_key to guest port
                                                        // This is needed to route TCP responses back to the right vsock port
                                                        if conn_id_opt.is_some() {
                                                            conn_key_to_guest_port.insert(conn_key, src_port);
                                                        }
                                                        // Send response back to guest
                                                        let resp_pkt = build_proxy_response(conn_key, &response);
                                                        vsock_transport.device_mut().queue_data_packet(
                                                            GUEST_CID, src_port, PROXY_PORT, &resp_pkt
                                                        );
                                                    }
                                                }
                                            }
                                            0x03 => {
                                                // DATA packet - forward to target
                                                if payload.len() >= 13 + proxy_payload_len {
                                                    let data = &payload[13..13 + proxy_payload_len];
                                                    if let Err(e) = outbound_proxy.forward_to_target(conn_key, data) {
                                                        eprintln!("[PROXY] Forward error: {}", e);
                                                    }
                                                }
                                            }
                                            0x04 => {
                                                // CLOSE packet
                                                outbound_proxy.close_connection(conn_key);
                                            }
                                            _ => {}
                                        }
                                    }
                                } else {
                                    // Regular vsock packet handling
                                    match op {
                                        1 => {
                                            // CONNECTION REQUEST
                                            // Note: The vsock device handles REQUEST/RESPONSE via its listener mechanism.
                                            // We don't need to manually send RESPONSE here - that would cause duplicates.
                                            println!("\n[VSOCK] Guest REQUEST from port {} to port {}", src_port, dst_port);
                                            if dst_port == PROXY_PORT {
                                                println!("[VSOCK] Proxy connection request - device will auto-respond");
                                            }
                                        }
                                        2 => {
                                            // RESPONSE - connection accepted
                                            println!("\n[VSOCK] Guest RESPONSE from port {} - connection established!", src_port);
                                            vsock_connected = true;
                                        }
                                        3 => println!("\n[VSOCK] Guest RST from port {}", src_port),
                                        5 => {
                                            // RW - data from guest
                                            if payload_len > 0 {
                                                let data = String::from_utf8_lossy(&pkt[44..]);
                                                println!("\n[VSOCK] Received {} bytes from guest port {}: {}", payload_len, src_port, data.trim());
                                            }
                                        }
                                        6 => {
                                            // CREDIT_UPDATE
                                            println!("\n[VSOCK] Guest CREDIT_UPDATE from port {}", src_port);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }

                        // Poll outbound proxy for incoming data from targets
                        let proxy_data = outbound_proxy.poll_connections();
                        for (conn_key, data) in proxy_data {
                            // Send data back to guest
                            let data_pkt = build_proxy_data_packet(conn_key, &data);
                            // Look up the guest's vsock port from our mapping
                            if let Some(&guest_port) = conn_key_to_guest_port.get(&conn_key) {
                                vsock_transport.device_mut().queue_data_packet(
                                    GUEST_CID, guest_port, PROXY_PORT, &data_pkt
                                );
                            }
                        }

                        // Process RX queue (host -> guest)
                        {
                            let memory = vm.memory_mut().as_mut_slice();
                            if vsock_transport.device_mut().process_rx(memory) {
                                // Packets were delivered, signal interrupt
                                vsock_transport.signal_interrupt();
                                gic.set_pending(32 + DeviceTreeBuilder::VIRTIO_VSOCK_IRQ);
                            }
                        }
                    }
                }
                // Advance PC
                {
                    let vcpu = vm.vcpu_mut(0).unwrap();
                    let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
                }
            }
            Ok(VcpuExit::MmioRead { addr, syndrome, .. }) => {
                mmio_read_count += 1;

                // Extract register from syndrome SRT field (bits 20:16)
                // ISV (bit 24) indicates if SRT is valid
                let isv = (syndrome >> 24) & 1;
                let srt = if isv == 1 {
                    ((syndrome >> 16) & 0x1F) as u32
                } else {
                    0 // Fallback to X0 if ISV not set
                };

                let value = if uart.contains(addr) {
                    uart.read(addr)
                } else if gic.contains(addr) {
                    gic.read(addr)
                } else if vsock_transport.contains(addr) {
                    vsock_transport.read(addr)
                } else {
                    0
                };

                // Write result to the correct destination register
                let vcpu = vm.vcpu_mut(0).unwrap();
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                let _ = vcpu.write_register(arm64_reg::HV_REG_X0 + srt, value as u64);
                let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
            }
            Ok(VcpuExit::Shutdown) => {
                shutdown_count += 1;
                // This is triggered by our timer thread's hv_vcpus_exit
                // Just continue - the timer injection happens at the top of the loop
                continue;
            }
            Ok(VcpuExit::Hlt) => {
                let vcpu = vm.vcpu_mut(0).unwrap();
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                println!("\n--- Guest halted at PC=0x{:x} ---", pc);
                running.store(false, Ordering::Relaxed);
                break;
            }
            Ok(VcpuExit::VTimer) => {
                vtimer_count += 1;
                // Virtual timer fired - the ARM generic timer works via system registers,
                // not GIC MMIO. The kernel reads CNTV_CTL_EL0 directly.
                // Just mask the timer to prevent re-triggering and let kernel handle it.
                let vcpu = vm.vcpu_mut(0).unwrap();
                let _ = vcpu.set_vtimer_mask(true);  // Mask to prevent immediate re-exit
                // Inject IRQ so kernel takes interrupt exception
                let _ = vcpu.set_pending_interrupt(arm64_interrupt::HV_INTERRUPT_TYPE_IRQ, true);
            }
            Ok(VcpuExit::Wfi) => {
                // WFI - Wait For Interrupt.
                // Poll outbound proxy for incoming TCP data while guest is waiting
                let proxy_data = outbound_proxy.poll_connections();
                for (conn_key, data) in proxy_data {
                    // Send data back to guest via vsock
                    let data_pkt = build_proxy_data_packet(conn_key, &data);
                    // Look up the guest's vsock port from our mapping
                    if let Some(&guest_port) = conn_key_to_guest_port.get(&conn_key) {
                        vsock_transport.device_mut().queue_data_packet(
                            GUEST_CID, guest_port, PROXY_PORT, &data_pkt
                        );
                    }
                }

                // Process RX queue (host -> guest) if there's data
                {
                    let memory = vm.memory_mut().as_mut_slice();
                    if vsock_transport.device_mut().process_rx(memory) {
                        // Packets were delivered, signal interrupt
                        vsock_transport.signal_interrupt();
                        gic.set_pending(32 + DeviceTreeBuilder::VIRTIO_VSOCK_IRQ);
                    }
                }

                // If an interrupt is pending, inject it and continue
                // Otherwise, briefly sleep to wait for timer/IO
                if gic.get_pending_irq().is_some() {
                    let vcpu = vm.vcpu_mut(0).unwrap();
                    let _ = vcpu.set_pending_interrupt(arm64_interrupt::HV_INTERRUPT_TYPE_IRQ, true);
                } else {
                    // No interrupt pending - sleep briefly to wait for timer
                    std::thread::sleep(std::time::Duration::from_micros(100));
                }
                // Advance past WFI
                let vcpu = vm.vcpu_mut(0).unwrap();
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
            }
            Ok(VcpuExit::Hvc { .. }) | Ok(VcpuExit::Smc { .. }) => {
                // HVC/SMC call - handle PSCI
                use microvm::backend::hvf::bindings::arm64_sys_reg;

                // Read all registers first
                #[allow(unused_variables)]
                let (x0, x1, x2, x3, x8, x29, x30, pc, sp, ttbr1) = {
                    let vcpu = vm.vcpu_mut(0).unwrap();
                    (
                        vcpu.read_register(arm64_reg::HV_REG_X0).unwrap_or(0),
                        vcpu.read_register(arm64_reg::HV_REG_X1).unwrap_or(0),
                        vcpu.read_register(arm64_reg::HV_REG_X2).unwrap_or(0),
                        vcpu.read_register(arm64_reg::HV_REG_X3).unwrap_or(0),
                        vcpu.read_register(arm64_reg::HV_REG_X8).unwrap_or(0),
                        vcpu.read_register(arm64_reg::HV_REG_X29).unwrap_or(0),
                        vcpu.read_register(arm64_reg::HV_REG_X30).unwrap_or(0),
                        vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0),
                        vcpu.read_sys_register(arm64_sys_reg::HV_SYS_REG_SP_EL1).unwrap_or(0),
                        vcpu.read_sys_register(arm64_sys_reg::HV_SYS_REG_TTBR1_EL1).unwrap_or(0),
                    )
                };

                // Handle PSCI call (debug output disabled for cleaner boot)
                let result = handle_psci_call(x0);
                // Uncomment for debugging:
                // eprintln!("[PSCI: fn=0x{:08x} -> 0x{:x}]", x0 as u32, result);

                // WORKAROUND: There's a cache coherency issue where LDR X4, [SP] loads 0
                // even though [SP] contains the correct value at HVC time.
                //
                // Instead of letting the kernel's SMCCC wrapper store results, we:
                // 1. Write results directly to the result struct via X8 (if X8 is valid)
                // 2. Skip the wrapper by jumping to LR (return to caller)
                //
                // Some PSCI calls don't provide a result pointer (X8=0), in which case
                // we just set X0 and advance PC normally.
                {
                    const RAM_BASE: u64 = 0x4000_0000;
                    let vcpu = vm.vcpu_mut(0).unwrap();
                    let _ = vcpu.write_register(arm64_reg::HV_REG_X0, result);

                    // Only do the wrapper skip if X8 is a valid kernel address
                    if x8 != 0 && (x8 & 0xffff_0000_0000_0000) == 0xffff_0000_0000_0000 {
                        drop(vcpu); // Need to drop to access memory
                        let memory = vm.memory_mut().as_mut_slice();
                        if let Some(res_pa) = translate_va_to_pa(memory, ttbr1, x8) {
                            // Convert PA to buffer offset (memory is mapped at RAM_BASE)
                            let offset = if res_pa >= RAM_BASE {
                                (res_pa - RAM_BASE) as usize
                            } else {
                                // PA is below RAM_BASE (shouldn't happen for kernel addresses)
                                usize::MAX
                            };
                            // Only write if offset is valid
                            if offset != usize::MAX && (offset + 32) <= memory.len() {
                                // SMCCC result struct: x0, x1, x2, x3 at offsets 0, 8, 16, 24
                                memory[offset..offset + 8]
                                    .copy_from_slice(&result.to_le_bytes());
                                memory[offset + 8..offset + 16]
                                    .copy_from_slice(&0u64.to_le_bytes());
                                memory[offset + 16..offset + 24]
                                    .copy_from_slice(&0u64.to_le_bytes());
                                memory[offset + 24..offset + 32]
                                    .copy_from_slice(&0u64.to_le_bytes());

                                // Skip the entire __arm_smccc_hvc function by jumping to LR
                                let vcpu = vm.vcpu_mut(0).unwrap();
                                let _ = vcpu.write_register(arm64_reg::HV_REG_PC, x30);
                            } else {
                                // PA/offset invalid, just advance PC normally
                                let vcpu = vm.vcpu_mut(0).unwrap();
                                let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
                            }
                        } else {
                            // Translation failed, just advance PC normally
                            let vcpu = vm.vcpu_mut(0).unwrap();
                            let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
                        }
                    } else {
                        // X8 is 0 or invalid - this is an inline HVC, just advance PC
                        let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
                    }
                }
            }
            Ok(VcpuExit::Unknown(1)) => {
                exception_count += 1;
                // Unknown exception
                let vcpu = vm.vcpu_mut(0).unwrap();
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);

                eprintln!("\n[Exception at PC=0x{:x}]", pc);

                // Skip the instruction and continue for a bit more
                if exception_count < 10 {
                    let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
                    continue;
                }
                break;
            }
            Ok(VcpuExit::Unknown(reason)) => {
                let vcpu = vm.vcpu_mut(0).unwrap();
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                println!("\n[Exit reason {} at PC=0x{:x}]", reason, pc);
                break;
            }
            Ok(VcpuExit::SystemRegAccess { reg, is_write, rt, .. }) => {
                // Handle system register access by providing a default value
                let vcpu = vm.vcpu_mut(0).unwrap();
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                if !is_write {
                    // For reads, return 0 to the destination register
                    let dest_reg = arm64_reg::HV_REG_X0 + rt as u32;
                    let _ = vcpu.write_register(dest_reg, 0);
                }
                // Advance past the instruction
                let _ = vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4);
            }
            Ok(exit) => {
                println!("\n[Unexpected exit: {:?}]", exit);
                break;
            }
            Err(e) => {
                let vcpu = vm.vcpu_mut(0).unwrap();
                let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                eprintln!("\n--- vCPU error: {} at PC=0x{:x} ---", e, pc);
                running.store(false, Ordering::Relaxed);
                break;
            }
        }

        // Progress indicator every million iterations
        if i > 0 && i % 1_000_000 == 0 {
            eprint!(".");
            let _ = std::io::stderr().flush();
        }

    }

    println!("\nBoot test completed.");
}

/// Parse a connect request from the proxy protocol.
fn parse_connect_request(data: &[u8]) -> Result<(String, u16), &'static str> {
    if data.len() < 6 {
        return Err("Connect request too short");
    }

    let _msg_type = data[0]; // Should be 0x01
    let addr_type = data[1];
    let addr_len = u16::from_le_bytes([data[2], data[3]]) as usize;

    if data.len() < 4 + addr_len + 2 {
        return Err("Connect request truncated");
    }

    let addr_bytes = &data[4..4 + addr_len];
    let port = u16::from_le_bytes([data[4 + addr_len], data[4 + addr_len + 1]]);

    let address = match addr_type {
        0x01 => {
            // IPv4
            if addr_len != 4 {
                return Err("Invalid IPv4 length");
            }
            format!("{}.{}.{}.{}", addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3])
        }
        0x03 => {
            // Domain
            String::from_utf8_lossy(addr_bytes).to_string()
        }
        _ => return Err("Unknown address type"),
    };

    Ok((address, port))
}

/// Build a proxy response packet.
fn build_proxy_response(conn_key: u64, response: &microvm::proxy::ConnectResponse) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(13 + 4);
    // Proxy packet header
    pkt.push(0x02); // Response type
    pkt.extend_from_slice(&conn_key.to_le_bytes());
    pkt.extend_from_slice(&4u32.to_le_bytes()); // Payload length
    // Response payload
    pkt.push(0x02); // MessageType::Response
    pkt.push(response.status as u8);
    pkt.extend_from_slice(&response.bound_port.to_le_bytes());
    pkt
}

/// Build a proxy data packet.
fn build_proxy_data_packet(conn_key: u64, data: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(13 + data.len());
    // Proxy packet header
    pkt.push(0x03); // Data type
    pkt.extend_from_slice(&conn_key.to_le_bytes());
    pkt.extend_from_slice(&(data.len() as u32).to_le_bytes());
    // Data payload
    pkt.extend_from_slice(data);
    pkt
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn run_linux_boot(kernel_path: &str, initrd_path: Option<&str>) {
    println!("x86_64 Linux boot not yet implemented");
    println!("Kernel: {}", kernel_path);
    if let Some(initrd) = initrd_path {
        println!("Initrd: {}", initrd);
    }
}

#[cfg(not(target_os = "macos"))]
fn run_linux_boot(_kernel_path: &str, _initrd_path: Option<&str>) {
    println!("Linux boot only supported on macOS currently");
}
