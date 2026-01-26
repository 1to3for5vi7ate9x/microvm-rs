//! Async VM runtime with device handling and vsock support.
//!
//! This module provides a complete VM runtime that handles:
//! - vCPU execution loop
//! - Device MMIO dispatch
//! - VirtIO vsock communication
//! - Timer interrupts
//!
//! # Example
//!
//! ```rust,no_run
//! use microvm::runtime::{VmRuntime, RuntimeConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = RuntimeConfig {
//!         memory_mb: 512,
//!         kernel_path: "/path/to/kernel".into(),
//!         initrd_path: Some("/path/to/initrd".into()),
//!         cmdline: "console=ttyAMA0".into(),
//!         ..Default::default()
//!     };
//!
//!     let (runtime, vsock_client) = VmRuntime::new(config)?;
//!
//!     // Start VM in background
//!     let handle = runtime.spawn();
//!
//!     // Communicate with guest via vsock
//!     let conn = vsock_client.connect(1025).await?;
//!     conn.send(b"{\"cmd\":\"ping\"}\n").await?;
//!     let response = conn.recv().await?;
//!
//!     // Shutdown
//!     handle.shutdown().await?;
//!     Ok(())
//! }
//! ```

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};

use crate::error::{Error, Result};
use crate::vsock::{VsockClient, VsockHandler, VsockMessage};
use crate::proxy::{ProxyConnectionManager, OUTBOUND_PROXY_PORT};
use crate::{debug_runtime, debug_vsock};

/// A writer that sends output through a channel
struct ChannelWriter {
    tx: mpsc::Sender<Vec<u8>>,
    buffer: Vec<u8>,
}

impl ChannelWriter {
    fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            tx,
            buffer: Vec::with_capacity(256),
        }
    }
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Also write to stdout for debugging
        std::io::stdout().write_all(buf)?;

        // Buffer the data
        self.buffer.extend_from_slice(buf);

        // Send on newline or when buffer is large
        if buf.contains(&b'\n') || self.buffer.len() > 1024 {
            let _ = self.tx.try_send(std::mem::take(&mut self.buffer));
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()?;
        if !self.buffer.is_empty() {
            let _ = self.tx.try_send(std::mem::take(&mut self.buffer));
        }
        Ok(())
    }
}

/// Configuration for the VM runtime.
pub struct RuntimeConfig {
    /// Memory size in megabytes.
    pub memory_mb: u32,
    /// Path to the kernel image.
    pub kernel_path: PathBuf,
    /// Path to the initrd (optional).
    pub initrd_path: Option<PathBuf>,
    /// Kernel command line.
    pub cmdline: String,
    /// Guest CID for vsock (default: 3).
    pub guest_cid: Option<u64>,
    /// Channel for console output (optional).
    pub console_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Channel for console input (optional, taken on spawn).
    pub console_rx: Option<mpsc::Receiver<Vec<u8>>>,
}

impl std::fmt::Debug for RuntimeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeConfig")
            .field("memory_mb", &self.memory_mb)
            .field("kernel_path", &self.kernel_path)
            .field("initrd_path", &self.initrd_path)
            .field("cmdline", &self.cmdline)
            .field("guest_cid", &self.guest_cid)
            .field("console_tx", &self.console_tx.is_some())
            .field("console_rx", &self.console_rx.is_some())
            .finish()
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            memory_mb: 512,
            kernel_path: PathBuf::new(),
            initrd_path: None,
            cmdline: String::new(),
            guest_cid: None,
            console_tx: None,
            console_rx: None,
        }
    }
}

/// Commands to control the VM runtime.
#[derive(Debug)]
pub enum RuntimeCommand {
    /// Request shutdown
    Shutdown,
    /// Force kill
    Kill,
}

/// Handle to control a running VM.
pub struct RuntimeHandle {
    /// Channel to send commands
    cmd_tx: mpsc::Sender<RuntimeCommand>,
    /// Channel to receive shutdown completion
    shutdown_rx: oneshot::Receiver<Result<()>>,
    /// Thread handle
    #[allow(dead_code)]
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl RuntimeHandle {
    /// Request graceful shutdown and wait for completion.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.cmd_tx.send(RuntimeCommand::Shutdown).await;
        self.shutdown_rx.await.map_err(|_| Error::DeviceError("Shutdown channel closed".into()))?
    }

    /// Force kill the VM.
    pub async fn kill(self) -> Result<()> {
        let _ = self.cmd_tx.send(RuntimeCommand::Kill).await;
        Ok(())
    }

    /// Check if the VM is still running.
    pub fn is_running(&self) -> bool {
        self.thread_handle.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
    }
}

/// VM runtime with full device support.
pub struct VmRuntime {
    config: RuntimeConfig,
    vsock_tx: mpsc::Sender<VsockMessage>,
    vsock_rx: Option<mpsc::Receiver<VsockMessage>>,
}

impl VmRuntime {
    /// Create a new VM runtime.
    ///
    /// Returns the runtime and a vsock client for communication.
    pub fn new(config: RuntimeConfig) -> Result<(Self, VsockClient)> {
        let guest_cid = config.guest_cid.unwrap_or(3);
        let (tx, rx) = mpsc::channel(256);
        let client = VsockClient::new(tx.clone(), guest_cid);

        Ok((
            Self {
                config,
                vsock_tx: tx,
                vsock_rx: Some(rx),
            },
            client,
        ))
    }

    /// Spawn the VM in a background thread.
    ///
    /// Returns a handle to control the VM.
    pub fn spawn(mut self) -> RuntimeHandle {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let vsock_rx = self.vsock_rx.take().expect("spawn called twice");
        let console_rx = self.config.console_rx.take();

        // Clone the clonable parts of config, move the rest
        let config = RuntimeConfig {
            memory_mb: self.config.memory_mb,
            kernel_path: self.config.kernel_path.clone(),
            initrd_path: self.config.initrd_path.clone(),
            cmdline: self.config.cmdline.clone(),
            guest_cid: self.config.guest_cid,
            console_tx: self.config.console_tx.clone(),
            console_rx: None, // Already taken
        };

        let thread_handle = thread::spawn(move || {
            let result = Self::run_event_loop(config, vsock_rx, cmd_rx, console_rx);
            let _ = shutdown_tx.send(result);
        });

        RuntimeHandle {
            cmd_tx,
            shutdown_rx,
            thread_handle: Some(thread_handle),
        }
    }

    /// Run the VM event loop (blocking).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn run_event_loop(
        config: RuntimeConfig,
        vsock_rx: mpsc::Receiver<VsockMessage>,
        mut cmd_rx: mpsc::Receiver<RuntimeCommand>,
        mut console_rx: Option<mpsc::Receiver<Vec<u8>>>,
    ) -> Result<()> {
        use crate::backend::hvf::bindings::{arm64_reg, arm64_interrupt};
        use crate::backend::hvf::{Vm, VcpuExit};
        use crate::backend::VmConfig;
        use crate::device::{Gic, Pl011, VirtioMmioTransport};
        use crate::device::virtio::vsock::VirtioVsock;
        use crate::loader::arm64::DeviceTreeBuilder;
        use crate::loader::{LinuxLoader, linux::MemoryWriter};

        let guest_cid = config.guest_cid.unwrap_or(3);

        // Create VM
        let vm_config = VmConfig {
            memory_mb: config.memory_mb,
            vcpus: 1,
            kernel: Some(config.kernel_path.clone()),
            initrd: config.initrd_path.clone(),
            rootfs: None,
            cmdline: config.cmdline.clone(),
        };

        let mut vm = Vm::new(&vm_config)?;

        // Load kernel using LinuxLoader
        let mut loader = LinuxLoader::new(&config.kernel_path)?;
        if let Some(ref initrd_path) = config.initrd_path {
            loader = loader.with_initrd(initrd_path)?;
        }
        loader = loader.with_cmdline(&config.cmdline);

        // Create a memory wrapper that implements MemoryWriter
        struct MemWrapper<'a>(&'a mut [u8]);
        impl MemoryWriter for MemWrapper<'_> {
            fn write(&mut self, addr: usize, data: &[u8]) -> Result<()> {
                if addr + data.len() <= self.0.len() {
                    self.0[addr..addr + data.len()].copy_from_slice(data);
                    Ok(())
                } else {
                    Err(Error::DeviceError("Memory write out of bounds".into()))
                }
            }
        }

        let kernel_info = {
            let memory = vm.memory_mut().as_mut_slice();
            let mut wrapper = MemWrapper(memory);
            loader.load(&mut wrapper)?
        };

        debug_runtime!("[RUNTIME] Kernel loaded at 0x{:x}, entry 0x{:x}", kernel_info.load_addr, kernel_info.entry);

        // Create devices
        let mut uart = if let Some(tx) = config.console_tx.clone() {
            let writer = ChannelWriter::new(tx);
            Pl011::with_output(Pl011::DEFAULT_BASE, Arc::new(Mutex::new(Box::new(writer))))
        } else {
            Pl011::default()
        };
        let mut gic = Gic::new();

        // Create vsock device
        let vsock = VirtioVsock::new(guest_cid);
        let vsock_base = DeviceTreeBuilder::VIRTIO_MMIO_BASE + 2 * DeviceTreeBuilder::VIRTIO_MMIO_SIZE;
        let mut vsock_transport = VirtioMmioTransport::new(vsock, vsock_base);

        // Register listeners
        const HOST_PORT: u32 = 1234;
        const DAEMON_PORT: u32 = 1025;
        vsock_transport.device_mut().listen(HOST_PORT);
        vsock_transport.device_mut().listen(OUTBOUND_PROXY_PORT);
        debug_runtime!("[RUNTIME] Listening on vsock ports: {} (host), {} (proxy)", HOST_PORT, OUTBOUND_PROXY_PORT);

        // Create vsock handler
        let mut vsock_handler = VsockHandler::new(vsock_rx);

        // Create proxy connection manager for outbound internet access
        let mut proxy_manager = ProxyConnectionManager::new();

        // Map proxy conn_key to vsock peer_port for routing responses
        let mut proxy_conn_to_vsock_port: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();

        // Build device tree
        let memory_size = (config.memory_mb as u64) * 1024 * 1024;
        let dtb = DeviceTreeBuilder::build_with_devices(
            memory_size,
            &config.cmdline,
            kernel_info.initrd_start,
            kernel_info.initrd_end,
            false, // console
            false, // block
            true,  // vsock
            false, // net
        );

        // Place DTB at a safe location (16MB into RAM)
        let dtb_addr = 0x4100_0000u64;
        {
            let memory = vm.memory_mut().as_mut_slice();
            let dtb_offset = (dtb_addr - 0x4000_0000) as usize;
            if dtb_offset + dtb.len() <= memory.len() {
                memory[dtb_offset..dtb_offset + dtb.len()].copy_from_slice(&dtb);
            }
        }

        // Set up vCPU registers
        {
            let vcpu = vm.vcpu_mut(0).ok_or(Error::DeviceError("No vCPU".into()))?;
            vcpu.write_register(arm64_reg::HV_REG_PC, kernel_info.entry)?;
            vcpu.write_register(arm64_reg::HV_REG_X0, dtb_addr)?;
            vcpu.write_register(arm64_reg::HV_REG_CPSR, 0x3c5)?; // EL1h with IRQ/FIQ masked
        }

        // Run loop state
        let running = Arc::new(AtomicBool::new(true));
        let boot_start = Instant::now();
        let mut daemon_connected = false;
        let mut last_connection_attempt: Option<Instant> = None;
        const MAX_CONNECTION_RETRIES: u32 = 20;
        let mut connection_retries = 0u32;
        let mut vsock_queues_synced = false;
        let mut last_rx_check = Instant::now();
        let mut last_timer_inject = Instant::now();
        const TIMER_INTERVAL_MS: u64 = 10; // Inject timer every 10ms (100 Hz)

        debug_runtime!("[RUNTIME] VM started, entering run loop");

        // Get a handle for forcing vCPU exit from the timer thread
        let vcpu_exit_handle = {
            let vcpu = vm.vcpu_mut(0).ok_or(Error::DeviceError("No vCPU".into()))?;
            vcpu.get_exit_handle()
        };

        // Spawn a timer thread that periodically forces vCPU exit
        // This ensures vcpu.run() returns even when guest is CPU-bound
        let timer_running = running.clone();
        let timer_handle = std::thread::spawn(move || {
            while timer_running.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(10)); // 100 Hz
                if timer_running.load(Ordering::Relaxed) {
                    let _ = vcpu_exit_handle.force_exit();
                }
            }
        });

        while running.load(Ordering::Relaxed) {
            // Check for commands (non-blocking)
            match cmd_rx.try_recv() {
                Ok(RuntimeCommand::Shutdown) => {
                    debug_runtime!("[RUNTIME] Shutdown requested");
                    running.store(false, Ordering::Relaxed);
                    break;
                }
                Ok(RuntimeCommand::Kill) => {
                    debug_runtime!("[RUNTIME] Kill requested");
                    running.store(false, Ordering::Relaxed);
                    break;
                }
                Err(_) => {} // No command, continue
            }

            // Check for console input and forward to UART
            // UART IRQ is SPI 1 = 32 + 1 = 33 (defined in device tree)
            const UART_IRQ: u32 = 33;
            if let Some(ref mut rx) = console_rx {
                match rx.try_recv() {
                    Ok(data) => {
                        debug_runtime!("[CONSOLE_INPUT] Received {} bytes: {:?}", data.len(),
                                  String::from_utf8_lossy(&data));
                        uart.queue_input(&data);
                        // Signal UART RX interrupt so the kernel's tty driver reads the data
                        gic.set_pending(UART_IRQ);
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        debug_runtime!("[CONSOLE_INPUT] Channel disconnected");
                        console_rx = None; // Channel closed
                    }
                }
            }

            // Sync vsock queues when device becomes ready (DRIVER_OK)
            if !vsock_queues_synced && vsock_transport.is_driver_ok() {
                // Check if all 3 queues are ready
                if vsock_transport.is_queue_ready(0) &&
                   vsock_transport.is_queue_ready(1) &&
                   vsock_transport.is_queue_ready(2) {
                    debug_runtime!("[RUNTIME] Syncing vsock queues...");
                    if let Some(q) = vsock_transport.queue(0).cloned() {
                        debug_runtime!("[RUNTIME] RX queue (0): desc=0x{:x} avail=0x{:x} used=0x{:x} size={} ready={}",
                                  q.desc_table, q.avail_ring, q.used_ring, q.size, q.ready);
                        vsock_transport.device_mut().sync_rx_queue(&q);
                    }
                    if let Some(q) = vsock_transport.queue(1).cloned() {
                        debug_runtime!("[RUNTIME] TX queue (1): desc=0x{:x} avail=0x{:x} used=0x{:x} size={} ready={}",
                                  q.desc_table, q.avail_ring, q.used_ring, q.size, q.ready);
                        vsock_transport.device_mut().sync_tx_queue(&q);
                    }
                    if let Some(q) = vsock_transport.queue(2).cloned() {
                        debug_runtime!("[RUNTIME] Event queue (2): desc=0x{:x} avail=0x{:x} used=0x{:x} size={} ready={}",
                                  q.desc_table, q.avail_ring, q.used_ring, q.size, q.ready);
                        vsock_transport.device_mut().sync_event_queue(&q);
                    }
                    vsock_queues_synced = true;
                    debug_runtime!("[RUNTIME] Vsock queues synced and ready");
                }
            }

            // Proactively process RX queue to deliver pending packets to guest
            // This is critical - don't wait for QUEUE_NOTIFY to deliver host->guest data
            if vsock_queues_synced {
                // Check periodically (every 1ms) to avoid spinning
                if last_rx_check.elapsed() > Duration::from_millis(1) {
                    last_rx_check = Instant::now();

                    // Deliver any pending RX packets to guest
                    if vsock_transport.device_mut().has_rx_data() {
                        let memory = vm.memory_mut().as_mut_slice();
                        if vsock_transport.device_mut().process_rx(memory) {
                            vsock_transport.signal_interrupt();
                            gic.set_pending(32 + DeviceTreeBuilder::VIRTIO_VSOCK_IRQ);
                        }
                    }

                    // Also check TX queue for responses from guest (e.g., CONNECTION RESPONSE)
                    // process_tx already calls process_tx_packet internally
                    if vsock_transport.device_mut().tx_queue_ready() {
                        let packets = {
                            let memory = vm.memory_mut().as_mut_slice();
                            vsock_transport.device_mut().process_tx(memory)
                        };

                        // Check for data packets to deliver to pending recvs or proxy
                        for pkt in &packets {
                            if pkt.len() >= 44 {
                                let op = u16::from_le_bytes([pkt[30], pkt[31]]);
                                let src_port = u32::from_le_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
                                let dst_port = u32::from_le_bytes([pkt[20], pkt[21], pkt[22], pkt[23]]);

                                if op == 5 { // RW
                                    let payload = &pkt[44..];
                                    if !payload.is_empty() {
                                        // Route based on destination port
                                        if dst_port == OUTBOUND_PROXY_PORT {
                                            // Proxy protocol traffic
                                            debug_vsock!("[PROXY] Received {} bytes from guest port {}", payload.len(), src_port);

                                            // Extract conn_key from CONNECT packets to map vsock port
                                            // Proxy packet header: type(1) + conn_key(8) + payload_len(4) = 13 bytes
                                            if payload.len() >= 13 {
                                                let pkt_type = payload[0];
                                                let conn_key = u64::from_le_bytes([
                                                    payload[1], payload[2], payload[3], payload[4],
                                                    payload[5], payload[6], payload[7], payload[8],
                                                ]);

                                                if pkt_type == 0x01 {  // CONNECT
                                                    debug_vsock!("[PROXY] Mapping conn_key {} -> vsock port {}", conn_key, src_port);
                                                    proxy_conn_to_vsock_port.insert(conn_key, src_port);
                                                } else if pkt_type == 0x04 {  // CLOSE
                                                    debug_vsock!("[PROXY] Removing conn_key {} mapping", conn_key);
                                                    proxy_conn_to_vsock_port.remove(&conn_key);
                                                }
                                            }

                                            let responses = proxy_manager.process_incoming(payload);
                                            for resp in responses {
                                                // Send proxy response back to guest
                                                vsock_transport.device_mut().queue_data_packet(
                                                    guest_cid,
                                                    src_port,  // Guest's port
                                                    OUTBOUND_PROXY_PORT,  // Our port
                                                    &resp,
                                                );
                                            }
                                        } else {
                                            // Regular vsock traffic (daemon, etc.)
                                            debug_vsock!("[VSOCK] RW packet: src_port={} dst_port={} payload_len={}",
                                                      src_port, dst_port, payload.len());
                                            vsock_handler.complete_recv(dst_port, src_port, payload.to_vec());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Poll TCP connections for incoming data
                    if proxy_manager.has_connections() {
                        let tcp_data = proxy_manager.poll_tcp();
                        for (conn_key, data) in tcp_data {
                            // Look up which vsock peer_port corresponds to this conn_key
                            if let Some(&peer_port) = proxy_conn_to_vsock_port.get(&conn_key) {
                                debug_vsock!("[PROXY] Sending {} bytes to guest port {} (conn_key={})", data.len(), peer_port, conn_key);
                                vsock_transport.device_mut().queue_data_packet(
                                    guest_cid,
                                    peer_port,
                                    OUTBOUND_PROXY_PORT,
                                    &data,
                                );
                            } else {
                                debug_vsock!("[PROXY] WARNING: No vsock port mapping for conn_key {}, data lost!", conn_key);
                            }
                        }
                    }
                }
            }

            // Process vsock messages from client
            while let Some(msg) = vsock_handler.try_recv() {
                match msg {
                    VsockMessage::Connect { guest_port, response } => {
                        let local_port = vsock_handler.next_local_port();
                        if let Err(e) = vsock_transport.device_mut().connect_to_guest(local_port, guest_port) {
                            eprintln!("[RUNTIME] vsock connect failed: {}", e);
                            let _ = response.send(Err(format!("Connect failed: {}", e)));
                        } else {
                            let _ = response.send(Ok(local_port));
                        }
                    }
                    VsockMessage::Send { local_port, guest_port, data, response } => {
                        vsock_transport.device_mut().queue_data_packet(
                            guest_cid,
                            guest_port,
                            local_port,
                            &data,
                        );
                        let _ = response.send(Ok(data.len()));
                    }
                    VsockMessage::Recv { local_port, guest_port, response } => {
                        vsock_handler.add_pending_recv(local_port, guest_port, response);
                    }
                    VsockMessage::Close { local_port, guest_port } => {
                        vsock_transport.device_mut().close(local_port, guest_cid, guest_port);
                    }
                }
            }

            // Try to connect to daemon after boot (with retries for CRNG delay)
            // Must wait for vsock queues to be synced first!
            if vsock_queues_synced && boot_start.elapsed() > Duration::from_secs(5) && !daemon_connected && connection_retries < MAX_CONNECTION_RETRIES {
                let should_retry = last_connection_attempt
                    .map(|t| t.elapsed() > Duration::from_secs(2))
                    .unwrap_or(true);

                if should_retry {
                    connection_retries += 1;
                    last_connection_attempt = Some(Instant::now());

                    debug_runtime!("[RUNTIME] Connecting to daemon (attempt {}/{})", connection_retries, MAX_CONNECTION_RETRIES);
                    if let Err(e) = vsock_transport.device_mut().connect_to_guest(HOST_PORT, DAEMON_PORT) {
                        debug_runtime!("[RUNTIME] Connection attempt failed: {}", e);
                    } else {
                        debug_runtime!("[RUNTIME] Connection request queued, waiting for response...");
                    }
                }
            }

            // Check if daemon connection succeeded
            if connection_retries > 0 && !daemon_connected {
                if vsock_transport.device_mut().is_connected_to_guest(HOST_PORT, DAEMON_PORT) {
                    debug_runtime!("[RUNTIME] Connected to daemon!");
                    daemon_connected = true;
                }
            }

            // Inject periodic timer interrupts to keep the kernel's scheduler running
            // The ARM virtual timer (IRQ 27) needs to fire regularly for sleep() to work
            if last_timer_inject.elapsed() >= Duration::from_millis(TIMER_INTERVAL_MS) {
                last_timer_inject = Instant::now();
                gic.set_pending(crate::device::gic::VTIMER_IRQ);
            }

            // Inject pending interrupts BEFORE running vCPU
            // This ensures the guest receives interrupts even if not in WFI
            if let Some(irq) = gic.get_pending_irq() {
                // Only log non-timer interrupts to reduce spam
                if irq != crate::device::gic::VTIMER_IRQ {
                    debug_runtime!("[RUNTIME] Injecting IRQ {} to guest", irq);
                }
                let vcpu = vm.vcpu_mut(0).ok_or(Error::DeviceError("No vCPU".into()))?;
                vcpu.set_pending_interrupt(
                    arm64_interrupt::HV_INTERRUPT_TYPE_IRQ,
                    true,
                )?;
            }

            // Run vCPU
            let exit = {
                let vcpu = vm.vcpu_mut(0).ok_or(Error::DeviceError("No vCPU".into()))?;
                vcpu.run()
            };

            match exit {
                Ok(VcpuExit::MmioRead { addr, syndrome, .. }) => {
                    let value = if uart.contains(addr) {
                        uart.read(addr) as u64
                    } else if gic.contains(addr) {
                        gic.read(addr) as u64
                    } else if vsock_transport.contains(addr) {
                        vsock_transport.read(addr) as u64
                    } else {
                        0
                    };

                    let vcpu = vm.vcpu_mut(0).unwrap();
                    let srt = if (syndrome >> 24) & 1 == 1 {
                        ((syndrome >> 16) & 0x1F) as u32
                    } else {
                        0
                    };

                    // NOTE: In ARM64, SRT=31 means XZR (zero register) - writes are discarded
                    if srt != 31 {
                        vcpu.write_register(arm64_reg::HV_REG_X0 + srt, value)?;
                    }

                    // Advance PC
                    let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                    vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
                }
                Ok(VcpuExit::MmioWrite { addr, syndrome, .. }) => {
                    // Read value from vcpu register using syndrome decode
                    // ARM64 Data Abort syndrome (ESR_EL2 ISS field):
                    // - ISV (bit 24): Instruction Syndrome Valid
                    // - SAS (bits 23:22): Access Size (0=byte, 1=half, 2=word, 3=dword)
                    // - SSE (bit 21): Syndrome Sign Extend
                    // - SRT (bits 20:16): Source Register (if ISV=1)
                    // - SF (bit 15): Sixty-Four bit register
                    // - WnR (bit 6): Write not Read
                    let (value, pc) = {
                        let vcpu = vm.vcpu_mut(0).unwrap();
                        let isv = (syndrome >> 24) & 1;
                        let sas = ((syndrome >> 22) & 0x3) as u8;
                        let srt = ((syndrome >> 16) & 0x1F) as u32;

                        // Debug: log syndrome decode for virtio writes (disabled to reduce spam)
                        let _is_virtio = addr >= 0x0a000000 && addr < 0x0a003000;

                        // Read the source register
                        // NOTE: In ARM64, SRT=31 means XZR (zero register), not X31/SP!
                        let reg_value = if isv == 1 {
                            if srt == 31 {
                                // XZR - zero register
                                0
                            } else {
                                vcpu.read_register(arm64_reg::HV_REG_X0 + srt).unwrap_or(0)
                            }
                        } else {
                            // ISV not set - need to decode instruction to find register
                            debug_runtime!("[MMIO] WARNING: ISV not set for write at 0x{:x}, syndrome=0x{:x}", addr, syndrome);
                            // Read PC and try to fetch instruction
                            let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                            debug_runtime!("[MMIO] PC=0x{:x}, cannot decode instruction - returning X0", pc);
                            vcpu.read_register(arm64_reg::HV_REG_X0).unwrap_or(0)
                        };

                        // Mask value based on access size
                        let value = match sas {
                            0 => (reg_value & 0xFF) as u32,           // byte
                            1 => (reg_value & 0xFFFF) as u32,         // halfword
                            2 => (reg_value & 0xFFFFFFFF) as u32,     // word
                            3 => reg_value as u32,                     // doubleword (truncate)
                            _ => reg_value as u32,
                        };

                        let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                        (value, pc)
                    };

                    if uart.contains(addr) {
                        uart.write(addr, value);
                    } else if gic.contains(addr) {
                        gic.write(addr, value);
                    } else if vsock_transport.contains(addr) {
                        vsock_transport.write(addr, value);

                        // Handle queue notify for vsock
                        let offset = addr - vsock_base;
                        if offset == 0x50 {
                            let queue_idx = value as usize;
                            if let Some(queue) = vsock_transport.queue(queue_idx).cloned() {
                                match queue_idx {
                                    0 => vsock_transport.device_mut().sync_rx_queue(&queue),
                                    1 => vsock_transport.device_mut().sync_tx_queue(&queue),
                                    2 => vsock_transport.device_mut().sync_event_queue(&queue),
                                    _ => {}
                                }
                            }

                            // Process TX queue (process_tx calls process_tx_packet internally)
                            let packets = {
                                let memory = vm.memory_mut().as_mut_slice();
                                vsock_transport.device_mut().process_tx(memory)
                            };

                            // Check for data packets to deliver to pending recvs or proxy
                            for pkt in &packets {
                                if pkt.len() >= 44 {
                                    let op = u16::from_le_bytes([pkt[30], pkt[31]]);
                                    let src_port = u32::from_le_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
                                    let dst_port = u32::from_le_bytes([pkt[20], pkt[21], pkt[22], pkt[23]]);

                                    if op == 5 { // RW
                                        let payload = &pkt[44..];
                                        if !payload.is_empty() {
                                            // Route based on destination port
                                            if dst_port == OUTBOUND_PROXY_PORT {
                                                // Proxy protocol traffic
                                                debug_vsock!("[PROXY] Received {} bytes from guest port {} (notify)", payload.len(), src_port);

                                                // Extract conn_key from CONNECT packets to map vsock port
                                                if payload.len() >= 13 {
                                                    let pkt_type = payload[0];
                                                    let conn_key = u64::from_le_bytes([
                                                        payload[1], payload[2], payload[3], payload[4],
                                                        payload[5], payload[6], payload[7], payload[8],
                                                    ]);

                                                    if pkt_type == 0x01 {  // CONNECT
                                                        debug_vsock!("[PROXY] Mapping conn_key {} -> vsock port {} (notify)", conn_key, src_port);
                                                        proxy_conn_to_vsock_port.insert(conn_key, src_port);
                                                    } else if pkt_type == 0x04 {  // CLOSE
                                                        debug_vsock!("[PROXY] Removing conn_key {} mapping (notify)", conn_key);
                                                        proxy_conn_to_vsock_port.remove(&conn_key);
                                                    }
                                                }

                                                let responses = proxy_manager.process_incoming(payload);
                                                for resp in responses {
                                                    // Send proxy response back to guest
                                                    vsock_transport.device_mut().queue_data_packet(
                                                        guest_cid,
                                                        src_port,  // Guest's port
                                                        OUTBOUND_PROXY_PORT,  // Our port
                                                        &resp,
                                                    );
                                                }
                                            } else {
                                                // Regular vsock traffic (daemon, etc.)
                                                debug_vsock!("[VSOCK] RW packet (notify): src_port={} dst_port={} payload_len={}",
                                                          src_port, dst_port, payload.len());
                                                vsock_handler.complete_recv(dst_port, src_port, payload.to_vec());
                                            }
                                        }
                                    }
                                }
                            }

                            // Deliver pending RX packets
                            {
                                let memory = vm.memory_mut().as_mut_slice();
                                if vsock_transport.device_mut().process_rx(memory) {
                                    vsock_transport.signal_interrupt();
                                    gic.set_pending(32 + DeviceTreeBuilder::VIRTIO_VSOCK_IRQ);
                                }
                            }
                        }
                    }

                    // Advance PC
                    let vcpu = vm.vcpu_mut(0).unwrap();
                    vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
                }
                Ok(VcpuExit::Hvc { .. }) | Ok(VcpuExit::Smc { .. }) => {
                    // Handle PSCI calls (minimal implementation)
                    let vcpu = vm.vcpu_mut(0).unwrap();
                    let func_id = vcpu.read_register(arm64_reg::HV_REG_X0).unwrap_or(0) as u32;
                    let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);

                    debug_runtime!("[RUNTIME] HVC func_id=0x{:08x} at PC=0x{:x}", func_id, pc);

                    match func_id {
                        0x8400_0000 => { // PSCI_VERSION
                            vcpu.write_register(arm64_reg::HV_REG_X0, 0x0001_0001)?; // v1.1
                        }
                        0x8400_0001 => { // PSCI_CPU_SUSPEND
                            vcpu.write_register(arm64_reg::HV_REG_X0, 0)?; // SUCCESS
                        }
                        0x8400_0002 => { // PSCI_CPU_OFF
                            vcpu.write_register(arm64_reg::HV_REG_X0, 0)?; // SUCCESS
                        }
                        0xC400_0003 => { // PSCI_CPU_ON (64-bit)
                            vcpu.write_register(arm64_reg::HV_REG_X0, 0)?; // SUCCESS
                        }
                        0x8400_0004 => { // PSCI_AFFINITY_INFO
                            vcpu.write_register(arm64_reg::HV_REG_X0, 0)?; // ON
                        }
                        0x8400_0005 => { // PSCI_MIGRATE
                            vcpu.write_register(arm64_reg::HV_REG_X0, 0xFFFF_FFFF_FFFF_FFFF)?; // NOT_SUPPORTED
                        }
                        0x8400_0006 => { // PSCI_MIGRATE_INFO_TYPE
                            vcpu.write_register(arm64_reg::HV_REG_X0, 2)?; // NOT_SUPPORTED - TOS not present
                        }
                        0x8400_0008 | 0xC400_0008 => { // SYSTEM_OFF
                            debug_runtime!("[RUNTIME] PSCI SYSTEM_OFF");
                            running.store(false, Ordering::Relaxed);
                            vcpu.write_register(arm64_reg::HV_REG_X0, 0)?;
                        }
                        0x8400_0009 | 0xC400_0009 => { // SYSTEM_RESET
                            debug_runtime!("[RUNTIME] PSCI SYSTEM_RESET");
                            running.store(false, Ordering::Relaxed);
                            vcpu.write_register(arm64_reg::HV_REG_X0, 0)?;
                        }
                        0x8400_000A => { // PSCI_FEATURES
                            let feature_id = vcpu.read_register(arm64_reg::HV_REG_X1).unwrap_or(0) as u32;
                            // Return SUCCESS for known features, NOT_SUPPORTED for others
                            let result = match feature_id {
                                0x8400_0000 | 0x8400_0001 | 0x8400_0002 | 0xC400_0003 |
                                0x8400_0008 | 0x8400_0009 | 0x8400_000A => 0u64, // SUCCESS
                                _ => 0xFFFF_FFFF_FFFF_FFFF, // NOT_SUPPORTED
                            };
                            vcpu.write_register(arm64_reg::HV_REG_X0, result)?;
                        }
                        _ => {
                            debug_runtime!("[RUNTIME] Unknown PSCI func: 0x{:08x}", func_id);
                            vcpu.write_register(arm64_reg::HV_REG_X0, 0xFFFF_FFFF_FFFF_FFFF)?; // NOT_SUPPORTED
                        }
                    }

                    // Note: For HVC/SMC on HVF, PC already points to next instruction
                    // Do NOT advance PC here - HVF handles it
                }
                Ok(VcpuExit::Wfi) => {
                    // Deliver pending interrupts
                    if gic.get_pending_irq().is_some() {
                        let vcpu = vm.vcpu_mut(0).unwrap();
                        vcpu.set_pending_interrupt(
                            arm64_interrupt::HV_INTERRUPT_TYPE_IRQ,
                            true,
                        )?;
                    } else {
                        // Small sleep to avoid spinning
                        std::thread::sleep(Duration::from_micros(100));
                    }
                }
                Ok(VcpuExit::SystemRegAccess { .. }) => {
                    // Ignore system register accesses
                    let vcpu = vm.vcpu_mut(0).unwrap();
                    let pc = vcpu.read_register(arm64_reg::HV_REG_PC).unwrap_or(0);
                    vcpu.write_register(arm64_reg::HV_REG_PC, pc + 4)?;
                }
                Ok(VcpuExit::Unknown(reason)) => {
                    debug_runtime!("[RUNTIME] Unknown exit: {}", reason);
                }
                Ok(_) => {
                    // Other exit types - just continue
                }
                Err(e) => {
                    debug_runtime!("[RUNTIME] vCPU error: {}", e);
                    return Err(e);
                }
            }
        }

        // Wait for timer thread to finish
        let _ = timer_handle.join();

        debug_runtime!("[RUNTIME] VM stopped");
        Ok(())
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn run_event_loop(
        _config: RuntimeConfig,
        _vsock_rx: mpsc::Receiver<VsockMessage>,
        _cmd_rx: mpsc::Receiver<RuntimeCommand>,
        _console_rx: Option<mpsc::Receiver<Vec<u8>>>,
    ) -> Result<()> {
        Err(Error::HypervisorNotAvailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = RuntimeConfig::default();
        assert_eq!(config.memory_mb, 512);
        assert_eq!(config.guest_cid, None);
    }
}
