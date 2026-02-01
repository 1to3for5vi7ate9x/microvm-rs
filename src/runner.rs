//! VM runner with multi-vCPU support.
//!
//! This module provides a high-level interface for running VMs with multiple vCPUs,
//! handling VM exits, and coordinating between threads.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::error::{Error, Result};

// Platform-specific VcpuExit imports
#[cfg(target_os = "macos")]
use crate::backend::hvf::VcpuExit;
#[cfg(target_os = "windows")]
use crate::backend::whp::VcpuExit;

// Provide a stub type for unsupported platforms
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[derive(Debug, Clone)]
pub enum VcpuExit {
    Unknown(u32),
}

/// Exit handler callback type.
/// Returns true to continue running, false to stop.
pub type ExitHandler = Box<dyn Fn(usize, &VcpuExit, &mut [u8]) -> ExitAction + Send + Sync>;

/// Action to take after handling a VM exit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExitAction {
    /// Continue running the vCPU.
    Continue,
    /// Stop this vCPU.
    Stop,
    /// Stop all vCPUs.
    StopAll,
}

/// vCPU thread state.
struct VcpuThread {
    /// Thread handle.
    handle: Option<JoinHandle<Result<()>>>,
    /// vCPU ID.
    #[allow(dead_code)]
    id: usize,
}

/// Multi-vCPU VM runner.
pub struct VmRunner {
    /// Whether the VM is running.
    running: Arc<AtomicBool>,
    /// vCPU threads.
    threads: Vec<VcpuThread>,
    /// Shared memory (accessible by all vCPUs).
    memory: Arc<Mutex<Vec<u8>>>,
}

impl VmRunner {
    /// Create a new VM runner.
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
            memory: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Set the shared memory buffer.
    pub fn set_memory(&mut self, memory: Vec<u8>) {
        *self.memory.lock().unwrap() = memory;
    }

    /// Get a clone of the running flag.
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    /// Check if the VM is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop all vCPUs.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Wait for all vCPU threads to complete.
    pub fn wait(&mut self) -> Result<()> {
        for thread in self.threads.drain(..) {
            if let Some(handle) = thread.handle {
                handle.join().map_err(|_| Error::VcpuError("Thread panicked".into()))??;
            }
        }
        Ok(())
    }
}

impl Default for VmRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple single-vCPU runner that runs in the current thread.
/// This is a simplified interface for basic use cases.
pub struct SimpleRunner {
    running: Arc<AtomicBool>,
}

impl SimpleRunner {
    /// Create a new simple runner.
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Get the running flag.
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    /// Stop the runner.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if still running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Default for SimpleRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// vCPU run loop configuration.
pub struct VcpuRunConfig {
    /// Maximum iterations before yielding.
    pub max_iterations: u64,
    /// Whether to print debug info on unknown exits.
    pub debug_unknown_exits: bool,
}

impl Default for VcpuRunConfig {
    fn default() -> Self {
        Self {
            max_iterations: u64::MAX,
            debug_unknown_exits: false,
        }
    }
}

/// Multi-threaded vCPU coordinator.
/// Manages running multiple vCPUs with shared state.
pub struct VcpuCoordinator {
    /// Shared running flag.
    running: Arc<AtomicBool>,
    /// Number of vCPUs.
    vcpu_count: usize,
    /// vCPU thread handles.
    handles: Vec<JoinHandle<Result<()>>>,
}

impl VcpuCoordinator {
    /// Create a new coordinator for the given number of vCPUs.
    pub fn new(vcpu_count: usize) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            vcpu_count,
            handles: Vec::with_capacity(vcpu_count),
        }
    }

    /// Get the running flag for sharing with threads.
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    /// Start all vCPUs.
    pub fn start(&mut self) {
        self.running.store(true, Ordering::SeqCst);
    }

    /// Stop all vCPUs.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Add a vCPU thread handle.
    pub fn add_handle(&mut self, handle: JoinHandle<Result<()>>) {
        self.handles.push(handle);
    }

    /// Wait for all threads to complete.
    pub fn wait(mut self) -> Vec<Result<()>> {
        self.handles
            .drain(..)
            .map(|h| h.join().unwrap_or_else(|_| Err(Error::VcpuError("Thread panicked".into()))))
            .collect()
    }

    /// Number of vCPUs.
    pub fn vcpu_count(&self) -> usize {
        self.vcpu_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_runner() {
        let runner = SimpleRunner::new();
        assert!(runner.is_running());
        runner.stop();
        assert!(!runner.is_running());
    }

    #[test]
    fn test_coordinator() {
        let mut coord = VcpuCoordinator::new(4);
        assert_eq!(coord.vcpu_count(), 4);
        assert!(!coord.is_running());
        coord.start();
        assert!(coord.is_running());
        coord.stop();
        assert!(!coord.is_running());
    }
}
