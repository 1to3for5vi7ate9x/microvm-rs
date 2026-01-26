//! Debug logging utilities for microvm.
//!
//! Set the `MICROVM_DEBUG` environment variable to enable verbose logging:
//! - `MICROVM_DEBUG=1` - Enable all debug output
//! - `MICROVM_DEBUG=vsock` - Enable only vsock-related logs
//! - `MICROVM_DEBUG=runtime` - Enable only runtime-related logs
//! - `MICROVM_DEBUG=vsock,runtime` - Enable multiple categories

use std::sync::OnceLock;

/// Debug categories that can be enabled
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugCategory {
    Vsock,
    Runtime,
    All,
}

/// Cached debug configuration
static DEBUG_CONFIG: OnceLock<DebugConfig> = OnceLock::new();

#[derive(Debug, Default)]
struct DebugConfig {
    enabled: bool,
    vsock: bool,
    runtime: bool,
}

impl DebugConfig {
    fn from_env() -> Self {
        match std::env::var("MICROVM_DEBUG") {
            Ok(val) if val == "1" || val.to_lowercase() == "all" => Self {
                enabled: true,
                vsock: true,
                runtime: true,
            },
            Ok(val) => {
                let val_lower = val.to_lowercase();
                Self {
                    enabled: true,
                    vsock: val_lower.contains("vsock"),
                    runtime: val_lower.contains("runtime"),
                }
            }
            Err(_) => Self::default(),
        }
    }
}

fn get_config() -> &'static DebugConfig {
    DEBUG_CONFIG.get_or_init(DebugConfig::from_env)
}

/// Check if debug logging is enabled for a category
pub fn is_debug_enabled(category: DebugCategory) -> bool {
    let config = get_config();
    if !config.enabled {
        return false;
    }
    match category {
        DebugCategory::All => config.vsock || config.runtime,
        DebugCategory::Vsock => config.vsock,
        DebugCategory::Runtime => config.runtime,
    }
}

/// Debug print macro for vsock-related logs
#[macro_export]
macro_rules! debug_vsock {
    ($($arg:tt)*) => {
        if $crate::debug::is_debug_enabled($crate::debug::DebugCategory::Vsock) {
            eprintln!($($arg)*);
        }
    };
}

/// Debug print macro for runtime-related logs
#[macro_export]
macro_rules! debug_runtime {
    ($($arg:tt)*) => {
        if $crate::debug::is_debug_enabled($crate::debug::DebugCategory::Runtime) {
            eprintln!($($arg)*);
        }
    };
}
