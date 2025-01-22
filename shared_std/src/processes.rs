use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

/// The Process is a structural representation of an individual process thats
/// running on the host machine, and keeping track of risk scores, and activity conducted
/// by processes. 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub pid: u64,
    pub process_image: String,
    pub commandline_args: String,
    pub risk_score: u16,
    pub allow_listed: bool, // whether the application is allowed to exist without monitoring
    pub sanctum_protected_process: bool, // scc (sanctum protected process) defines processes which require additional protections from access / abuse, such as lsass.exe.
    /// Creates a time window in which a process handle must match from a hooked syscall with
    /// the kernel receiving the notification. Failure to match this may be an indicator of hooked syscall evasion.
    pub ghost_hunting_timers: Vec<GhostHuntingTimers>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostHuntingTimers {
    pub pid: u32,
    pub timer: SystemTime,
    pub syscall_type: SyscallType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Syscall {
    OpenProcess(OpenProcessData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenProcessData {
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum SyscallType {
    OpenProcess = 20,
    CreateRemoteThread = 60,
}