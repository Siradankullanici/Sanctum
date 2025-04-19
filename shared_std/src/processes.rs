use serde::{Deserialize, Serialize};
use std::{rc::Rc, time::SystemTime};

/// Bitfields which act as a mask to determine which event types (kernel, syscall hook, etw etc)
/// are required to fully cancel out the ghost hunt timers.
///
/// This is because not all events are capturable in the kernel without tampering with patch guard etc, so there are some events
/// only able to be caught by ETW and the syscall hook.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum SyscallEventSource {
    EventSourceKernel = 0x1,
    EventSourceSyscallHook = 0x2,
    EventSourceEtw = 0x4,
}

/****************************** GENERAL *******************************/

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
    pub ghost_hunting_timers: Vec<GhostHuntingTimer>,
}

/// A `GhostHuntingTimer` is the timer metadata associated with the Ghost Hunting technique on my blog:
/// https://fluxsec.red/edr-syscall-hooking
///
/// The data contained in this struct allows timers to be polled and detects abuse of direct syscalls / hells gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GhostHuntingTimer {
    pub timer: SystemTime,
    pub event_type: NtFunction,
    /// todo update docs
    pub origin: SyscallEventSource,
    /// Specifies which syscall types of a matching event this is cancellable by. As the EDR monitors multiple
    /// sources of telemetry, we cannot do a 1:1 cancellation process.
    /// todo update docs
    pub cancellable_by: isize,
    pub weight: i16,
}

/// A wrapper for IPC messages sent by the injected DLL in all processes. This allows the same IPC interface to
/// be used across any number of IPC senders, so long as the enum has a discriminant for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DLLMessage {
    SyscallWrapper(Syscall),
    NtdllOverwrite,
}

/****************************** SYSCALLS *******************************/

/// Information relating to a syscall event which happened on the device. This struct holds:
///
/// - `data`: This field is generic over T which must implement the `HasPid` trait. This field contains the metadata associated
/// with the syscall.
/// - `source`: Where the system event was captured, e.g. a hooked syscall, ETW, or the driver.
/// - `evasion_weight`: The weight associated with the event if EDR evasion is detected.
/// - todo: `event_weight` for general weighting if this occurs, same as the normal weight i guess?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Syscall {
    pub nt_function: NtFunction,
    pub pid: u32,
    pub source: SyscallEventSource,
    pub evasion_weight: i16,
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NtFunction {
    NtOpenProcess(Option<NtOpenProcessData>),
    NtWriteVirtualMemory(Option<NtWriteVirtualMemoryData>),
    NtAllocateVirtualMemory(Option<NtAllocateVirtualMemory>),
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtOpenProcessData {
    pub target_pid: u32,
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtWriteVirtualMemoryData {
    pub target_pid: u32,
    pub base_address: usize,
    pub buf_len: usize,
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtAllocateVirtualMemory {
    /// The base address is the base of the remote process which is stored as a usize but is actually a hex
    /// address and will need converting if using as an address.
    pub base_address: usize,
    /// THe size of the allocated memory
    pub region_size: usize,
    /// A bitmask containing flags that specify the type of allocation to be performed.
    pub allocation_type: u32,
    /// A bitmask containing page protection flags that specify the protection desired for the committed
    /// region of pages.
    pub protect: u32,
    /// The pid in which the allocation is taking place in
    pub remote_pid: u32,
}

impl Syscall {
    /// Creates a new Syscall data packet where the source is from the ETW module
    pub fn new_etw(pid: u32, nt_function: NtFunction, evasion_weight: i16) -> Self {
        Self {
            nt_function,
            pid,
            source: SyscallEventSource::EventSourceEtw,
            evasion_weight,
        }
    }
}

unsafe impl Send for Syscall {}
