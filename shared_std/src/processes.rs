use std::time::SystemTime;
use serde::{Deserialize, Serialize};


/****************************** CONSTANT *******************************/

//
// The below constants are bitfields which are a design decision over using an enum. The logic of the `um_engine::core::core` 
// uses the bit fields as a mask to determine which event types (kernel, syscall hook, etw etc) are required to fully cancel
// out the ghost hunt timers.
//
// This is because not all events are capturable in the kernel without tampering with patch guard etc, so there are some events
// only able to be caught by ETW and the syscall hook.
//

// /// The event source came from the kernel, intercepted by the driver
// pub const EVENT_SOURCE_KERNEL: u8        = 0b0001;
// /// The event source came from a syscall hook
// pub const EVENT_SOURCE_SYSCALL_HOOK: u8  = 0b0010;
// /// The event source came from the PPL Service receiving ETW:TI
// pub const EVENT_SOURCE_ETW: u8           = 0b0100;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub origin: u8,
    /// Specifies which syscall types of a matching event this is cancellable by. As the EDR monitors multiple 
    /// sources of telemetry, we cannot do a 1:1 cancellation process.
    /// todo update docs
    pub cancellable_by: u8,
}

pub trait HasPid {
    fn get_pid(&self) -> u32;
    fn print_data(&self);
}

/*****************************************************************************/
/***                         EVENTS FROM SYSCALL HOOK                        */
/*****************************************************************************/

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SyscallData<T: HasPid> {
    pub inner: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenProcessData {
    pub pid: u32,
    pub target_pid: u32,
}

impl HasPid for OpenProcessData {
    fn get_pid(&self) -> u32 {
        self.pid
    }
    
    fn print_data(&self) {
        println!("{:?}", self);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteVirtualMemoryData {
    pub pid: u32,
    pub target_pid: u32,
    pub base_address: usize,
    pub buf_len: usize,
}

impl HasPid for WriteVirtualMemoryData {
    fn get_pid(&self) -> u32 {
        self.pid
    }

    fn print_data(&self) {
        println!("{:?}", self);
    }
}



/*****************************************************************************/
/***                                ETW EVENTS                                */
/*****************************************************************************/


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwData<T: HasPid> {
    pub inner: T,
}

/// Wrap an ETW event with an enum so that we can send messages between the process we have hooked and our EDR engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EtwMessage {
    // todo these have the same inner type, could this be condensed seeing as though we dont take the extra
    // telemetry from the ETW:TI?
    VirtualAllocEx(VirtualAllocExEtw),
    WriteProcessMemoryRemote(WriteProcessMemoryEtw),
}

/// ETW Telemetry for a process calling VirtualAllocEx
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualAllocExEtw {
    /// The pid of the process calling VirtualAllocEx
    pub pid: u32,
}

impl HasPid for VirtualAllocExEtw {
    fn get_pid(&self) -> u32 {
        self.pid
    }

    fn print_data(&self) {
        println!("{:?}", self);
    }
}

/// ETW Telemetry for a process calling WriteProcessMemoryEtw
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteProcessMemoryEtw {
    /// The pid of the process calling WriteProcessMemoryEtw
    pub pid: u32,
}

impl HasPid for WriteProcessMemoryEtw {
    fn get_pid(&self) -> u32 {
        self.pid
    }

    fn print_data(&self) {
        println!("{:?}", self);
    }
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
#[serde(bound(
    serialize = "T: Serialize",
    deserialize = "T: for<'a> Deserialize<'a>"
))]
pub struct SyscallEvent<T> 
where T: HasPid + Serialize + for<'a> Deserialize<'a> {
    nt_function: NtFunction,
    data: T,
    source: SyscallEventSource,
    evasion_weight: u8,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NtFunction {
    NtOpenProcess,
    NtWriteVirtualMemory,
    NtAllocateVirtualMemory,
}


/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtAllocateVirtualMemory {
    /// The pid of the process making the syscall
    pub pid: u32,
    /// The metadata associated with the syscall
    pub metadata: Option<NtAllocateVirtualMemoryMetadata>,
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtAllocateVirtualMemoryMetadata {
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

impl HasPid for NtAllocateVirtualMemory {
    fn get_pid(&self) -> u32 {
        self.pid
    }

    fn print_data(&self) {
        println!("{:?}", self);
    }
}