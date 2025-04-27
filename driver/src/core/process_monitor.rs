//! The Process Monitor is responsible for monitoring and tracking processes through their lives
//! to detect indications of malicious behaviour.

use core::time::Duration;

use alloc::{collections::btree_map::BTreeMap, string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use wdk::println;
use wdk_mutex::{errors::GrtError, fast_mutex::FastMutexGuard, grt::Grt, kmutex::KMutex};
use wdk_sys::{ntddk::KeQuerySystemTimePrecise, LARGE_INTEGER};

/// A `Process` is a Sanctum driver representation of a Windows process so that actions it preforms, and is performed
/// onto it, can be tracked and monitored.
pub struct Process {
    pid: u64,
    pub process_image: String,
    pub commandline_args: String,
    pub risk_score: u16,
    pub allow_listed: bool, // whether the application is allowed to exist without monitoring
    /// Creates a time window in which a process handle must match from a hooked syscall with
    /// the kernel receiving the notification. Failure to match this may be an indicator of hooked syscall evasion.
    pub ghost_hunting_timers: Vec<GhostHuntingTimer>,
    targeted_by_apis: Vec<ProcessTargetedApis>,
}

// todo
#[derive(Debug, Default)]
pub struct ProcessTargetedApis {}

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

/// A `GhostHuntingTimer` is the timer metadata associated with the Ghost Hunting technique on my blog:
/// https://fluxsec.red/edr-syscall-hooking
///
/// The data contained in this struct allows timers to be polled and detects abuse of direct syscalls / hells gate.
pub struct GhostHuntingTimer {
    // Query the time via `KeQuerySystemTime`
    pub timer_start: LARGE_INTEGER,
    pub event_type: NtFunction,
    /// todo update docs
    pub origin: SyscallEventSource,
    /// Specifies which syscall types of a matching event this is cancellable by. As the EDR monitors multiple
    /// sources of telemetry, we cannot do a 1:1 cancellation process.
    /// todo update docs
    pub cancellable_by: isize,
    pub weight: i16,
}

/// The ProcessMonitor is responsible for monitoring all processes running; this
/// structure holds a hashmap of all processes by the pid as an integer, and
/// the data within is a MonitoredProcess containing the details
///
/// The key of processes hashmap is the pid, which is duplicated inside the Process
/// struct.
pub struct ProcessMonitor;

#[derive(Debug)]
pub enum ProcessErrors {
    PidNotFound,
    DuplicatePid,
    BadHandle,
    BadFnAddress,
    BaseAddressNull,
    FailedToWriteMemory,
    FailedToCreateRemoteThread,
    FailedToOpenProcess,
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
    pub target_pid: u64,
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtWriteVirtualMemoryData {
    pub target_pid: u64,
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
    pub remote_pid: u64,
}

impl ProcessMonitor {
    /// Instantiates a new `ProcessMonitor`; which is just an interface for access to the underlying 
    /// globally managed mutex via `Grt` (my `wdk-mutex` crate).
    /// 
    /// This function should only be called once on driver initialisation.
    /// 
    /// The `ProcessMonitor` is required for use in driver callback routines, therefore we can either track via a single
    /// static; or use the `Grt` design pattern (favoured in this case).
    pub fn new() -> Result<(), GrtError> {
        Grt::register_fast_mutex("ProcessMonitor", BTreeMap::<u64, Process>::new())
    }

    pub fn onboard_new_process(pid: u64) -> Result<(), ProcessErrors> {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        if process_lock.get(&pid).is_some() {
            return Err(ProcessErrors::DuplicatePid);
        }

        // todo this actually needs filling out with the relevant data
        process_lock.insert(pid, Process {
            pid,
            process_image: String::new(),
            commandline_args: String::new(),
            risk_score: 0,
            allow_listed: false,
            ghost_hunting_timers: Vec::new(),
            targeted_by_apis: Vec::new(),
        });

        Ok(())
    }

    pub fn remove_process(pid: u64) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();
        process_lock.remove(&pid);
    }

    pub fn ghost_hunt_add_event(pid: u64) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        if let Some(process) = process_lock.get_mut(&pid) {
            let mut current_time = LARGE_INTEGER::default();
            unsafe { KeQuerySystemTimePrecise(&mut current_time) };

            process.add_ghost_hunt_timer(GhostHuntingTimer { 
                timer_start: current_time, 
                event_type: NtFunction::NtAllocateVirtualMemory(None),
                origin: SyscallEventSource::EventSourceKernel,
                cancellable_by: 1, 
                weight: 50,
            });
        }
    }

    /// This function is responsible for polling all Ghost Hunting timers to try match up hooked syscall API calls
    /// with kernel events sent from our driver.
    ///
    /// This is part of my Ghost Hunting technique https://fluxsec.red/edr-syscall-hooking
    pub fn poll_ghost_timers() {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        for (_, process) in process_lock.iter_mut() {
            if process.ghost_hunting_timers.is_empty() {
                continue;
            }

            println!("[sanctum] [i] Querying process byt pid: {}", process.pid);

            //
            // In here process each API event we are tracking in the ghost timers.
            //

            // todo URGENT try integrate the following into the windows-drivers-rs project:
            // https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/using-timers
            // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdftimer/nf-wdftimer-wdftimercreate
            // Kinda wanna do it as a driver POC for now, then once working, can try migrate it into the windows drivers
            // project so I can use event timers from the wdk, rather than a system thread.
            // todo it may also be better for now to use work items, rather than have the heavy work on the thread itself? Can
            // the thread just queue the work item? Is that betteR? idk

            // todo add to a struct somewhere
            let max_time_allowed = Duration::from_secs(3);
            let max_time_allowed = LARGE_INTEGER {
                QuadPart: -((max_time_allowed.as_nanos() / 100) as i64),
            };

            let mut index: usize = 0; // index of iterator over the ghost timers
            for item in &process.ghost_hunting_timers {

                let mut current_time = LARGE_INTEGER::default();
                unsafe { KeQuerySystemTimePrecise(&mut current_time) };
                println!("[sanctum] [i] Current time queried.");

                // We are only running the driver on x64, so we can compute the delta using the QuadPart.

                let time_delta = unsafe { current_time.QuadPart - item.timer_start.QuadPart };

                if time_delta > unsafe { max_time_allowed.QuadPart } {
                    println!("[sanctum] [i] Time delta greater than inner! {}", time_delta);
                } else {
                    println!("[sanctum] [i] Time delta smaller than inner! {}", time_delta);
                }


                // if let Ok(t) = item.timer_start.elapsed() {
                //     // if we are waiting on the ETW feed, it takes a little longer
                //     if item.cancellable_by & SyscallEventSource::EventSourceEtw as isize
                //         == SyscallEventSource::EventSourceEtw as isize
                //     {
                //         if t > MAX_WAIT_ETW {
                //             process.update_process_risk_score(item.weight);
                //             process.ghost_hunting_timers.remove(index);
                //             println!(
                //                 "******* RISK SCORE RAISED AS TIMER EXCEEDED on: {:?}, pid responsible: {}",
                //                 item.event_type, process.pid
                //             );
                //             break;
                //         }
                //     } else {
                //         if t > MAX_WAIT {
                //             process.update_process_risk_score(item.weight);
                //             process.ghost_hunting_timers.remove(index);
                //             println!(
                //                 "******* RISK SCORE RAISED AS TIMER EXCEEDED on: {:?}, pid responsible: {}",
                //                 item.event_type, process.pid
                //             );
                //             break;
                //         }
                //     }
                // }

                index += 1;
            }
        }
    }

    fn get_mtx_inner<'a>() -> FastMutexGuard<'a, BTreeMap::<u64, Process>> {
        // todo rather than panic, ? error
        let process_lock: FastMutexGuard<BTreeMap::<u64, Process>> = match Grt::get_fast_mutex("ProcessMonitor") {
            Ok(mtx) => {
                match mtx.lock() {
                    Ok(l) => l,
                    Err(e) => {
                        println!("[-] Error locking KMutex for new process. Panicking. {:?}", e);
                        panic!()
                    },
                }
            },
            Err(e) => {
                println!("[sanctum] [-] Could not lock fast mutex. {:?}", e);
                panic!()
            },
        };

        process_lock
    }
}

impl Process {
    fn add_ghost_hunt_timer(
        &mut self,
        origin: GhostHuntingTimer,
    ) {
        self.ghost_hunting_timers.push(origin);
    }
}