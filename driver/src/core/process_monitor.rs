//! The Process Monitor is responsible for monitoring and tracking processes through their lives
//! to detect indications of malicious behaviour.

use core::time::Duration;

use alloc::{collections::btree_map::BTreeMap, string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use shared_no_std::{driver_ipc::ProcessStarted, ghost_hunting::{DLLMessage, NtFunction, Syscall, SyscallEventSource}};
use wdk::println;
use wdk_mutex::{errors::GrtError, fast_mutex::FastMutexGuard, grt::Grt, kmutex::KMutex};
use wdk_sys::{ntddk::KeQuerySystemTimePrecise, LARGE_INTEGER};

/// A `Process` is a Sanctum driver representation of a Windows process so that actions it preforms, and is performed
/// onto it, can be tracked and monitored.
pub struct Process {
    pid: u64,
    /// Parent pid
    ppid: u64,
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

    pub fn onboard_new_process(process: &ProcessStarted) -> Result<(), ProcessErrors> {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        if process_lock.get(&process.pid).is_some() {
            return Err(ProcessErrors::DuplicatePid);
        }

        // todo this actually needs filling out with the relevant data
        process_lock.insert(process.pid, Process {
            pid: process.pid,
            ppid: process.parent_pid,
            process_image: process.image_name.clone(),
            commandline_args: process.command_line.clone(),
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

    /// Notifies the Ghost Hunting management that a new huntable event has occurred.
    pub fn ghost_hunt_add_event(
        pid: u64,
        signal: Syscall,
    ) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        if let Some(process) = process_lock.get_mut(&pid) {
            let mut current_time = LARGE_INTEGER::default();
            unsafe { KeQuerySystemTimePrecise(&mut current_time) };

            process.add_ghost_hunt_timer(GhostHuntingTimer { 
                timer_start: current_time, 
                cancellable_by: signal.nt_function.find_cancellable_apis_ghost_hunting(),
                event_type: signal.nt_function,
                origin: signal.source,
                weight: signal.evasion_weight,
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
                QuadPart: ((max_time_allowed.as_nanos() / 100) as i64),
            };

            let mut index: usize = 0; // index of iterator over the ghost timers
            for item in &process.ghost_hunting_timers {

                let mut current_time = LARGE_INTEGER::default();
                unsafe { KeQuerySystemTimePrecise(&mut current_time) };
                println!("[sanctum] [i] Current time queried.");

                // We are only running the driver on x64, so we can compute the delta using the QuadPart.

                let time_delta = unsafe { current_time.QuadPart - item.timer_start.QuadPart };

                if time_delta > unsafe { max_time_allowed.QuadPart } {
                    println!("[sanctum] [i] Time delta greater than inner! delta: {}, current {}, item: {}, max: {}", time_delta, unsafe {current_time.QuadPart}, unsafe { item.timer_start.QuadPart}, unsafe { max_time_allowed.QuadPart } );
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

    pub fn handle_syscall_ghost_hunt_event(data: &Syscall) {
        println!("[sanctum] [i] Syscall ghost hunt data: {:?}", data);
        ProcessMonitor::ghost_hunt_add_event(data.pid, data.clone());
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

/// Remove an event source from a given Ghost Hunting timer.
///
/// This function will modify the timer object to remove a cancellable event origin in place.
///
/// # Args
/// - `timer`: A mutable reference to the GhostHuntingTimer for a given process
#[inline(always)]
fn unset_event_flag_in_timer(timer: &mut GhostHuntingTimer) {
    timer.cancellable_by = timer.cancellable_by as isize ^ timer.origin as isize;
    // flip the set bit back to a 0
}

impl Process {
    fn add_ghost_hunt_timer(
        &mut self,
        mut timer: GhostHuntingTimer,
    ) {
        // If the timers are empty; then its the first in so we can add it to the list straight up.
        if self.ghost_hunting_timers.is_empty() {
            // remove the current notification from the cancellable by (prevent dangling timers)
            unset_event_flag_in_timer(&mut timer);
            self.ghost_hunting_timers.push(timer);
            return;
        }

        // Otherwise, there is data in the ghost hunting timers ...
        for (index, timer_iter) in self.ghost_hunting_timers.iter_mut().enumerate() {
            // If the API Origin that this fn relates to is found in the list of cancellable APIs then cancel them out.
            // Part of the core Ghost Hunting logic. First though we need to check that the event type that can cancel it out
            // is present in the active flags (bugs were happening where other events of the same type were being XOR'ed, so if they
            // were previously unset, the flag  was being reset and the process was therefore failing).
            // To get around this we do a bitwise& check before running the XOR in unset_event_flag_in_timer.
            if core::mem::discriminant(&timer_iter.event_type) == core::mem::discriminant(&timer.event_type) {
                if timer_iter.cancellable_by & timer.origin as isize == timer.origin as isize {
                    unset_event_flag_in_timer(timer_iter);

                    // If everything is cancelled out (aka all bit fields set to 0 remove the timer completely from the process)
                    if timer_iter.cancellable_by == 0 {
                        self.ghost_hunting_timers.remove(index);
                        return;
                    }

                    return;
                }
            }
        }

        // we did not match on the above timer.event_type in the list of active timers, so add the element as a new timer
        // remove the current notification from the cancellable by (prevent dangling timers)
        unset_event_flag_in_timer(&mut timer);
        self.ghost_hunting_timers.push(timer);
    }
}