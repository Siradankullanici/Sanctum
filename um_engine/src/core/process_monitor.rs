use std::collections::HashMap;

use shared_no_std::driver_ipc::ProcessStarted;
use shared_std::processes::Process;
use windows::Win32::{Storage::FileSystem::{DELETE, READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER}, System::Threading::{PROCESS_ALL_ACCESS, PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE}};

use crate::utils::log::Log;

/// The ProcessMonitor is responsible for monitoring all processes running; this 
/// structure holds a hashmap of all processes by the pid as an integer, and 
/// the data within is a MonitoredProcess containing the details
/// 
/// The key of processes hashmap is the pid, which is duplicated inside the Process
/// struct.
#[derive(Debug, Default)]
pub struct ProcessMonitor {
    processes: HashMap<u64, Process>
}

pub enum ProcessErrors {
    PidNotFound,
    DuplicatePid,
}


impl ProcessMonitor {
    pub fn new() -> Self {
        ProcessMonitor {
            processes: HashMap::new(),
        }
    }

    /// todo more fn comments
    pub async fn insert(&mut self, proc: &ProcessStarted) -> Result<(), ProcessErrors> {
        //
        // First check we aren't inserting a duplicate PID, this may happen if we haven't received
        // a notification that a process has been terminated; or that we have a new process queued to
        // insert before a delete item which is queued.
        // todo this can be solved by first batch running deletes, before running updates.
        //

        let e = self.processes.get(&proc.pid);
        if e.is_some() {
            return Err(ProcessErrors::DuplicatePid);
        }

        self.processes.insert(proc.pid, Process {
            pid: proc.pid,
            process_image: proc.image_name.clone(),
            commandline_args: proc.command_line.clone(),
            risk_score: 0,
            allow_listed: false,
            sanctum_protected_process: false,
        });

        Ok(())
    }

    pub async fn remove_process(&mut self, pid: u64) {
        self.processes.remove(&pid);
    }

    /// Extends the processes hashmap through the std extend function on the inner processes hashmap
    pub fn extend_processes(&mut self, foreign_hashmap: ProcessMonitor) {
        self.processes.extend(foreign_hashmap.processes);

        let logger = Log::new();
        logger.log(crate::utils::log::LogLevel::Info, &format!("Discovered {} running processes on startup.", self.processes.len()));
    }


    /// Query a given process by its Pid, returning information about the process
    pub fn query_process_by_pid(&self, pid: u64) -> Option<Process> {
        if let Some(process) = self.processes.get(&pid) {
            return Some(process.clone());
        } else {
            return None;
        }
    }

    pub fn add_handle(&self, pid: u64, target: u64, granted: u32, requested: u32) {
        let log = Log::new();   

        //
        // Do some basic error checking before adding data
        //
        if !self.processes.contains_key(&pid) {
            log.log(
                crate::utils::log::LogLevel::Error, 
                &format!("Source pid: {pid} not found when trying to process a handle request.")
            );

            return;
        }

        if !self.processes.contains_key(&target) {
            log.log(
                crate::utils::log::LogLevel::Error, 
                &format!("Target pid: {pid} not found when trying to process a handle request.")
            );

            return;
        }

        //
        // Determine the mask
        //
        if granted & PROCESS_ALL_ACCESS.0 != 0 {
            println!("ALL ACCESS RIGHTS")
        }
        if granted & PROCESS_CREATE_PROCESS.0 != 0 {
            println!("PROCESS_CREATE_PROCESS")
        }
        if granted & PROCESS_CREATE_THREAD.0 != 0 {
            println!("PROCESS_CREATE_THREAD")
        }
        if granted & PROCESS_DUP_HANDLE.0 != 0 {
            println!("PROCESS_DUP_HANDLE")
        }
        if granted & PROCESS_QUERY_INFORMATION.0 != 0 {
            println!("PROCESS_QUERY_INFORMATION")
        }
        if granted & PROCESS_QUERY_LIMITED_INFORMATION.0 != 0 {
            println!("PROCESS_QUERY_LIMITED_INFORMATION")
        }
        if granted & PROCESS_SET_INFORMATION.0 != 0 {
            println!("PROCESS_SET_INFORMATION")
        }
        if granted & PROCESS_SET_QUOTA.0 != 0 {
            println!("PROCESS_SET_QUOTA")
        }
        if granted & PROCESS_SUSPEND_RESUME.0 != 0 {
            println!("PROCESS_SUSPEND_RESUME")
        }
        if granted & PROCESS_TERMINATE.0 != 0 {
            println!("PROCESS_TERMINATE")
        }
        if granted & PROCESS_VM_READ.0 != 0 {
            println!("PROCESS_VM_READ")
        }
        if granted & PROCESS_VM_OPERATION.0 != 0 {
            println!("PROCESS_VM_OPERATION")
        }
        if granted & PROCESS_VM_WRITE.0 != 0 {
            println!("PROCESS_VM_WRITE")
        }
        if granted & SYNCHRONIZE.0 != 0 {
            println!("SYNCHRONIZE")
        }
        if granted & DELETE.0 != 0 {
            println!("DELETE")
        }
        if granted & READ_CONTROL.0 != 0 {
            println!("READ_CONTROL")
        }
        if granted & WRITE_DAC.0 != 0 {
            println!("WRITE_DAC")
        }
        if granted & WRITE_OWNER.0 != 0 {
            println!("WRITE_OWNER")
        }
        



    }
}