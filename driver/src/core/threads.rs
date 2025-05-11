//! This module handles callback implementations and and other function related to processes.

use core::{arch::asm, ffi::{c_void, CStr}, ptr::null_mut, str};

use wdk::{nt_success, println};
use wdk_sys::{ntddk::{IoThreadToProcess, PsGetProcessId, PsLookupProcessByProcessId, PsSetCreateThreadNotifyRoutine, ZwClose, ZwOpenProcess}, BOOLEAN, CLIENT_ID, DISPATCHER_HEADER, PROCESS_ALL_ACCESS, _KTHREAD};

use crate::alt_syscalls::{AltSyscallStatus, AltSyscalls};

/// Instructs the driver to register the thread creation callback routine.
pub fn set_thread_creation_callback() {
    if unsafe { PsSetCreateThreadNotifyRoutine(Some(thread_callback)) } != 0 {
        println!("Failed to call set_thread_creation_callback");
    }
}

/// The callback routine that specifically deals with thread creation monitoring. This function is used to handle:
///
/// - Newly created threads which need analysis for signs of malicious behaviour
/// - Setting up the AltSyscallHandler so that we can intercept syscalls kernel-side from usermode.
///
/// # Args
/// - pid: The process ID of the process.
/// - thread_id: The thread ID of the thread.
/// = create: Indicates whether the thread was created (TRUE) or deleted (FALSE).
pub unsafe extern "C" fn thread_callback(
    pid: *mut c_void,
    thread_id: *mut c_void,
    create: BOOLEAN,
) {
    let pid = pid as u32;
    let thread_id = thread_id as u32;

    thread_reg_alt_callbacks();
}

unsafe extern "system" {
    fn PsGetProcessImageFileName(
        p_eprocess: *const c_void
    ) -> *const c_void;
}

pub fn thread_reg_alt_callbacks() {
    let mut ke_thread: *mut c_void = null_mut();

    unsafe {
        asm!(
            "mov {}, gs:[0x188]",
            out(reg) ke_thread,
        )
    };

    let process = unsafe {
        IoThreadToProcess(ke_thread as *mut _)
    };

    if process.is_null() {
        println!("[sanctum] [-] PEPROCESS was null.");
        return;
    }

    let name_ptr = unsafe {
        PsGetProcessImageFileName(process as *mut _)
    };

    if name_ptr.is_null() {
        println!("[sanctum] [-] Name ptr was null");
    }

    let name = match unsafe { CStr::from_ptr(name_ptr as *const i8) }.to_str() {
        Ok(name_str) => name_str,
        Err(e) => {
            println!("[sanctum] [-] Could not get the process name as a str. {e}");
            return;
        },
    };

    // Set the thread attributes for "malware.exe"
    // if name.contains("malware.") {
    //     AltSyscalls::set_thread_for_alt_syscalls(ke_thread as *mut _);
    //     AltSyscalls::set_process_for_alt_syscalls(ke_thread as *mut _);
    //     // unsafe { asm!("int3") };
    // }

    AltSyscalls::configure_thread_for_alt_syscalls(ke_thread as *mut _, AltSyscallStatus::Enable);
    AltSyscalls::configure_process_for_alt_syscalls(ke_thread as *mut _);
}
