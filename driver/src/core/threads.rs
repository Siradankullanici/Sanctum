//! This module handles callback implementations and and other function related to processes.

use core::{arch::asm, ffi::c_void};

use wdk::println;
use wdk_sys::{ntddk::{KeGetCurrentIrql, PsGetCurrentProcessId, PsSetCreateThreadNotifyRoutine}, BOOLEAN, DISPATCH_LEVEL, PETHREAD};

use crate::core::syscall_handlers::set_information_for_alt_syscall;

use super::syscall_handlers::enable_alt_syscall_for_thread;


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
/// MSDN reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_thread_notify_routine
/// 
/// # Args
/// - pid: The process ID of the process.
/// - thread_id: The thread ID of the thread.
/// = create: Indicates whether the thread was created (TRUE) or deleted (FALSE). 
pub unsafe extern "C" fn thread_callback(pid: *mut c_void, thread_id: *mut c_void, create: BOOLEAN) {
    //
    // Set up the thread so that it is handled via the Alt Syscall process
    //
    set_information_for_alt_syscall(pid);

    // As PsGetCurrentThread is not available in the Rust wdk; read the gs register offset 0x188, then casting into a PETHREAD.
    // In the C implementation this is as follows:
    /*
    PETHREAD
    PsGetCurrentThread (
        VOID
        )
    {
        return (PETHREAD)KeGetCurrentThread();
    }

    PKTHREAD
    KeGetCurrentThread (
        VOID
        )

    {
        return (struct _KTHREAD *)__readgsqword(0x188);
    }
    */
    if unsafe { KeGetCurrentIrql() } > DISPATCH_LEVEL as _ {
        println!("[sanctum] [-] Dispatch level too high to call enable_alt_syscall_for_thread");
        return;
    }

    let mut ke_thread: u64 = 0;

    unsafe { asm!(
        "mov {}, gs:[0x188]",
        out(reg) ke_thread,
    )};

    enable_alt_syscall_for_thread(ke_thread as PETHREAD);

}