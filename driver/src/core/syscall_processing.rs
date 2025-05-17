//! This module relates to the post-processing of system call's intercepted via the Alternate Syscalls technique.

use wdk::println;
use wdk_sys::{ntddk::IoFreeWorkItem, PIO_WORKITEM, PVOID};

pub unsafe extern "C" fn syscall_post_processing(
    io_object: PVOID,
    context: PVOID,
    io_work_item: PIO_WORKITEM
) {
    println!("[sanctum] [i] Syscall callback!");
    
    // Free memory allocated for the work item
    unsafe { IoFreeWorkItem(io_work_item); }
}