//! Stubs that act as callback functions from syscalls.

use std::{arch::asm, ffi::c_void};
use shared_std::processes::{OpenProcessData, Syscall, SyscallData, VirtualAllocExSyscall};
use windows::Win32::{Foundation::HANDLE, System::{Threading::{GetCurrentProcessId, GetProcessId}, WindowsProgramming::CLIENT_ID}};
use crate::ipc::send_syscall_info_ipc;

/// Injected DLL routine for examining the arguments passed to ZwOpenProcess and NtOpenProcess from 
/// any process this DLL is injected into.
#[unsafe(no_mangle)]
unsafe extern "system" fn open_process(
    process_handle: HANDLE,
    desired_access: u32,
    object_attrs: *mut c_void,
    client_id: *mut CLIENT_ID,
) {
    if !client_id.is_null() {
        let target_pid = unsafe {(*client_id).UniqueProcess.0 } as u32;
        let pid = unsafe { GetCurrentProcessId() };

        let data = Syscall::OpenProcess(SyscallData{
            inner: OpenProcessData {
                pid,
                target_pid,
            },
        });

        // send the telemetry to the engine
        send_syscall_info_ipc(&data);
    }
    
    // todo automate the syscall number so not hardcoded
    let ssn = 0x26; // give the compiler awareness of rax

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",
            in("rax") ssn,
            // Use the asm macro to load our registers so that the Rust compiler has awareness of the
            // use of the registers. Loading these by hands caused some instability
            in("rcx") process_handle.0,
            in("rdx") desired_access,
            in("r8") object_attrs,
            in("r9") client_id,

            options(nostack, preserves_flags)
        );
    }
}

/// Syscall hook for ZwAllocateVirtualMemory
#[unsafe(no_mangle)]
unsafe extern "system" fn virtual_alloc_ex(
    process_handle: HANDLE,
    base_address: *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) {

    //
    // Check whether we are allocating memory in our own process, or a remote process. For now, we are not interested in 
    // self allocations - we can deal with that later. We just want remote process memory allocations for the time being.
    // todo - future do self alloc
    //

    let pid = unsafe { GetCurrentProcessId() };
    let remote_pid = unsafe { GetProcessId(process_handle) };

    // send telemetry in the case of a remote allocation
    if pid != remote_pid {
        let region_size_checked = if region_size.is_null() {
            0
        } else {
            // SAFETY: Null pointer checked above
            unsafe { *region_size }
        };
    
        send_syscall_info_ipc(&Syscall::VirtualAllocEx(
            SyscallData { 
                inner: VirtualAllocExSyscall {
                    base_address: base_address as usize,
                    region_size: region_size_checked,
                    allocation_type,
                    protect,
                    remote_pid,
                    pid,
                }
            }
        ));
    }
    
    // proceed with the syscall
    let ssn = 0x18;
    unsafe {
        asm!(
            "sub rsp, 0x38",            // reserve shadow space + 8 byte ptr as it expects a stack of that size
            "mov [rsp + 0x30], {1}",    // 8 byte ptr + 32 byte shadow space + 8 bytes offset from 5th arg
            "mov [rsp + 0x28], {0}",    // 8 byte ptr + 32 byte shadow space
            "mov r10, rcx",
            "syscall",
            "add rsp, 0x38",

            in(reg) allocation_type,
            in(reg) protect,
            in("rax") ssn,
            in("rcx") process_handle.0,
            in("rdx") base_address,
            in("r8") zero_bits,
            in("r9") region_size,
            options(nostack),
        );
    }
}