//! Stubs that act as callback functions from syscalls.

use std::{arch::asm, ffi::c_void};

use windows::{core::{s, PCSTR}, Win32::{Foundation::HANDLE, UI::WindowsAndMessaging::{MessageBoxA, MB_OK}}};

/// Injected DLL routine for examining the arguments passed to ZwOpenProcess and NtOpenProcess from 
/// any process this DLL is injected into.
#[unsafe(no_mangle)]
unsafe extern "system" fn open_process(
    process_handle: HANDLE,
    desired_access: u32,
    // We do not care for now about the OA
    _: *mut c_void,
    // We do not  care for now about the client id
    _: *mut c_void,
) {
    unsafe {
        MessageBoxA(None, s!("Inside the callback!"), s!("Inside the callback!"), MB_OK);
    }
}
