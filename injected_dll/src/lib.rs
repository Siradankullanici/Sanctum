use std::{arch::asm, ffi::c_void};

use windows::Win32::{Foundation::HANDLE, System::SystemServices::*, UI::WindowsAndMessaging::{MessageBoxA, MB_OK}};
use windows::core::s;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
fn DllMain(_: usize, dw_reason: u32, _: usize) -> i32 {
    match dw_reason {
        DLL_PROCESS_ATTACH => attach(),
        _ => (),
    }

    1
}

fn attach() {
    unsafe {
        MessageBoxA(None, s!("Hello from Rust DLL"), s!("Hello from Rust DLL"), MB_OK);
    }
}


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
    // start off by causing a break in the injected process indicating we successfully called our function!
    unsafe {asm!("int3")};
}