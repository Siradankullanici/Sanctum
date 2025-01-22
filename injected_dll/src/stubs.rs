//! Stubs that act as callback functions from syscalls.

use std::{arch::asm, ffi::c_void, fs::OpenOptions, io::Write, thread::sleep, time::Duration};

use serde_json::to_vec;
use shared_std::{constants::PIPE_FOR_INJECTED_DLL, processes::{OpenProcessData, Syscall}};
use windows::{core::PCSTR, Win32::{Foundation::{ERROR_PIPE_BUSY, HANDLE}, System::WindowsProgramming::CLIENT_ID, UI::WindowsAndMessaging::{MessageBoxA, MB_OK}}};

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
        let pid = unsafe {(*client_id).UniqueProcess.0 } as u32;

        let data = Syscall::OpenProcess(OpenProcessData{
            pid,
        });

        // send information to the engine via IPC; do not use Tokio as we don't want the async runtime in our processes..
        // and it would not be FFI safe, so we will use the standard library to achieve this
        let mut client = loop {
            match OpenOptions::new().read(true).write(true).open(PIPE_FOR_INJECTED_DLL) {
                Ok(client) => break client,
                // If the pipe is busy, try again after a wait
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as _) => (),
                Err(e) => panic!("An error occurred talking to the engine, {e}"), // todo is this acceptable?
            }

            sleep(Duration::from_millis(50));
        };

        let message_data = to_vec(&data).unwrap();
        if let Err(e) = client.write_all(&message_data) {
            panic!("Error writing to named pipe to UM Engine. {e}");
        };
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