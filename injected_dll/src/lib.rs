use std::{arch::asm, ffi::c_void};
use windows::{core::PCSTR, Win32::{Foundation::STATUS_SUCCESS, System::{LibraryLoader::{GetModuleHandleA, GetProcAddress}, SystemServices::*, Threading::{CreateThread, THREAD_CREATION_FLAGS}}, UI::WindowsAndMessaging::{MessageBoxA, MB_OK}}};
use windows::core::s;

mod stubs;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
fn DllMain(_: usize, dw_reason: u32, _: usize) -> i32 {
    match dw_reason {
        DLL_PROCESS_ATTACH => {
            // Initialise the DLL in a new thread. Calling this from DllMain is always a bad idea;
            // for more info check my blog: https://fluxsec.red/remote-process-dll-injection#a-dll-update-automatic-unloading 
            unsafe {
                let _ = CreateThread(
                    None,
                    0,
                    Some(initialise_injected_dll),
                    None,
                    THREAD_CREATION_FLAGS(0),
                    None,
                );
            }
        },
        _ => (),
    }

    1
}

/// Initialise the DLL by resolving function pointers to our syscall hook callbacks.
unsafe extern "system" fn initialise_injected_dll(_: *mut c_void) -> u32 {

    let stub_addresses = StubAddresses::new();

    // test jump to open_process
    unsafe {
        asm!(
            // move our VA into eax
            "mov rax, {x}",
            // call the function
            "call rax",

            x = in(reg) stub_addresses.open_process
        );
    }

    // Proof we returned successfully!
    unsafe {
        MessageBoxA(None, s!("Bazinga!"), s!("Bazinga!"), MB_OK);
    }

    STATUS_SUCCESS.0 as _
}

/// A structure to hold the stub addresses for each callback function we wish to have for syscalls.
/// 
/// The address of each function within the DLL will be used to overwrite memory in the syscall, allowing us to jmp
/// to the address.
pub struct StubAddresses {
    open_process: usize,
}

impl StubAddresses {
    /// Retrieve the virtual addresses of all callback functions for the DLL
    fn new() -> Self {

        // Get a handle to ourself
        let h_kernel32 = unsafe { GetModuleHandleA(s!("sanctum.dll")) };
        let h_kernel32 = match h_kernel32 {
            Ok(h) => h,
            Err(_) => todo!(),
        };

        //
        // Get function pointers to our callback symbols
        //

        // Get a function pointer to LoadLibraryA from Kernel32.dll
        let open_process_fn_addr = unsafe { GetProcAddress(h_kernel32, s!("open_process")) };
        let open_process_fn_addr = match open_process_fn_addr {
            None => {
                unsafe { MessageBoxA(None, s!("Could not get fn addr"), s!("Could not get fn addr"), MB_OK) };
                todo!();
            },
            Some(address) => address as *const (),
        } as usize;

        Self {
            open_process: open_process_fn_addr,
        }
    }
}