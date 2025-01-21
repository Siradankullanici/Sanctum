use std::{arch::asm, ffi::c_void};
use windows::{core::PCSTR, Win32::{Foundation::{CloseHandle, HANDLE, STATUS_SUCCESS}, System::{Diagnostics::{Debug::{DebugActiveProcess, WriteProcessMemory}, ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32}}, LibraryLoader::{GetModuleHandleA, GetProcAddress}, SystemServices::*, Threading::{CreateThread, GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread, THREAD_ALL_ACCESS, THREAD_CREATION_FLAGS, THREAD_SUSPEND_RESUME}}, UI::WindowsAndMessaging::{MessageBoxA, MB_OK}}};
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

    //
    // The order of setup will be to:
    // 1) Suspend all threads except for this thread.
    // 2) Perform all modification and patching of the current process.
    // 3) Resume all threads
    //

    // get all thread ID's except the current thread
    let thread_ids = get_thread_ids();
    if thread_ids.is_err() {
        todo!()
    }
    let thread_ids = thread_ids.unwrap();
    let suspended_handles= suspend_all_threads(thread_ids);

    let stub_addresses = StubAddresses::new();

    unsafe {
        MessageBoxA(None, s!("b4!"), s!("b4!"), MB_OK);
    }

    patch_ntdll(&stub_addresses);

    resume_all_threads(suspended_handles);

    STATUS_SUCCESS.0 as _
}

/// A structure to hold the stub addresses for each callback function we wish to have for syscalls.
/// 
/// The address of each function within the DLL will be used to overwrite memory in the syscall, allowing us to jmp
/// to the address.
pub struct StubAddresses {
    edr: EdrAddresses,
    ntdll: NtDll,
}

struct EdrAddresses {
    open_process: usize,
}

struct NtDll {
    zw_open_process: usize,
}

impl StubAddresses {
    /// Retrieve the virtual addresses of all callback functions for the DLL
    fn new() -> Self {

        // Get a handle to ourself
        let h_sanc_dll = unsafe { GetModuleHandleA(s!("sanctum.dll")) };
        let h_sanc_dll = match h_sanc_dll {
            Ok(h) => h,
            Err(_) => todo!(),
        };

        // Get a handle to ntdll
        let h_ntdll = unsafe { GetModuleHandleA(s!("Ntdll.dll")) };
        let h_ntdll = match h_ntdll {
            Ok(h) => h,
            Err(_) => todo!(),
        };


        //
        // Get function pointers to our callback symbols
        //

        // open_process
        let open_process_fn_addr = unsafe { GetProcAddress(h_sanc_dll, s!("open_process")) };
        let open_process_fn_addr = match open_process_fn_addr {
            None => {
                unsafe { MessageBoxA(None, s!("Could not get fn addr"), s!("Could not get fn addr"), MB_OK) };
                panic!("Oh no :("); // todo dont panic a process?
            },
            Some(address) => address as *const (),
        } as usize;


        //
        // Get function pointers to the functions we wish to hook
        //

        // ZwOpenProcess
        let zwop = unsafe { GetProcAddress(h_ntdll, s!("ZwOpenProcess")) };
        let zwop = match zwop {
            None => {
                unsafe { MessageBoxA(None, s!("Could not get fn addr"), s!("Could not get fn addr"), MB_OK) };
                panic!("Oh no :("); // todo dont panic a process?
            },
            Some(address) => address as *const (),
        } as usize;

        Self {
            edr: EdrAddresses{
                open_process: open_process_fn_addr
            },
            ntdll: NtDll {
                zw_open_process: zwop
            },
        }
    }
}

/// Patches hooked NTDLL functions with our flow redirection
fn patch_ntdll(addresses: &StubAddresses) {
    // ZwOpenProcess
    let buffer: &[u8] = &[
        0x90, 0x90, 0x90,
        0x90, 0x90, 0x90,
        0x90, 0x90, 0x90,
        0x90, 0x90, 0x90,
        0x90, 0x90, 0x90,
        0x90, 0x90, 0x90,
        0x90, 0x90, 0x90,
        0x90, 0x90, 0x90,
        0x90, 0x90, 0x90,
        0x90, 0x90, 0x90,
        0x90, 0x90,
    ];

    let proc_hand = unsafe { GetCurrentProcess() };
    let mut bytes_written: usize = 0;
    let _ = unsafe {
        WriteProcessMemory(
            proc_hand, 
            addresses.ntdll.zw_open_process as *const _,
            buffer.as_ptr() as *const _, 
            buffer.len(), 
            Some(&mut bytes_written)
        )
    };

    // write movabs rax, _ (thanks to https://defuse.ca/online-x86-assembler.htm#disassembly)
    let mob_abs_rax: [u8; 2] = [0x48, 0xB8];
    let _ = unsafe {
        WriteProcessMemory(
            proc_hand, 
            addresses.ntdll.zw_open_process as *const _,
            mob_abs_rax.as_ptr() as *const _, 
            mob_abs_rax.len(), 
            None,
        )
    };

    //
    // convert the address of the function to little endian (8) bytes and write them at the correct offset
    //
    let mut addr_bytes = [0u8; 8]; // 8 for ptr, 2 for call
    let addr64 = addresses.edr.open_process as u64; // ensure we are 8-byte aligned
    for (i, b) in addr_bytes.iter_mut().enumerate() {
        *b = ((addr64 >> (i * 8)) & 0xFF) as u8;
    }

    // write it
    let _ = unsafe {
        WriteProcessMemory(
            proc_hand, 
            (addresses.ntdll.zw_open_process + 2) as *const _,
            addr_bytes.as_ptr() as *const _, 
            addr_bytes.len(), 
            None,
        )
    };

    let jmp_bytes: &[u8] = &[0xFF, 0xE0];
    let _ = unsafe {
        WriteProcessMemory(
            proc_hand,
            (addresses.ntdll.zw_open_process + 10) as *const _,
            jmp_bytes.as_ptr() as *const _, 
            jmp_bytes.len(), 
            None,
        )
    };

    // unsafe { MessageBoxA(None, s!("Done writes"), s!("Done writes"), MB_OK) };


    // unsafe {
    //     asm!(
    //         // move our VA into eax
    //         "mov rax, {x}",
    //         // call the function
    //         "call rax",

    //         x = in(reg) addresses.edr.open_process
    //     );
    // }


}

/// Suspend all threads in the current process except for the thread executing our EDR setup (i.e. the current thread)
/// 
/// # Returns
/// A vector of the suspended handles
fn suspend_all_threads(thread_ids: Vec<u32>) -> Vec<HANDLE> {
    let mut suspended_handles: Vec<HANDLE> = vec![];
    for id in thread_ids {
        let h = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, id) };
        match h {
            Ok(handle) => {
                unsafe { SuspendThread(handle)};
                suspended_handles.push(handle);
            },
            Err(e) => {
                unsafe {
                    let x = format!("Error with handle: {:?}\0", e);
                    MessageBoxA(None, PCSTR::from_raw(x.as_ptr()), PCSTR::from_raw(x.as_ptr()), MB_OK);
                }
            },
        }
    }

    suspended_handles
}

/// Resume all threads in the process
fn resume_all_threads(thread_handles: Vec<HANDLE>) {
    for handle in thread_handles {
        unsafe { ResumeThread(handle)};
        let _ = unsafe { CloseHandle(handle) };
    }
}

/// Enumerate all threads in the current process
/// 
/// # Returns
/// A vector of thread ID's
fn get_thread_ids() -> Result<Vec<u32>, ()> {
    let pid = unsafe { GetCurrentProcessId() };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid) };
    let snapshot = match snapshot {
        Ok(s) => s,
        Err(_) => return Err(()),
    };

    // todo hashset
    let mut thread_ids: Vec<u32> = vec![];
    let current_thread = unsafe { GetCurrentThreadId() };

    let mut thread_entry = THREADENTRY32::default();
    thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    if unsafe { Thread32First(snapshot,&mut thread_entry)}.is_ok() {
        loop {

            if thread_entry.th32OwnerProcessID == pid {
                // We dont want to suspend our own thread..
                if thread_entry.th32ThreadID != current_thread {
                    thread_ids.push(thread_entry.th32ThreadID);
                }
            }
            
            if !unsafe { Thread32Next(snapshot, &mut thread_entry) }.is_ok() {
                break;
            }
        }
    }

    Ok(thread_ids)

}