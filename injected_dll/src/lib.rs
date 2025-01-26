#![feature(naked_functions)]

use std::{collections::HashMap, ffi::c_void};
use windows::{core::PCSTR, Win32::{Foundation::{CloseHandle, HANDLE, STATUS_SUCCESS}, System::{Diagnostics::{Debug::WriteProcessMemory, ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32}}, LibraryLoader::{GetModuleHandleA, GetProcAddress}, SystemServices::*, Threading::{CreateThread, GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread, THREAD_CREATION_FLAGS, THREAD_SUSPEND_RESUME}}, UI::WindowsAndMessaging::{MessageBoxA, MB_OK}}};
use windows::core::s;

mod stubs;
mod ipc;

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
    
    // suspend the threads
    let suspended_handles= suspend_all_threads();
    unsafe { MessageBoxA(None, s!("break"), s!("break"), MB_OK) };

    let stub_addresses = StubAddresses::new();

    patch_ntdll(&stub_addresses);


    resume_all_threads(suspended_handles);

    STATUS_SUCCESS.0 as _
}

/// A structure to hold the stub addresses for each callback function we wish to have for syscalls.
/// 
/// The address of each function within the DLL will be used to overwrite memory in the syscall, allowing us to jmp
/// to the address.
pub struct StubAddresses<'a> {
    addresses: HashMap<&'a str, Addresses>,
}

struct Addresses {
    edr: usize,
    ntdll: usize,
}

impl<'a> StubAddresses<'a> {
    /// Retrieve the virtual addresses of all callback functions for the DLL.
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

        // open_process
        let virtual_alloc_stub = unsafe { GetProcAddress(h_sanc_dll, s!("virtual_alloc_ex")) };
        let virtual_alloc_stub = match virtual_alloc_stub {
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

        // ZwAllocateVirtualMemory
        let zwavm = unsafe { GetProcAddress(h_ntdll, s!("ZwAllocateVirtualMemory")) };
        let zwavm = match zwavm {
            None => {
                unsafe { MessageBoxA(None, s!("Could not get fn addr"), s!("Could not get fn addr"), MB_OK) };
                panic!("Oh no :("); // todo dont panic a process?
            },
            Some(address) => address as *const (),
        } as usize;

        let mut hm = HashMap::new();
        hm.insert("ZwOpenProcess", Addresses {
            edr: open_process_fn_addr,
            ntdll: zwop,
        });
        hm.insert("ZwAllocateVirtualMemory", Addresses {
            edr: virtual_alloc_stub,
            ntdll: zwavm,
        });

        Self {
            addresses: hm,
        }
    }
}

/// Patches hooks into NTDLL functions to redirect execution to our DLL so we can inspect params.
/// 
/// This works by doing the following:
/// 
/// 1) Overwrite a syscall stub we wish to hook with NOPs
/// 2) Replace the starting bytes of that memory with a jmp to our EDR DLL function callback
/// 3) Write the jmp instruction
fn patch_ntdll(addresses: &StubAddresses) {
    for (_, item) in &addresses.addresses {
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
                item.ntdll as *const _,
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
                item.ntdll as *const _,
                mob_abs_rax.as_ptr() as *const _, 
                mob_abs_rax.len(), 
                None,
            )
        };

        //
        // convert the address of the function to little endian (8) bytes and write them at the correct offset
        //
        let mut addr_bytes = [0u8; 8]; // 8 for ptr, 2 for call
        let addr64 = item.edr as u64; // ensure we are 8-byte aligned
        for (i, b) in addr_bytes.iter_mut().enumerate() {
            *b = ((addr64 >> (i * 8)) & 0xFF) as u8;
        }

        // write it
        let _ = unsafe {
            WriteProcessMemory(
                proc_hand, 
                (item.ntdll + 2) as *const _,
                addr_bytes.as_ptr() as *const _, 
                addr_bytes.len(), 
                None,
            )
        };

        let jmp_bytes: &[u8] = &[0xFF, 0xE0];
        let _ = unsafe {
            WriteProcessMemory(
                proc_hand,
                (item.ntdll + 10) as *const _,
                jmp_bytes.as_ptr() as *const _, 
                jmp_bytes.len(), 
                None,
            )
        };

    }

}

/// Suspend all threads in the current process except for the thread executing our EDR setup (i.e. the current thread)
/// 
/// # Returns
/// A vector of the suspended handles
fn suspend_all_threads() -> Vec<HANDLE> {
    // get all thread ID's except the current thread
    let thread_ids = get_thread_ids();
    if thread_ids.is_err() {
        todo!()
    }
    let thread_ids = thread_ids.unwrap();

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