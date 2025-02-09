//! This module deals with kernel side hooks of a syscall we can register via the 
//! undocumented PsRegisterAltSystemCallHandler routine, and we can get its address through
//! `MmGetSystemRoutineAddress`. Good resource on this https://lesnik.cc/hooking-all-system-calls-in-windows-10-20h1/.

use core::{ffi::c_void, mem::transmute, ptr::{self, null_mut}};

use wdk::println;
use wdk_sys::{ntddk::{ExAllocatePool2, ExGetPreviousMode, MmGetSystemRoutineAddress, RtlInitUnicodeString, ZwClose, ZwOpenProcess}, BOOLEAN, CLIENT_ID, DISPATCHER_HEADER, HANDLE, KPROCESSOR_MODE, NTSTATUS, OBJECT_ATTRIBUTES, OBJ_KERNEL_HANDLE, PETHREAD, PKTRAP_FRAME, POOL_TYPE, PROCESSINFOCLASS, PROCESS_ALL_ACCESS, STATUS_SUCCESS, UNICODE_STRING, _POOL_TYPE::NonPagedPool};

use crate::{ffi::InitializeObjectAttributes, utils::ToU16Vec};

type ZwSetInformationProcess = extern "system" fn(
    handle: *mut c_void,
    process_info_class: PROCESSINFOCLASS,
    procesS_info: *mut c_void,
    process_info_len: u32,
) -> u32;

pub enum CoreSyscallHandlerError {
    /// This error is used when we failed to resolve the address of pPsRegisterAltSystemCallHandler
    FuncResolveError,
    /// Indicates the registration of the syscall callback function failed
    RegistrationFail(u32),
    CallHandlerNone,
}

pub struct SyscallHandler;

/// Addresses commonly used / resolved that will prevent constant lookups. Addresses saved as usize so will need converting
/// to a *mut c_void before use. `usize` is Send, whereas *mut c_void is not.
#[allow(non_snake_case)]
pub struct Addresses;

impl SyscallHandler {
    pub fn remove_alt_syscall_handler_from_threads(&self) {
        // todo once implemented
        // ref: https://github.com/Xacone/BestEdrOfTheMarket/blob/main/BestEdrOfTheMarketDriver/src/SyscallsTracing.cpp#L881
        // todo NOTE: the &self may not be required; if not move out of impl
    }
}

pub unsafe extern "system" fn syscall_handler(frame: PKTRAP_FRAME) -> BOOLEAN {
    println!("HELLO FROM THE CALLBACK :). Frame: {:p}", frame);
    
    true as _
}

pub fn enable_alt_syscall_for_thread(thread: PETHREAD) {
    if thread.is_null() { return; }

    // ref: https://xacone.github.io/BestEdrOfTheMarketV3.html#4
    // setting the 5th bit (set with 0x20) PsAltSystemCallHandlers is invoked by the kernel, allowing our syscall callbacks to work
    let mut thread_dispatch_header = unsafe {*(thread as *const DISPATCHER_HEADER)};
    unsafe { thread_dispatch_header.__bindgen_anon_1.__bindgen_anon_6.__bindgen_anon_2.DebugActive |= 0x20 };

    // println!("Thread enabled.");
}

pub fn disable_alt_syscall_for_thread(thread: PETHREAD) {
    if thread.is_null() { return; }

    // ref: https://xacone.github.io/BestEdrOfTheMarketV3.html#4
    let mut thread_dispatch_header = unsafe {*(thread as *const DISPATCHER_HEADER)};
    thread_dispatch_header.__bindgen_anon_1.__bindgen_anon_6.__bindgen_anon_2.DebugActive = 0x0;

}

extern "system" {
    fn PsRegisterSyscallProvider(provider: *mut SyscallProvider, set_to_1: *mut u8, out_provider: *mut *mut SyscallProvider) -> NTSTATUS;
    fn PsInitializeSyscallProviders() -> NTSTATUS;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallProvider {
    pub next: *mut SyscallProvider,   // 0x00 - Next provider in linked list
    pub prev: *mut SyscallProvider,   // 0x08 - Previous provider in linked list
    pub provider_id: u64,             // 0x10 - Unique provider ID
    pub reserved1: u64,               // 0x18 - Possibly used for metadata
    pub handler_fn: *mut c_void,      // 0x20 - Function pointer to syscall handler
    pub reserved2: [u8; 0x38],        // 0x28 - Extra space, alignment
}

unsafe fn enable_syscall_providers() {
    // Address from your image
    let psp_syscall_providers_enabled: *mut u8 = 0x140d520e as *mut u8;

    // Set the value to 1
    ptr::write_volatile(psp_syscall_providers_enabled, 1);

    println!("Set PspSyscallProvidersEnabled to 1!");
}

pub fn register_syscall_provider(handler: *mut c_void) -> Result<(), NTSTATUS> {
    unsafe {
        let mut provider = SyscallProvider {
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
            provider_id: 0x42, // Example ID
            reserved1: 0,
            handler_fn: handler,
            reserved2: [0; 0x38],
        };

        let mut out_provider: *mut SyscallProvider = core::ptr::null_mut();
        let set_to_1: u8 = 1; // Must be set to 1

        // println!("Calling enable_syscall_providers");

        // enable_syscall_providers();

        println!("About to go into PsRegisterSyscallProvider");

        let status = PsRegisterSyscallProvider(&mut provider, &set_to_1 as *const _ as *mut u8, &mut out_provider);

        println!("Result was: {status}");
        
        if status != 0 {
            return Err(status);
        }

        println!("Syscall Provider Registered: {:p}", out_provider);
        Ok(())
    }
}

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
pub fn register_syscall_hooks() -> Result<(), CoreSyscallHandlerError> {
    let mut func_name = UNICODE_STRING::default();
    let func_name_wide = "PsRegisterAltSystemCallHandler".to_u16_vec();
    unsafe { RtlInitUnicodeString(&mut func_name, func_name_wide.as_ptr()) };

    let pPsRegisterAltSystemCallHandler_raw: *mut c_void  = unsafe { MmGetSystemRoutineAddress(&mut func_name) };
    if pPsRegisterAltSystemCallHandler_raw.is_null() {
        return Err(CoreSyscallHandlerError::FuncResolveError);
    }

    // Cast to the fn pointer correct function type 
    let pPsRegisterAltSystemCallHandler: extern "system" fn(
        p1: *mut c_void, 
        p2: u32,
    ) -> u32 =  unsafe { transmute(pPsRegisterAltSystemCallHandler_raw) };

    // let call_handlers = leak_system_call_handlers(pPsRegisterAltSystemCallHandler_raw as usize);
    // if call_handlers.is_none() {
    //     println!("CALL HANDLERS WAS NONE!!");
    //     return Err(CoreSyscallHandlerError::CallHandlerNone);
    // }

    // if unsafe { core::ptr::read(call_handlers.unwrap() as *const usize) } != 0 {
    //     println!("CALL HANDLER VALUE WAS NOT 0!!!!");
    //     return Err(CoreSyscallHandlerError::CallHandlerNone);
    // }

    let status = pPsRegisterAltSystemCallHandler(syscall_handler as *mut _, 1);

    // if not STATUS_SUCCESS
    if status != 0 {
        println!("Callback registration failed!");
        return Err(CoreSyscallHandlerError::RegistrationFail(status));
    }

    println!("Syscall handler address: {:p}", syscall_handler as *mut c_void);

    println!("About to do PspInsertSyscallProvider");

    if register_syscall_provider(syscall_handler as *mut _).is_err() {
        println!("Error from func");
        return Err(CoreSyscallHandlerError::RegistrationFail(status));
    }

    println!("OK FINISHED CALLING IT!!??");

    Ok(())
}


#[repr(C, packed)]
struct AltSyscallBuffer {
    process_handle: HANDLE, // 8 bytes
    thread_handle: HANDLE,  // 8 bytes
    reserved: [u8; 4], // fill out to 20 bytes
}

pub fn set_information_for_alt_syscall(pid: *mut c_void) {
    let mut ob = OBJECT_ATTRIBUTES::default();
    let mut client_id = CLIENT_ID::default();
    
    if unsafe { InitializeObjectAttributes(
        &mut ob, 
        null_mut(),
        OBJ_KERNEL_HANDLE, 
        null_mut(), 
        null_mut()) 
    }.is_err() {
        println!("[sanctum] [-] Failed to create object attributes in set_information_for_alt_syscall.");
        return;
    }
    
    client_id.UniqueProcess = pid;
    client_id.UniqueThread = null_mut();
    let mut process_handle: HANDLE = null_mut();
    
    if unsafe {ZwOpenProcess(&mut process_handle, PROCESS_ALL_ACCESS, 
        &mut ob, &mut client_id) } == STATUS_SUCCESS {
                
        let mut func_name = UNICODE_STRING::default();
        let func_name_wide = "ZwSetInformationProcess".to_u16_vec();
        unsafe { RtlInitUnicodeString(&mut func_name, func_name_wide.as_ptr()) };
        
        let ZwSetInformationProcess_addr: *mut c_void  = unsafe { MmGetSystemRoutineAddress(&mut func_name) };

        if ZwSetInformationProcess_addr.is_null() {
            println!("[sanctum] [-] Error that ZwSetInformationProcess_addr was null.");
            return;
        }

        let pZwSetInformationProcess: ZwSetInformationProcess = unsafe { transmute(ZwSetInformationProcess_addr as *mut c_void) };
        let qw_pid: *mut c_void = client_id.UniqueProcess;
        let mut alt_buffer = AltSyscallBuffer {
            process_handle: client_id.UniqueProcess,
            thread_handle: client_id.UniqueThread,
            reserved: [0,0,0,0],
        };

        let result = pZwSetInformationProcess(
            process_handle,
            0x64,
            &mut alt_buffer as *mut _ as *mut c_void,
            0x14,
        );

        if result == STATUS_SUCCESS as u32 {
            unsafe { let _ = ZwClose(process_handle); };
            println!("Successfully modified via ZwSetInformationProcess ***************************************");
            return;
        }

        println!("[sanctum] [-] pZwSetInformationProcess failed - {:X}.", result);
    }
        
        
    if !process_handle.is_null() {
        unsafe { let _ = ZwClose(process_handle); };
    }

}


fn leak_system_call_handlers(mut r_offset: usize) -> Option<usize> {
    for _ in 0..0x100 {
        let sig_bytes: [u8; 3] = [0x4C, 0x8D, 0x35];
        let opcodes = unsafe { *(r_offset as *const usize) }; // isnt this just the same??

        if starts_with_signature(r_offset, &sig_bytes) {
            let correct_offset: usize = (opcodes >> 24) & 0x0000FFFFFF;
            return Some(r_offset + 7 + correct_offset);
        }

        r_offset += 2;
    }

    None
}

fn starts_with_signature(address: usize, signature: &[u8]) -> bool {

    let address: *const u8 = address as *const _;

    for i in 0..signature.len()    {
        if unsafe { core::ptr::read(address.add(i)) } != signature[i] {
            return false;
        }
    }
    
    true
}