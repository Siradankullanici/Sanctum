//! This module deals with kernel side hooks of a syscall we can register via the 
//! undocumented PsRegisterAltSystemCallHandler routine, and we can get its address through
//! `MmGetSystemRoutineAddress`. Good resource on this https://lesnik.cc/hooking-all-system-calls-in-windows-10-20h1/.

use core::{arch::asm, ffi::c_void, mem::transmute, ptr::{self, null_mut}};

use alloc::{alloc::alloc_zeroed, vec::Vec};
use wdk::println;
use wdk_sys::{ntddk::{ExAllocatePool2, ExGetPreviousMode, MmGetSystemRoutineAddress, RtlInitUnicodeString, ZwClose, ZwOpenProcess}, BOOLEAN, CLIENT_ID, DISPATCHER_HEADER, HANDLE, KPROCESSOR_MODE, NTSTATUS, OBJECT_ATTRIBUTES, OBJ_KERNEL_HANDLE, PCWSTR, PETHREAD, PKTRAP_FRAME, POOL_TYPE, PROCESSINFOCLASS, PROCESS_ALL_ACCESS, STATUS_SUCCESS, UNICODE_STRING, _POOL_TYPE::NonPagedPool};


use crate::{ffi::InitializeObjectAttributes, utils::ToU16Vec};

type ZwSetInformationProcess = extern "C" fn(
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
    if thread.is_null() { 
        println!("Thread was null. Returning.");
        return; 
    }

    // ref: https://xacone.github.io/BestEdrOfTheMarketV3.html#4
    // setting the 5th bit (set with 0x20) PsAltSystemCallHandlers is invoked by the kernel, allowing our syscall callbacks to work
    // let mut thread_dispatch_header = unsafe {*(thread as *const DISPATCHER_HEADER)};
    // unsafe { thread_dispatch_header.__bindgen_anon_1.__bindgen_anon_6.__bindgen_anon_2.DebugActive |= 0x20 };

    
    
    // get a mutable reference to the memory
    let thread_dispatch_header_ptr = unsafe { &mut *(thread as *mut DISPATCHER_HEADER) };
    
    // directly modify the field in memory:
    unsafe { thread_dispatch_header_ptr.__bindgen_anon_1
        .__bindgen_anon_6
        .__bindgen_anon_2
        .DebugActive |= 0x20 };
    
    println!("Thread enabled using xor to try this time. Debug active: {:b}", unsafe {thread_dispatch_header_ptr.__bindgen_anon_1.__bindgen_anon_6.__bindgen_anon_2.DebugActive});

}

pub fn disable_alt_syscall_for_thread(thread: PETHREAD) {
    if thread.is_null() { return; }

    // ref: https://xacone.github.io/BestEdrOfTheMarketV3.html#4
    let mut thread_dispatch_header = unsafe {*(thread as *const DISPATCHER_HEADER)};
    thread_dispatch_header.__bindgen_anon_1.__bindgen_anon_6.__bindgen_anon_2.DebugActive = 0x0;

}

extern "system" {
    fn PsRegisterSyscallProvider(provider: *mut SyscallProvider, set_to_1: *mut u8, out_provider: *mut *mut SyscallProvider) -> NTSTATUS;
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

extern "system" {
    fn MmIsAddressValid(Address: *mut core::ffi::c_void) -> bool;
}

/// Checks if a function is safe to call
unsafe fn is_function_executable(fn_addr: u64) -> bool {
    let ptr = fn_addr as *mut core::ffi::c_void;
    MmIsAddressValid(ptr)
}

unsafe fn force_page_in(fn_addr: u64) {
    let ptr = fn_addr as *const u8;
    core::ptr::read_volatile(ptr);
}


unsafe fn enable_syscall_providers() {
    // let psp_syscall_providers_enabled: *mut u8 = 0x140d520e as *mut u8;

    // ptr::write_volatile(psp_syscall_providers_enabled, 1);

    // Cast to the fn pointer correct function type 
    // let PsInitializeSyscallProviders: extern "system" fn() -> u64 =  unsafe { transmute(0xfffff80580bf5950 as u64) };
    // let result = PsInitializeSyscallProviders();

    // let mut result: u64 = 0;
    // let fn_adr: u64 = 0xfffff803747f5950;
    // force_page_in(fn_adr);
    // println!("is executable? {}", is_function_executable(fn_adr));
    // asm!(
    //     "call {0:r}",
    //     in(reg) fn_adr,
    //     out("rax") result,
    //     options(nostack),
    // );

    // println!("Result of PsInitializeSyscallProviders = {}!", result);
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

        println!("Calling enable_syscall_providers");

        enable_syscall_providers();

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
    unsafe { install_alt_ssdt() };
    return Ok(());

    
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


// #[repr(C, packed)]
// struct AltSyscallBuffer {
//     process_handle: HANDLE, // 8 bytes
//     thread_handle: HANDLE,  // 8 bytes
//     reserved: [u8; 4], // fill out to 20 bytes
// }

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
        // let mut alt_buffer = AltSyscallBuffer {
        //     process_handle: client_id.UniqueProcess,
        //     thread_handle: client_id.UniqueThread,
        //     reserved: [0,0,0,0],
        // };

        if client_id.UniqueProcess.is_null() || process_handle.is_null() {
            println!("[-] HANDLE WAS NULL!! CANNOT CONTINUE!!!");
            return;
        }

        let result = pZwSetInformationProcess(
            process_handle,
            0x64,
            qw_pid,
            1,
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













////////////////////////////////////////////////////////////////////////////////////////////////

/// Type alias for a 64-bit kernel system-call function that takes 4 parameters
/// and returns an NTSTATUS (which we'll treat as i32 here).
pub type NtSyscallFn = unsafe extern "system" fn(
    ProcessHandle: *mut c_void,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    ClientId: *mut c_void,
) -> i32;

// Define a simple unimplemented stub that returns STATUS_NOT_IMPLEMENTED (0xC0000002).
unsafe extern "system" fn unimplemented(
    _proc_handle: *mut c_void,
    _access: u32,
    _obj_attrs: *mut c_void,
    _cid: *mut c_void,
) -> i32 {
    // 0xC0000002 = STATUS_NOT_IMPLEMENTED
    0xC0000002_u32 as i32
}

/// This is our custom implementation of NtOpenProcess
#[no_mangle]
pub unsafe extern "system" fn MyAltNtOpenProcess(
    ProcessHandle: *mut c_void,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    ClientId: *mut c_void,
) -> i32 {
    // Example: log, modify, or filter calls
    println!(
        "MyAltNtOpenProcess invoked! DesiredAccess = 0x{:X}",
        DesiredAccess
    );

    // If you have a real address of NtOpenProcess, you could call it here:
    // let real_ntopen: NtSyscallFn = core::mem::transmute(REAL_NTOPENPROCESS_ADDR);
    // let status = real_ntopen(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    // return status;

    // For demonstration, return STATUS_SUCCESS (0)
    0
}

// We'll just store *function pointers* in a single array (no Option),
// so it's guaranteed to be a contiguous array of pointers in memory.
#[repr(C)]
pub struct AltSsdt {
    pub entries: [NtSyscallFn; ALT_SSDT_LIMIT],
}

const ALT_SSDT_LIMIT: usize = 0x27;

// Create a mutable static with default = unimplemented for all entries
static mut ALT_SSDT_BASE: AltSsdt = AltSsdt {
    entries: [unimplemented; ALT_SSDT_LIMIT],
};

// Also an array of argument counts, one per entry
static mut ALT_SSDT_ARGS: [u8; ALT_SSDT_LIMIT] = [0; ALT_SSDT_LIMIT];

extern "system" {
    fn KeAddSystemServiceTable(
        base: i64,
        count: i64,
        limit: i32,
        arguments: i64,
        index: i32,
    ) -> i64;
}

static mut ALT_SSDT_INSTALLED: bool = false;

#[no_mangle]
pub unsafe extern "system" fn install_alt_ssdt() -> i32 {

    patch_out_second_ssdt_shadow();

    // 1) Set up the hooking entry
    ALT_SSDT_BASE.entries[0x26] = MyAltNtOpenProcess; 
    ALT_SSDT_ARGS[0x26] = 4; // NtOpenProcess typically has 4 params

    // 2) Call KeAddSystemServiceTable with index=1 (the "alt" slot)
    let base_ptr = ALT_SSDT_BASE.entries.as_ptr() as i64;
    let args_ptr = ALT_SSDT_ARGS.as_ptr() as i64;
    let limit = ALT_SSDT_LIMIT as i32;

    let result = KeAddSystemServiceTable(
        base_ptr,
        0,      // no "count" array
        limit,  // # of entries
        args_ptr,
        1,      // index=1 => alt table
    );

    if result == 1 {
        ALT_SSDT_INSTALLED = true;
        println!("Installed alt SSDT successfully!");
        STATUS_SUCCESS
    } else {
        println!("Failed to install alt SSDT table!");
        0xC0000001_u32 as i32 // some error code
    }
}

fn patch_out_second_ssdt_shadow() {
    // lookup the table
    let mut shadow_name = UNICODE_STRING::default();
    let src: Vec<u16> = "KeServiceDescriptorTable".encode_utf16().collect();
    let src_ptr = PCWSTR::from(src.as_ptr());
    unsafe { RtlInitUnicodeString(&mut shadow_name, src_ptr) };

    let mut sys_srv_disp_tbl_ptr = unsafe { MmGetSystemRoutineAddress(&mut shadow_name) };

    if sys_srv_disp_tbl_ptr.is_null() {
        println!("SSDT was null.");
        return;
    }

    // add the offset to the shadow table at offset 40. Source: https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/ssdt-hook
    let shadow_sys_srv_disp_tbl_ptr = (sys_srv_disp_tbl_ptr as usize + 0x40) as *mut c_void;

    // Add the offset to the 2nd shadow table
    let sssdt_ptr = (shadow_sys_srv_disp_tbl_ptr as usize + 0x20) as *mut c_void;
    let overwrite: u32 = 0;

    unsafe { core::ptr::write(sssdt_ptr as *mut u32, overwrite) };

    println!("Write done at address: {:p}", sssdt_ptr);
}