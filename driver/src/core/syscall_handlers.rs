//! This module deals with kernel side hooks of a syscall we can register via the 
//! undocumented PsRegisterAltSystemCallHandler routine, and we can get its address through
//! `MmGetSystemRoutineAddress`. Good resource on this https://lesnik.cc/hooking-all-system-calls-in-windows-10-20h1/.

use core::{ffi::c_void, mem::transmute};

use wdk::println;
use wdk_sys::{ntddk::{MmGetSystemRoutineAddress, RtlInitUnicodeString}, BOOLEAN, PKTRAP_FRAME, UNICODE_STRING};

use crate::utils::ToU16Vec;

pub enum CoreSyscallHandlerError {
    /// This error is used when we failed to resolve the address of pPsRegisterAltSystemCallHandler
    FuncResolveError,
    /// Indicates the registration of the syscall callback function failed
    RegistrationFail(u32),
}

#[allow(non_snake_case)]
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

    let status = pPsRegisterAltSystemCallHandler(syscall_handler as *mut _, 1);

    // if not STATUS_SUCCESS
    if status != 0 {
        println!("Callback registration failed!");
        return Err(CoreSyscallHandlerError::RegistrationFail(status));
    }

    println!("Callback registered!!");

    Ok(())
}

pub unsafe extern "system" fn syscall_handler(frame: PKTRAP_FRAME) -> BOOLEAN {
    println!("HELLO FROM THE CALLBACK :). Frame: {:p}", frame);
    
    true as _
}

pub fn remove_alt_syscall_handler_from_threads() {
    // todo once implemented
    // ref: https://github.com/Xacone/BestEdrOfTheMarket/blob/main/BestEdrOfTheMarketDriver/src/SyscallsTracing.cpp#L881
}