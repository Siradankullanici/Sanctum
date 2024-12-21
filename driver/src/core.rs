// ******************************************************************** //
// ************************** CORE CALLBACKS ************************** //
// ******************************************************************** //

use core::{ffi::c_void, iter::once, ptr::null_mut, sync::atomic::Ordering};

use alloc::vec::Vec;
use shared_no_std::driver_ipc::{ProcessStarted, ProcessTerminated};
use wdk::println;
use wdk_sys::{ntddk::{KeGetCurrentIrql, ObRegisterCallbacks, PsGetCurrentProcessId, PsGetProcessId, RtlInitUnicodeString}, PsProcessType, APC_LEVEL, HANDLE, NTSTATUS, OB_CALLBACK_REGISTRATION, OB_FLT_REGISTRATION_VERSION, OB_OPERATION_HANDLE_CREATE, OB_OPERATION_HANDLE_DUPLICATE, OB_OPERATION_REGISTRATION, OB_PREOP_CALLBACK_STATUS, OB_PRE_OPERATION_INFORMATION, PEPROCESS, PS_CREATE_NOTIFY_INFO, PVOID, STATUS_SUCCESS, UNICODE_STRING, _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS};

use crate::{utils::unicode_to_string, DRIVER_MESSAGES, REGISTRATION_HANDLE};

/// Callback function for a new process being created on the system.
pub unsafe extern "C" fn core_callback_notify_ps(process: PEPROCESS, pid: HANDLE, created: *mut PS_CREATE_NOTIFY_INFO) {

    //
    // If `created` is not a null pointer, this means a new process was started, and you can query the 
    // args for information about the newly spawned process.
    //
    // In the event that `create` is null, it means a process was terminated.
    //

    if !created.is_null() {
        // process started

        let image_name = unicode_to_string((*created).ImageFileName);
        let command_line = unicode_to_string((*created).CommandLine);
        let parent_pid = (*created).ParentProcessId as u64;
        let pid = pid as u64;

        if image_name.is_err() || command_line.is_err() {
            return;
        }

        let process_started = ProcessStarted {
            image_name: image_name.unwrap().replace("\\??\\", ""),
            command_line: command_line.unwrap().replace("\\??\\", ""),
            parent_pid,
            pid,
        };
        
        // Attempt to dereference the DRIVER_MESSAGES global; if the dereference is successful,
        // add the relevant data to the queue
        if !DRIVER_MESSAGES.load(Ordering::SeqCst).is_null() {
            let obj = unsafe { &mut *DRIVER_MESSAGES.load(Ordering::SeqCst) };
            obj.add_process_creation_to_queue(process_started);
        } else {
            println!("[sanctum] [-] Driver messages is null");
        };
        
    } else {
        // process terminated

        let pid = pid as u64;
        let process_terminated = ProcessTerminated {
            pid,
        };

        println!("[sanctum] [-] Process terminated, {:?}", process_terminated);

        // Attempt to dereference the DRIVER_MESSAGES global; if the dereference is successful,
        // add the relevant data to the queue
        if !DRIVER_MESSAGES.load(Ordering::SeqCst).is_null() {
            let obj = unsafe { &mut *DRIVER_MESSAGES.load(Ordering::SeqCst) };
            obj.add_process_termination_to_queue(process_terminated);
        } else {
            println!("[sanctum] [-] Driver messages is null");
        };
    }
}

pub struct ProcessHandleCallback {
    handle: PVOID,
}

impl ProcessHandleCallback {
    pub fn new() -> Result<Self, NTSTATUS> {

        let irql = unsafe { KeGetCurrentIrql() };
        if irql as u32 > APC_LEVEL {
            return Err(1)
        }

        // todo will need a microsoft issues 'altitude'
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request
        let mut callback_registration = OB_CALLBACK_REGISTRATION::default();
        let mut altitude = UNICODE_STRING::default();
        let altitude_str = "327146";
        let altitude_str = altitude_str.encode_utf16().chain(once(0)).collect::<Vec<_>>();
        unsafe { RtlInitUnicodeString(&mut altitude, altitude_str.as_ptr()) };

        // operation registration
        let mut operation_registration = OB_OPERATION_REGISTRATION::default();
        operation_registration.ObjectType = unsafe { PsProcessType };
        operation_registration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operation_registration.PreOperation = Some(pre_process_handle_callback);

        // assign to the callback registration
        callback_registration.Altitude = altitude;
        callback_registration.Version = OB_FLT_REGISTRATION_VERSION as u16;
        callback_registration.OperationRegistrationCount = 1;
        callback_registration.RegistrationContext = null_mut();
        callback_registration.OperationRegistration = &mut operation_registration;

        let status = unsafe {ObRegisterCallbacks(&mut callback_registration, &raw mut REGISTRATION_HANDLE)};
        if status != STATUS_SUCCESS {
            println!("[sanctum] [-] Unable to register callback for handle interception. Failed with code: {status}.");
            return Err(status);
        }

        Ok(
            unsafe {
                ProcessHandleCallback {
                    handle: REGISTRATION_HANDLE,
                }
            }
        )
    }
}

/// Callback function to handle process handle request,s 
pub unsafe extern "C" fn pre_process_handle_callback(ctx: *mut c_void, oi: *mut OB_PRE_OPERATION_INFORMATION) -> OB_PREOP_CALLBACK_STATUS {
    println!("Inside callback for handle. oi: {:?}", oi);

    // Check the pointer is valid before attempting to dereference it. We will return 1 as an error code
    if oi.is_null() {
        return 1
    }

    let p_target_process = (*oi).Object as PEPROCESS;
    let target_pid = PsGetProcessId(p_target_process);
    let source_pid = PsGetCurrentProcessId();
    
    println!("PEPROCESS: {:?}, target: {}, source: {}", p_target_process, target_pid as u64, source_pid as u64);

    OB_PREOP_SUCCESS

}