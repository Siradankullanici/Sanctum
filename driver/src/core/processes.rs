//! This module handles callback implementations and and other function related to processes.

use alloc::{string::{String, ToString}, vec::Vec};
use core::{ffi::c_void, iter::once, ptr::{null_mut, slice_from_raw_parts}, sync::atomic::Ordering};
use shared_no_std::driver_ipc::{HandleObtained, ProcessStarted, ProcessTerminated};
use wdk::println;
use wdk_sys::{
    ntddk::{
        KeGetCurrentIrql, ObOpenObjectByPointer, ObRegisterCallbacks, PsGetCurrentProcessId, PsGetProcessId, PsRemoveLoadImageNotifyRoutine, PsSetLoadImageNotifyRoutine, RtlInitUnicodeString
    }, PsProcessType, APC_LEVEL, HANDLE, NTSTATUS, OB_CALLBACK_REGISTRATION, OB_FLT_REGISTRATION_VERSION, OB_OPERATION_HANDLE_CREATE, OB_OPERATION_HANDLE_DUPLICATE, OB_OPERATION_REGISTRATION, OB_PREOP_CALLBACK_STATUS, OB_PRE_OPERATION_INFORMATION, PEPROCESS, PIMAGE_INFO, PROCESS_ALL_ACCESS, PS_CREATE_NOTIFY_INFO, PUNICODE_STRING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, UNICODE_STRING, _IMAGE_INFO, _MODE::KernelMode, _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS, _UNICODE_STRING
};

use crate::{DRIVER_MESSAGES, REGISTRATION_HANDLE, utils::unicode_to_string};

/// Callback function for a new process being created on the system.
pub unsafe extern "C" fn process_create_callback(
    process: PEPROCESS,
    pid: HANDLE,
    created: *mut PS_CREATE_NOTIFY_INFO,
) {
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

        // todo was trying to do this before!
        // let mut peprocess: PEPROCESS = null_mut();
        // let mut proc_name: PUNICODE_STRING = null_mut();
        // unsafe { PsLookupProcessByProcessId(pid as *mut _, &mut peprocess) };
        // unsafe { SeLocateProcessImageName(peprocess, &mut proc_name) };

        let mut process_handle: HANDLE = null_mut();
        let _ = unsafe {
            ObOpenObjectByPointer(
                process as *mut _,
                0,
                null_mut(),
                PROCESS_ALL_ACCESS,
                *PsProcessType,
                KernelMode as _,
                &mut process_handle,
            )
        };

        // Set both bits: EnableReadVmLogging (bit 0) and EnableWriteVmLogging (bit 1)
        let mut logging_info = ProcessLoggingInformation { flags: 0x03 };
        let result = unsafe {
            ZwSetInformationProcess(
                process_handle,
                87,
                &mut logging_info as *mut _ as *mut _,
                size_of::<ProcessLoggingInformation>() as _,
            )
        };
        // println!("RESULT OF ZwSetInformationProcess: {}", result);

        // todo if image name is malware, here we need to instruct the DLL to be inserted

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
        let process_terminated = ProcessTerminated { pid };

        // println!("[sanctum] [-] Process terminated, {:?}", process_terminated);

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

pub struct ProcessHandleCallback {}

impl ProcessHandleCallback {
    pub fn register_callback() -> Result<(), NTSTATUS> {
        // IRQL <= APC_LEVEL required for ObRegisterCallbacks
        let irql = unsafe { KeGetCurrentIrql() };
        if irql as u32 > APC_LEVEL {
            return Err(1);
        }

        // todo will need a microsoft issues 'altitude'
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request
        let mut callback_registration = OB_CALLBACK_REGISTRATION::default();
        let mut altitude = UNICODE_STRING::default();
        let altitude_str = "327146";
        let altitude_str = altitude_str
            .encode_utf16()
            .chain(once(0))
            .collect::<Vec<_>>();
        unsafe { RtlInitUnicodeString(&mut altitude, altitude_str.as_ptr()) };

        // operation registration
        let mut operation_registration = OB_OPERATION_REGISTRATION::default();
        operation_registration.ObjectType = unsafe { PsProcessType };
        operation_registration.Operations =
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operation_registration.PreOperation = Some(pre_process_handle_callback);

        // // assign to the callback registration
        callback_registration.Altitude = altitude;
        callback_registration.Version = OB_FLT_REGISTRATION_VERSION as u16;
        callback_registration.OperationRegistrationCount = 1;
        callback_registration.RegistrationContext = null_mut();
        callback_registration.OperationRegistration = &mut operation_registration;

        let mut reg_handle: *mut c_void = null_mut();

        let status = unsafe { ObRegisterCallbacks(&mut callback_registration, &mut reg_handle) };
        if status != STATUS_SUCCESS {
            println!(
                "[sanctum] [-] Unable to register callback for handle interception. Failed with code: {status}."
            );
            return Err(STATUS_UNSUCCESSFUL);
        }
        REGISTRATION_HANDLE.store(reg_handle as *mut _, Ordering::Relaxed);

        Ok(())
    }
}

/// Callback function to handle process handle request,s
/// TODO this needs updating to pause on handle, communicate with engine, and make a decision as per drawing
pub unsafe extern "C" fn pre_process_handle_callback(
    ctx: *mut c_void,
    oi: *mut OB_PRE_OPERATION_INFORMATION,
) -> OB_PREOP_CALLBACK_STATUS {
    // todo pick up from here after thread testing

    // println!("Inside callback for handle. oi: {:?}", oi);

    // Check the inbound pointer is valid before attempting to dereference it. We will return 1 as an error code
    if oi.is_null() {
        return 1;
    }

    let p_target_process = (*oi).Object as PEPROCESS;
    let target_pid = PsGetProcessId(p_target_process);
    let source_pid = PsGetCurrentProcessId();

    let desired_access = (*(*oi).Parameters).CreateHandleInformation.DesiredAccess;
    let og_desired_access = (*(*oi).Parameters)
        .CreateHandleInformation
        .OriginalDesiredAccess;

    // if target_pid as u64 == 5228 && source_pid as u64 != 9552 {
    //     println!("[sanctum] [i] Sending PROCESS STARTED INFO {:?}", HandleObtained {
    //         source_pid: source_pid as u64,
    //         dest_pid: target_pid as u64,
    //         rights_desired: og_desired_access,
    //         rights_given: desired_access,
    //     });

    // }

    if !DRIVER_MESSAGES.load(Ordering::SeqCst).is_null() {
        let obj = unsafe { &mut *DRIVER_MESSAGES.load(Ordering::SeqCst) };
        obj.add_process_handle_to_queue(HandleObtained {
            source_pid: source_pid as u64,
            dest_pid: target_pid as u64,
            rights_desired: og_desired_access,
            rights_given: desired_access,
        });
    } else {
        println!("[sanctum] [-] Driver messages is null");
    };

    OB_PREOP_SUCCESS
}

#[repr(C)]
pub union ProcessLoggingInformation {
    pub flags: u32,
}

unsafe extern "system" {
    fn ZwSetInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
    ) -> NTSTATUS;
}

pub fn register_image_load_callback() -> NTSTATUS {
    unsafe { PsSetLoadImageNotifyRoutine(Some(image_load_callback)) }
}

pub fn unregister_image_load_callback() {
    let _ = unsafe { PsRemoveLoadImageNotifyRoutine(Some(image_load_callback)) };
}

/// The callback function for image load events (exe, dll)
extern "C" fn image_load_callback(
    image_name: *mut _UNICODE_STRING,
    pid: HANDLE,
    image_info: *mut _IMAGE_INFO,
) {
    if image_info.is_null() || image_name.is_null() {
        return;
    }

    // Check that we aren't dealing with a driver load, we dont care about those for now
    if pid.is_null() {
        return;
    }

    // Check the inbound pointers
    if image_info.is_null() || image_name.is_null() {
        println!("[sanctum] [-] Pointers were null in image_load_callback, and this is unexpected.");
        return;
    }

    // // SAFETY: Pointers validated so deref
    let image_name = unsafe { *image_name };
    let image_info = unsafe { *image_info };

    let name_slice = slice_from_raw_parts(image_name.Buffer, (image_name.Length / 2) as usize);
    let name = String::from_utf16_lossy(unsafe {&*name_slice});

    // For now only concern ourselves with image loads where its an exe
    if !name.contains(".exe") {
        return;
    }

    println!("name: {:?}, base: {:p}", name, image_info.ImageBase);

    // Step 1: Instruct the engine to inject the DLL

    // Step 2: Loop until done (recv ioctl, going to have to be handled async)

    // Step 3: Return / do other things
}