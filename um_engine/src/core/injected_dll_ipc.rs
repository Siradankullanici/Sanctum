//! The Sanctum EDR DLL which is injected into processes needs a way to communicate
//! with the engine, and this module provides the functionality for this.

use std::{ffi::c_void, mem, ptr::null_mut, sync::atomic::AtomicPtr};

use shared_std::constants::PIPE_FOR_INJECTED_DLL;
use tokio::net::windows::named_pipe::ServerOptions;
use windows::Win32::{Foundation::{FALSE, GENERIC_ALL}, Security::{AddAccessAllowedAceEx, AllocateAndInitializeSid, GetSidLengthRequired, InitializeAcl, InitializeSecurityDescriptor, SetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SECURITY_WORLD_SID_AUTHORITY}, System::SystemServices::{SECURITY_DESCRIPTOR_REVISION, SECURITY_WORLD_RID}};

use crate::utils::log::{Log, LogLevel};

static SECURITY_PTR: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// Starts the IPC server for the DLL injected into processes to communicate with
pub async fn run_ipc_for_injected_dll() {
    // Store the pointer in the atomic so we can safely access it across 
    let sa_ptr = create_security_attributes() as *mut c_void;
    SECURITY_PTR.store(sa_ptr, std::sync::atomic::Ordering::SeqCst);

    // SAFETY: Null pointer checked at start of function
    let mut server = unsafe {ServerOptions::new()
        .first_pipe_instance(true)
        .create_with_security_attributes_raw(PIPE_FOR_INJECTED_DLL, sa_ptr)
        .expect("[-] Unable to create named pipe server for injected DLL")};

    let server = tokio::spawn(async move {
        let logger = Log::new();

        loop {
            // wait for a connection 
            logger.log(LogLevel::Info, "Waiting for IPC message from DLL");
            server.connect().await.expect("Could not get a client connection for injected DLL ipc");
            let connected_client = server;

            // Construct the next server before sending the one we have onto a task, which ensures
            // the server isn't closed
            let sec_ptr = SECURITY_PTR.load(std::sync::atomic::Ordering::SeqCst);
            if sec_ptr.is_null() {
                logger.panic("Security pointer was null for IPC server.");
            }
            // SAFETY: null pointer checked above
            server = unsafe { ServerOptions::new().create_with_security_attributes_raw(PIPE_FOR_INJECTED_DLL, sec_ptr).expect("Unable to create new version of IPC for injected DLL") };
            
            let client = tokio::spawn(async move {
                println!("Hello from the client! {:?}", connected_client);
                // todo use the client 
            });
        }
    });
}

/// Create a permissive security descriptor allowing processes at all user levels, groups, etc to access this named pipe.
/// This will ensure processes at a low privilege can communicate with the pipe
/// 
/// # Note
/// A number of heap allocated structures will be leaked via `Box::leak()` - this is okay and not considered a memory leak as
/// this will be called once during the creation of the named pipe and then are required for the duration of the process.
fn create_security_attributes() -> *mut SECURITY_ATTRIBUTES {
    unsafe {
        //
        // Allocate the SECURITY_DESCRIPTOR on the heap and initialise
        //
        let mut sd_box = Box::new(SECURITY_DESCRIPTOR::default());

        InitializeSecurityDescriptor(
            PSECURITY_DESCRIPTOR(&mut *sd_box as *mut _ as _),
            SECURITY_DESCRIPTOR_REVISION,
        )
        .ok()
        .expect("InitializeSecurityDescriptor failed");


        //
        // build the ACL and add the Everyone ACE
        //
        let acl_size = mem::size_of::<ACL>() as u32
            + mem::size_of::<ACCESS_ALLOWED_ACE>() as u32
            + GetSidLengthRequired(1);
        let mut acl_buf = Vec::with_capacity(acl_size as usize);
        acl_buf.set_len(acl_size as usize); // reserve space

        InitializeAcl(
            acl_buf.as_mut_ptr() as *mut ACL,
            acl_size,
            ACL_REVISION,
        )
        .ok()
        .expect("InitializeAcl failed");

        
        //
        // Allocate the SID for Everyone
        //
        let mut everyone_sid: PSID = PSID::default();
        AllocateAndInitializeSid(
            &SECURITY_WORLD_SID_AUTHORITY,
            1,
            SECURITY_WORLD_RID as u32,
            0,0,0,0,0,0,0,
            &mut everyone_sid,
        )
        .ok()
        .expect("AllocateAndInitializeSid failed");

        AddAccessAllowedAceEx(
            acl_buf.as_mut_ptr() as *mut ACL,
            ACL_REVISION,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            GENERIC_ALL.0,
            everyone_sid,
        )
        .ok()
        .expect("AddAccessAllowedAceEx failed");


        //
        // Attach the ACL to the descriptor
        //
        SetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(&mut *sd_box as *mut _ as _),
            true,
            Some(acl_buf.as_ptr() as *const ACL),
            false,
        )
        .ok()
        .expect("SetSecurityDescriptorDacl failed");


        //
        // Allocate SECURITY_ATTRIBUTES on the heap and fill it
        //
        let mut sa_box = Box::new(SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: &mut *sd_box as *mut _ as *mut core::ffi::c_void,
            bInheritHandle: FALSE,
        });


        // 
        // Leak everything so that we can ensure their lifetime is valid for the duration of the 
        // entire program. The memory will be cleaned up when the process exits.
        //
        Box::leak(sd_box);
        Box::leak(Box::new(acl_buf));
        Box::leak(sa_box)
    }
}