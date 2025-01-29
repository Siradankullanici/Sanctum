//! A service runner for the Protected Process Lite Antimalware which allows us to interact with ETW:TI

use std::{sync::atomic::{AtomicBool, Ordering}, thread::sleep, time::Duration};

use windows::{core::{PCWSTR, PWSTR}, Win32::{Foundation::ERROR_SUCCESS, System::Services::{RegisterServiceCtrlHandlerW, SetServiceStatus, StartServiceCtrlDispatcherW, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS}}};

static SERVICE_STOP: AtomicBool = AtomicBool::new(false);

/// The service entrypoint for the binary which will be run via powershell / persistence
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ServiceMain(_: u32, _: *mut PWSTR) {
    // register the service with SCM (service control manager)
    let h_status = match unsafe {RegisterServiceCtrlHandlerW(
        PCWSTR(svc_name().as_ptr()), 
        Some(service_handler)
    )} {
        Ok(h) => h,
        Err(e) => panic!("[!] Could not register service. {e}"),
    };

    // notify SCM that service is starting
    unsafe { update_service_status(h_status, SERVICE_START_PENDING.0) };

    // start the service main loop
    run_service(h_status);

}


/// Main service execution loop
fn run_service(h_status: SERVICE_STATUS_HANDLE) {
    unsafe {
        update_service_status(h_status, SERVICE_RUNNING.0);

        // Main loop
        while !SERVICE_STOP.load(Ordering::SeqCst) {
            sleep(Duration::from_secs(1)); // Simulated workload
        }

        // Cleanup and notify SCM of service stop
        update_service_status(h_status, SERVICE_STOPPED.0);
    }
}


fn svc_name() -> Vec<u16> {
    let mut svc_name: Vec<u16> = vec![];
    "sanctum_ppl_runner".encode_utf16().for_each(|c| svc_name.push(c));
    svc_name.push(0);
    
    svc_name
}

/// Handles service control events (e.g., stop)
unsafe extern "system" fn service_handler(control: u32) {
    match control {
        SERVICE_CONTROL_STOP => {
            SERVICE_STOP.store(true, Ordering::SeqCst);
        }
        _ => {}
    }
}

/// Update the service status in the SCM
unsafe fn update_service_status(h_status: SERVICE_STATUS_HANDLE, state: u32) {
    let mut service_status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_STATUS_CURRENT_STATE(state),
        dwControlsAccepted: if state == SERVICE_RUNNING.0 { 1 } else { 0 },
        dwWin32ExitCode: ERROR_SUCCESS.0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };

    unsafe {SetServiceStatus(h_status, &mut service_status)};
}

fn main() {
    let mut service_name: Vec<u16> = "SanctumPPLRunner\0".encode_utf16().collect();
    
    let mut service_table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(service_name.as_mut_ptr()),
            lpServiceProc: Some(ServiceMain),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];

    unsafe {
        StartServiceCtrlDispatcherW(service_table.as_ptr()).unwrap();
    }
}