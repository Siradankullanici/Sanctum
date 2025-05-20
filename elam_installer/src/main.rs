use windows::{
    Win32::{
        Foundation::GENERIC_READ,
        Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING},
        System::{
            Antimalware::InstallELAMCertificateInfo,
            Services::{
                ChangeServiceConfig2W, CreateServiceW, OpenSCManagerW, SC_MANAGER_ALL_ACCESS,
                SERVICE_CONFIG_LAUNCH_PROTECTED, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT, SERVICE_LAUNCH_PROTECTED_INFO,
                SERVICE_WIN32_OWN_PROCESS,
            },
        },
    },
    core::PCWSTR,
};

use std::{env, os::windows::ffi::OsStrExt, path::PathBuf};

fn main() {
    println!("[i] Starting ELAM installer...");

    let driver_path = full_path("sanctum.sys");
    let handle = unsafe {
        CreateFileW(
            PCWSTR(driver_path.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    let handle = match handle {
        Ok(h) => {
            println!(
                "[+] Opened handle to driver at {:?}",
                to_string(&driver_path)
            );
            h
        }
        Err(e) => panic!("[!] Failed to open driver handle. Error: {e}"),
    };

    if let Err(e) = unsafe { InstallELAMCertificateInfo(handle) } {
        panic!("[!] Failed to install ELAM certificate. Error: {e}");
    }

    println!("[+] ELAM certificate installed successfully!");

    println!("[i] Attempting to create the service...");
    let h_sc_mgr =
        match unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) } {
            Ok(h) => h,
            Err(e) => panic!("[!] Unable to open Service Control Manager. Error: {e}"),
        };

    let svc_path = full_path("sanctum_ppl_runner.exe");
    println!(
        "[i] Binary path to be used for service: {}",
        to_string(&svc_path)
    );

    let h_svc = match unsafe {
        CreateServiceW(
            h_sc_mgr,
            PCWSTR(svc_name().as_ptr()),
            PCWSTR(svc_name().as_ptr()),
            SC_MANAGER_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(svc_path.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    } {
        Ok(h) => h,
        Err(e) => panic!("[!] Failed to create service. Error: {e}"),
    };

    let mut info = SERVICE_LAUNCH_PROTECTED_INFO::default();
    info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;

    if let Err(e) = unsafe {
        ChangeServiceConfig2W(
            h_svc,
            SERVICE_CONFIG_LAUNCH_PROTECTED,
            Some(&mut info as *mut _ as *mut _),
        )
    } {
        panic!("[!] Failed to set PPL protection. Error: {e}");
    }

    println!("[+] Service created and protected successfully!");
    println!("[*] Start it with: net.exe start sanctum_ppl_runner");
}

fn svc_name() -> Vec<u16> {
    "sanctum_ppl_runner"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

fn full_path(file: &str) -> Vec<u16> {
    let mut path = env::current_dir().expect("Failed to get current directory");
    path.push(file);
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn to_string(wide: &[u16]) -> String {
    String::from_utf16_lossy(
        wide.iter()
            .take_while(|&&c| c != 0)
            .copied()
            .collect::<Vec<u16>>()
            .as_slice(),
    )
}
