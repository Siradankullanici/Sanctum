use windows::{
    Win32::{
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_READ_DATA, FILE_SHARE_READ, OPEN_EXISTING,
        },
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

fn main() {
    //
    // Step 1:
    // Install the ELAM certificate via the driver (.sys) file.
    //
    println!("[i] Starting Elam installer..");

    let mut path: Vec<u16> = vec![];
    r"C:\Users\flux\AppData\Roaming\Sanctum\sanctum.sys"
        .encode_utf16()
        .for_each(|c| path.push(c));
    path.push(0);

    // todo un hanrdcode this
    let result = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            FILE_READ_DATA.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    let handle = match result {
        Ok(h) => h,
        Err(e) => panic!("[!] An error occurred whilst trying to open a handle to the driver. {e}"),
    };

    if let Err(e) = unsafe { InstallELAMCertificateInfo(handle) } {
        panic!("[!] Failed to install ELAM certificate. Error: {e}");
    }

    println!("[+] ELAM certificate installed successfully!");

    //
    // Step 2:
    // Create a service with correct privileges
    //

    println!("[i] Attempting to create the service.");
    let result = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) };

    let h_sc_mgr = match result {
        Ok(h) => h,
        Err(e) => panic!("[!] Unable to open SC Manager. {e}"),
    };

    // create an own process service

    let result = unsafe {
        CreateServiceW(
            h_sc_mgr,
            PCWSTR(svc_name().as_ptr()),
            PCWSTR(svc_name().as_ptr()),
            SC_MANAGER_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, // Service that runs in its own process
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(svc_bin_path().as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    };

    let h_svc = match result {
        Ok(h) => h,
        Err(e) => panic!("[!] Failed to create service. {e}"),
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
        panic!("[!] Error calling ChangeServiceConfig2W. {e}");
    }

    println!(
        "[+] Successfully initialised the PPL AntiMalware service. It now needs staring with `net.exe start sanctum_ppl_runner`"
    );
}

fn svc_name() -> Vec<u16> {
    let mut svc_name: Vec<u16> = vec![];
    "sanctum_ppl_runner"
        .encode_utf16()
        .for_each(|c| svc_name.push(c));
    svc_name.push(0);

    svc_name
}

fn svc_bin_path() -> Vec<u16> {
    let mut svc_path: Vec<u16> = vec![];
    // todo not hardcode
    r"C:\Users\flux\AppData\Roaming\Sanctum\sanctum_ppl_runner.exe"
        .encode_utf16()
        .for_each(|c| svc_path.push(c));
    svc_path.push(0);
    svc_path
}
