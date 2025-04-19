use std::ptr::null_mut;

use windows::{
    Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_OPENED_EXISTING_KEY,
            REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegSetValueExW,
        },
    },
    core::{Error, PCWSTR, PWSTR},
};

fn to_wstring(s: &str) -> Vec<u16> {
    use std::os::windows::prelude::*;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn create_event_source_key() -> windows::core::Result<()> {
    let subkey_path =
        to_wstring("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\SanctumPPLRunner");

    let mut hkey: HKEY = HKEY(null_mut());
    let mut disposition: u32 = 0;

    unsafe {
        let ret = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_path.as_ptr()),
            None,
            PWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE,
            None, // default security
            &mut hkey,
            Some(&mut disposition as *mut _ as *mut _),
        );
        if ret != ERROR_SUCCESS {
            return Err(Error::from_win32());
        }

        // only create the key once, if it exists, return out
        if disposition == REG_OPENED_EXISTING_KEY.0 {
            return Ok(());
        }

        let value_name = to_wstring("EventMessageFile");
        let exe_path = to_wstring(r"C:\Users\flux\AppData\Roaming\Sanctum\sanctum_ppl_runner.exe"); // todo dont hardcode in prod

        let exe_bytes: &[u8] = std::slice::from_raw_parts(
            exe_path.as_ptr() as *const u8,
            exe_path.len() * std::mem::size_of::<u16>(),
        );

        let ret = RegSetValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            REG_SZ,
            Some(exe_bytes),
        );
        if ret != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(Error::from_win32());
        }

        let value_name_types = to_wstring("TypesSupported");
        let types_supported: u32 = 7; // 7 (0x7) Supports Error, Warning, and Information event types.
        let types_bytes: &[u8] = std::slice::from_raw_parts(
            (&types_supported as *const u32) as *const u8,
            std::mem::size_of::<u32>(),
        );
        let ret = RegSetValueExW(
            hkey,
            PCWSTR(value_name_types.as_ptr()),
            None,
            REG_DWORD,
            Some(types_bytes),
        );
        if ret != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(Error::from_win32());
        }

        let _ = RegCloseKey(hkey);
    }

    Ok(())
}
