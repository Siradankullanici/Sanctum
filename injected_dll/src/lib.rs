use std::{ffi::c_void, ptr::null_mut};
use windows::{Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK}, Win32::System::SystemServices::*,};
use windows::core::s;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::LibraryLoader::FreeLibraryAndExitThread;
use windows::Win32::System::Threading::{CreateThread, LPTHREAD_START_ROUTINE, THREAD_CREATION_FLAGS};

static mut HMODULE_INSTANCE: HINSTANCE = HINSTANCE(null_mut()); // handle to the module instance of the injected dll

enum LoadModule {
    FreeLibrary,
    StartImplant,
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
fn DllMain(hmod_instance: HINSTANCE, dw_reason: u32, _: usize) -> i32 {
    match dw_reason {
        DLL_PROCESS_ATTACH => unsafe {
            HMODULE_INSTANCE = hmod_instance; // set a handle to the module for a clean unload
            spawn_thread(LoadModule::StartImplant); // start implant in a new thread
        },
        _ => (),
    }

    1
}

/// Entrypoint to the actual implant to be spawned as a new thread from DLL_PROCESS_ATTACH.
/// This should help to prevent problems whereby a LoaderLock interferes with our implant.<br/><br/>
/// Think of this as calling a function to start something from main().
#[unsafe(no_mangle)]
unsafe extern "system" fn attach(_lp_thread_param: *mut c_void) -> u32 {
    unsafe { MessageBoxA(None, s!("Hello from Rust DLL"), s!("Hello from Rust DLL"), MB_OK) };

    // implant completed execution, unload the DLL
    spawn_thread(LoadModule::FreeLibrary);

    1
}

/// Spawn a new thread in the current injected process, calling a function pointer to a function
/// will run.
fn spawn_thread(lib_to_load: LoadModule) {
    unsafe {
        // function pointer to where the new thread will begin
        let thread_start: LPTHREAD_START_ROUTINE;

        match lib_to_load {
            LoadModule::FreeLibrary => thread_start = Some(unload_dll),
            LoadModule::StartImplant => thread_start = Some(attach)
        }

        // create a thread with a function pointer to the region of the program we want to execute.
        let _thread_handle = CreateThread(
            None,
            0,
            thread_start,
            None,
            THREAD_CREATION_FLAGS(0),
            None,
        );
    }
}

#[unsafe(no_mangle)]
/// Unload the DLL by its handle, so that there is no live evidence of hte DLL in memory after its
/// finished its business, plus allows for loading multiple of the same DLL into the same process
unsafe extern "system" fn unload_dll(_lpthread_param: *mut c_void) -> u32 {
    unsafe { MessageBoxA(None, s!("Unloading"), s!("Unloading"), MB_OK) };
    unsafe { FreeLibraryAndExitThread(HMODULE_INSTANCE.into(), 1) };
}