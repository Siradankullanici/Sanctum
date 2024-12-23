use core::{ffi::c_void, ptr::null_mut, sync::atomic::AtomicPtr};
use alloc::boxed::Box;
use wdk::println;
use wdk_mutex::FastMutex;
use wdk_sys::{ntddk::{KeGetCurrentIrql, KeWaitForSingleObject, PsCreateSystemThread}, CLIENT_ID, FALSE, HANDLE, OBJECT_ATTRIBUTES, PASSIVE_LEVEL, STATUS_SUCCESS, _KWAIT_REASON::Executive, _MODE::KernelMode};

extern crate alloc;

static INT_PTR: AtomicPtr<FastMutex<i32>> = AtomicPtr::new(null_mut());

pub fn multi_thread_test() {

    let my_int_mutex = Box::into_raw(Box::new(
        FastMutex::new(0i32).unwrap()
    ));

    INT_PTR.store(my_int_mutex, core::sync::atomic::Ordering::Relaxed);

    let mut thread_handles: [HANDLE; 2] = [
        null_mut(),
        null_mut(),
    ];

    if unsafe { KeGetCurrentIrql() } != PASSIVE_LEVEL as u8 {
        println!("[-] IRQL invalid. Set at: {}", unsafe { KeGetCurrentIrql() });
        return;
    }

    for i in 0..2 {
        let mut thread_handle: HANDLE = null_mut();

        let status = unsafe {
            PsCreateSystemThread(
                &mut thread_handle, 
                0, 
                null_mut::<OBJECT_ATTRIBUTES>(), 
                null_mut(),
                null_mut::<CLIENT_ID>(), 
                Some(callback_fn), 
                null_mut(),
            )
        };
        assert_eq!(status, STATUS_SUCCESS);
        thread_handles[i] = thread_handle;
    }

    println!("IRQL From main thread: {}", unsafe {
        KeGetCurrentIrql()
    });

    // for handle in &thread_handles {
    //     unsafe {
    //         let _ = KeWaitForSingleObject(
    //             *handle, 
    //             Executive, 
    //             KernelMode as i8, 
    //             FALSE as u8, 
    //             null_mut(),
    //         );
    //     }
    // }

}

unsafe extern "C" fn callback_fn(_: *mut c_void) {
    println!("IRQL From spawned thread: {}", unsafe {
        KeGetCurrentIrql()
    });
    let ptr_mutex = &*INT_PTR.load(core::sync::atomic::Ordering::Relaxed);

    for i in 0..10 {
        let mut mtx = ptr_mutex.lock().unwrap();
        *mtx += 1;
        println!("i = {i}, mutex val = {}", *mtx);
    }
}