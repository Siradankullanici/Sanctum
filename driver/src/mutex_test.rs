use core::{ffi::c_void, ptr::null_mut, sync::atomic::{AtomicPtr, Ordering}};
use alloc::boxed::Box;
use wdk::println;
use wdk_mutex::kmutex::KMutex;
use wdk_sys::{ntddk::PsCreateSystemThread, CLIENT_ID, HANDLE, OBJECT_ATTRIBUTES};


extern crate alloc;

pub static HEAP_MTX_PTR: AtomicPtr<KMutex<u32>> = AtomicPtr::new(null_mut());

pub fn test_multithread_mutex() {

    //
    // inline mutex on same thread
    //

    let mtx = KMutex::new(12u32).unwrap();
    let lock = mtx.lock().unwrap();
    println!("The value is: {}", lock);

    //
    // Prepare global static for access in multiple threads.
    //

    let heap_mtx = Box::new(KMutex::new(0u32).unwrap());
    let heap_mtx_ptr = Box::into_raw(heap_mtx);
    HEAP_MTX_PTR.store(heap_mtx_ptr, Ordering::SeqCst);
    println!("After mutex stuff");

    let p = HEAP_MTX_PTR.load(Ordering::SeqCst);
    if !p.is_null() {
        let p = unsafe { &*p };
        let mut lock = p.lock().unwrap();
        println!("Got the lock before change! {}", *lock);
        *lock += 1;
        println!("After the change: {}", *lock);
    }
    
    //
    // spawn x threads to test
    //
    for _ in 0..3 {
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

        println!("[i] Thread status: {status}");
    }
}


unsafe extern "C" fn callback_fn(_: *mut c_void) {
    for _ in 0..1500 {
        let p = HEAP_MTX_PTR.load(Ordering::SeqCst);
        if !p.is_null() {
            let p = unsafe { &*p };
            let mut lock = p.lock().unwrap();
            // println!("Got the lock before change! {}", *lock);
            *lock += 1;
            println!("After the change: {}", *lock);
        }
    }

    // Proof of threads acting concurrently; if these printed after x iterations from the for loop, that
    // would indicate that it is not running concurrently. 
    println!("THREAD FINISHED.");
}