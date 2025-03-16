//! Monitoring of the Events Tracing for Windows kernel structures for tampering by
//! rootkits or kernel mode exploitation.

use core::{ffi::c_void, ptr::null_mut, time::Duration};

use alloc::{collections::btree_map::BTreeMap, format, string::String, vec::Vec};
use wdk::println;
use wdk_mutex::{fast_mutex::FastMutex, grt::Grt};
use wdk_sys::{
    ntddk::{
        KeBugCheckEx, KeDelayExecutionThread, MmGetSystemRoutineAddress, ObReferenceObjectByHandle,
        PsCreateSystemThread, PsTerminateSystemThread, RtlInitUnicodeString,
    },
    FALSE, HANDLE, LARGE_INTEGER, STATUS_SUCCESS, THREAD_ALL_ACCESS, UNICODE_STRING,
    _MODE::KernelMode,
};

/// Entrypoint for monitoring kernel ETW structures to detect rootkits or other ETW manipulation
pub fn monitor_kernel_etw() {
    // Call the functions
    monitor_etw_dispatch_table()
        .expect("[sanctum] [-] Failed to start the monitoring of ETW Table");
    monitor_system_logger_bitmask()
        .expect("[sanctum] [-] Failed to start the monitoring of system logging ETW bitmask");

    // Start the thread that will monitor for changes
    let mut thread_handle: HANDLE = null_mut();

    let thread_status = unsafe {
        PsCreateSystemThread(
            &mut thread_handle,
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            Some(thread_run_monitor_etw),
            null_mut(),
        )
    };

    if thread_status != STATUS_SUCCESS {
        panic!("[sanctum] [-] Could not create new thread for monitoring ETW patching");
    }

    // To prevent a BSOD when exiting the thread on driver unload, we need to reference count the handle
    // so that it isn't deallocated whilst waiting on the thread to exit.
    let mut object: *mut c_void = null_mut();
    if unsafe {
        ObReferenceObjectByHandle(
            thread_handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            KernelMode as _,
            &mut object,
            null_mut(),
        )
    } != STATUS_SUCCESS
    {
        panic!("[sanctum] [-] Could not get thread handle by ObRef..");
    }

    Grt::register_fast_mutex("TERMINATION_FLAG_ETW_MONITOR", false)
        .expect("[sanctum] [-] Could not register TERMINATION_FLAG_ETW_MONITOR as a FAST_MUTEX");
    Grt::register_fast_mutex("ETW_THREAD_HANDLE", object)
        .expect("[sanctum] [-] Could not register ETW_THREAD_HANDLE as a FAST_MUTEX");
}

fn monitor_etw_dispatch_table() -> Result<(), ()> {
    let table = match get_etw_dispatch_table() {
        Ok(t) => t,
        Err(_) => panic!("[sanctum] [-] Could not get the ETW Kernel table"),
    };

    // use my `fast-mutex` crate to wrap the ETW table in a mutex and have it globally accessible
    if let Err(e) = Grt::register_fast_mutex_checked("etw_table", table) {
        panic!("[sanctum] [-] wdk-mutex could not register new fast mutex for etw_table");
    }

    Ok(())
}

/// Resolves the relative offset to a symbol being searched for by directly reading kernel memory.
///
/// # Args
///
/// - `function_name`: The name of the function contained in ntoskrnl you wish to search for the symbol
/// - `offset`: The pre-calculated offset to the symbol from manual disassembly. The offset should be the instruction address
///   which IMMEDIATELY follows the 4 byte offset to the struct. See the note for a better explanation.
///
/// # Note
///
/// To accurately select the offset location of the search, you **must** choose the address immediately following the
/// 4 byte (DWORD) offset to  the symbol. For example with this disassembly:
///
///     nt!KeInsertQueueApc:
///     fffff802`7f280380 4c89442418         mov     qword ptr [rsp+18h], r8
///     fffff802`7f280385 4889542410         mov     qword ptr [rsp+10h], rdx
///     fffff802`7f28038a 489c               pushfq  
///     fffff802`7f28038c 53                 push    rbx
///     fffff802`7f28038d 55                 push    rbp
///     fffff802`7f28038e 56                 push    rsi
///     fffff802`7f28038f 57                 push    rdi
///     fffff802`7f280390 4154               push    r12
///     fffff802`7f280392 4155               push    r13
///     fffff802`7f280394 4156               push    r14
///     fffff802`7f280396 4157               push    r15
///     fffff802`7f280398 4883ec70           sub     rsp, 70h
///     fffff802`7f280399 83ec70             sub     esp, 70h
///     fffff802`7f28039a ec                 in      al, dx
///     fffff802`7f28039b 704c               jo      ntkrnlmp!KeInsertQueueApc+0x69 (fffff8027f2803e9)
///     fffff802`7f28039d 8b15b5dfc700       mov     edx, dword ptr [ntkrnlmp!EtwThreatIntProvRegHandle (fffff8027fefe358)]
///     fffff802`7f2803a3 458be9             mov     r13d, r9d
///     ^ YOU WANT THE OFFSET IN BYTES TO THIS ADDRESS
///     fffff802`7f2803a6 488be9             mov     rbp, rcx
///
/// The function will then step back 4 bytes, as they are encoded in LE, to calculate the offset to the actual virtual address of the symbol .
fn resolve_relative_symbol_offset(
    function_name: &str,
    offset: usize,
) -> Result<*const c_void, EtwMonitorError> {
    let mut function_name_unicode = UNICODE_STRING::default();
    let string_wide: Vec<u16> = function_name.encode_utf16().collect();
    unsafe {
        RtlInitUnicodeString(&mut function_name_unicode, string_wide.as_ptr());
    }

    let function_address =
        unsafe { MmGetSystemRoutineAddress(&mut function_name_unicode) } as usize;
    if function_address == 0 {
        println!("[sanctum] [-] Address of {function_name} was null whilst searching for the function address.");
        return Err(EtwMonitorError::SymbolNotFound);
    }

    let offset_to_next_instruction = function_address + offset;
    let mut distance_to_symbol: i32 = 0;

    for i in 0..4 {
        // The starting point has us displaced immediately after the 4 byte offset; so we want to start with the
        // first byte and we then process each byte in the DWORD.
        // We calculate a pointer to the byte we want to read as a u32 (so it can be shifted into a u32). Then
        // shift it left by (i * 8) bits, and then OR them in place by setting the relevant bits.
        let ptr = unsafe { (offset_to_next_instruction as *const u8).sub(4 - i) };
        let byte = unsafe { core::ptr::read(ptr) } as i32;
        distance_to_symbol |= byte << (i * 8);
    }

    // Calculate the actual virtual address of the symbol we are hunting..
    let symbol = offset_to_next_instruction as isize + distance_to_symbol as isize;

    Ok(symbol as *const c_void)
}

pub fn get_etw_dispatch_table<'a>() -> Result<BTreeMap<&'a str, *const c_void>, EtwMonitorError> {
    // Construct the table of pointers to the kernel ETW dispatch objects. This will be stored in
    // a BTreeMap with the key of the dispatch symbol name, and a value of the pointer to the symbol.
    let mut dispatch_table: alloc::collections::BTreeMap<&str, *const c_void> = BTreeMap::new();

    let etw_threat_int_prov_reg_handle = resolve_relative_symbol_offset("KeInsertQueueApc", 35)?;
    dispatch_table.insert("EtwThreatIntProvRegHandle", etw_threat_int_prov_reg_handle);

    // EtwKernelProvRegHandle contiguously follows EtwThreatIntProvRegHandle
    dispatch_table.insert("EtwKernelProvRegHandle", unsafe {
        etw_threat_int_prov_reg_handle.add(8)
    });

    // EtwApiCallsProvRegHandle contiguously follows EtwKernelProvRegHandle
    dispatch_table.insert("EtwApiCallsProvRegHandle", unsafe {
        etw_threat_int_prov_reg_handle.add(8 * 2)
    });

    // Now we are out of contiguous addressing, so we need to search for the symbol
    let etwp_event_tracing_prov_reg_handle = resolve_relative_symbol_offset("EtwUnregister", 452)?;
    dispatch_table.insert(
        "EtwpEventTracingProvRegHandle",
        etwp_event_tracing_prov_reg_handle,
    );

    // EtwpPsProvRegHandle acts as a memory anchor to find the remainder of the table
    dispatch_table.insert("EtwpPsProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x20)
    });

    // The remainder can be calculated based off of pre-determined in memory offsets from EtwpPsProvRegHandle

    dispatch_table.insert("EtwpFileProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(8 * 1)
    });
    dispatch_table.insert("EtwpDiskProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x30)
    });
    dispatch_table.insert("EtwpNetProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x28)
    });
    dispatch_table.insert("EtwLpacProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(8 * 4)
    });
    dispatch_table.insert("EtwCVEAuditProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(8 * 5)
    });
    dispatch_table.insert("EtwAppCompatProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x10)
    });
    dispatch_table.insert("EtwpMemoryProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x8)
    });
    dispatch_table.insert("EtwCpuPartitionProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(0x30)
    });
    dispatch_table.insert("EtwCpuStarvationProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(0x10)
    });
    dispatch_table.insert("EtwSecurityMitigationsRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(0x18)
    });

    for item in &dispatch_table {
        if !(*item.1).is_null() {
            // SAFETY: Null pointer of the inner pointer is checked above; we can guarantee at this point that the original pointer
            // in item.1 is valid, thus the question only remains of the inner pointer.
            let inner_ptr: *const EtwRegEntry = unsafe { *(*item.1 as *const *const EtwRegEntry) };

            if inner_ptr.is_null() {
                println!("[sanctum] [!] Symbol {}: inner pointer is null, raw value found: {:?}. This is indicative of tampering.", item.0, inner_ptr);
                return Err(EtwMonitorError::NullPtr);
            }

            // SAFETY: Pointer dereference checked above
            let etw_reg_entry: &EtwRegEntry = unsafe { &*inner_ptr };
            let actual_guid_entry: *const GuidEntry =
                etw_reg_entry.p_guid_entry as *const GuidEntry;
            if actual_guid_entry.is_null() {
                println!(
                    "[sanctum] [!] Symbol {}: p_guid_entry is null, this is indicative of tampering.",
                    item.0
                );
                return Err(EtwMonitorError::NullPtr);
            }
        }
    }

    Ok(dispatch_table)
}

/// This routine is to be spawned in a thread that monitors rootkit behaviour in the kernel where it tries to blind the
/// EDR via ETW manipulation.
///
/// It monitors for manipulation of:
///
/// - ETW Kernel Dispatch Table
/// - Disabling global active system loggers
unsafe extern "C" fn thread_run_monitor_etw(_: *mut c_void) {
    let table: &FastMutex<BTreeMap<&str, *const c_void>> = Grt::get_fast_mutex("etw_table")
        .expect("[sanctum] [-] Could not get fast mutex for etw_table");
    let delay_as_duration = Duration::from_micros(1);
    let mut sleep_time = LARGE_INTEGER {
        QuadPart: -((delay_as_duration.as_nanos() / 100) as i64),
    };

    loop {
        // Check if we have received the cancellation flag, without this check we will get a BSOD. This flag will be
        // set to true on DriverExit.
        let terminate_flag_lock = Grt::get_fast_mutex("TERMINATION_FLAG_ETW_MONITOR")
            .expect("[sanctum] [-] Could not find TERMINATION_FLAG_ETW_MONITOR");
        let lock = terminate_flag_lock.lock().unwrap();
        if *lock {
            break;
        }

        // Check the ETW table for modification
        check_etw_table_for_modification(table);

        // Check modification of the active system logger bitmask
        check_etw_system_logger_modification();

        let _ = KeDelayExecutionThread(KernelMode as _, FALSE as _, &mut sleep_time);
    }

    let _ = unsafe { PsTerminateSystemThread(STATUS_SUCCESS) };
}

fn check_etw_system_logger_modification() {
    let bitmask_address: &FastMutex<(*const u32, u32)> = Grt::get_fast_mutex("system_logger_bitmask_addr").expect("[sanctum] [-] Could not get system_logger_bitmask_addr from Grt.");
    let lock = bitmask_address.lock().unwrap();

    if (*lock).0.is_null() {
        println!("[sanctum] [-] system_logger_bitmask_addr bitmask was null, this is unexpected.");
        return;
    }

    // Dereference the first item in the tuple (the address of the DWORD bitmask), and compare it with the item at the second tuple entry
    // which is the original value we read when we initialised the driver.
    if unsafe {*(*lock).0} != (*lock).1 {
        println!("[sanctum] [TAMPERING] Modification detected!");
        unsafe { KeBugCheckEx(0x00000109, 0, 0, 0, 0) };
    }
}

fn check_etw_table_for_modification(table: &FastMutex<BTreeMap<&str, *const c_void>>) {
    let table_live_read = match get_etw_dispatch_table() {
        Ok(t) => t,
        Err(e) => match e {
            EtwMonitorError::NullPtr => {
                // This case will tell us tampering has taken place and as such, we need to handle it - we will do this by
                // doing what Patch Guard will do, bringing about a kernel panic with the stop code CRITICAL_STRUCTURE_CORRUPTION.
                // This is acceptable as an EDR. Before panicking however, it would be good to send telemetry to a telemetry collection
                // service, for example if this was an actual networked EDR in an enterprise environment, we would want to send that
                // signal before we execute the bug check. Seeing as this is only building a POC, I am happy just to BSOD :)
                println!("[sanctum] [TAMPERING] Tampering detected with the ETW Kernel Table.");
                unsafe { KeBugCheckEx(0x00000109, 0, 0, 0, 0) };
            }
            EtwMonitorError::SymbolNotFound => {
                println!("[sanctum] [-] Etw function failed with SymbolNotFound when trying to read kernel symbols.");
                return;
            }
        },
    };

    let table_lock = table.lock().unwrap();

    if table_live_read != *table_lock {
        // As above - this should shoot some telemetry off in a real world EDR
        println!("[sanctum] [TAMPERING] ETW Tampering detected, the ETW table does not match the current ETW table.");
        unsafe { KeBugCheckEx(0x00000109, 0, 0, 0, 0) };
    }
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_REG_ENTRY
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct EtwRegEntry {
    unused_0: ListEntry,
    unused_1: ListEntry,
    p_guid_entry: *const GuidEntry,
    // we dont care about the rest of the fields
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_GUID_ENTRY
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct GuidEntry {
    unused_0: ListEntry,
    unused_1: ListEntry,
    unused_2: i64,
    guid: GUID,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct GUID {
    data_1: u32,
    data_2: u16,
    data_3: u16,
    data_4: [u8; 8],
}

impl GUID {
    /// Converts GUID bytes to a prettified hex encoded string in GUID format
    fn to_string(&self) -> String {
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data_1,
            self.data_2,
            self.data_3,
            self.data_4[0],
            self.data_4[1],
            self.data_4[2],
            self.data_4[3],
            self.data_4[4],
            self.data_4[5],
            self.data_4[6],
            self.data_4[7]
        )
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct ListEntry {
    flink: *const c_void,
    blink: *const c_void,
}

#[derive(Debug)]
enum EtwMonitorError {
    NullPtr,
    SymbolNotFound,
}

/// Monitor the system logger bitmask as observed to be exploited by Lazarus in their FudModule rootkit.
///
/// This function monitors abuse of teh _ETW_SILODRIVERSTATE.SystemLoggerSettings.EtwpActiveSystemLoggers bitmask.
fn monitor_system_logger_bitmask() -> Result<(), ()> {
    let address = resolve_relative_symbol_offset("EtwSendTraceBuffer", 78)
        .expect("[ferric-fox] [-] Unable to resolve function EtwSendTraceBuffer")
        as *const *const EtwSiloDriverState;

    if address.is_null() {
        println!("[sanctum] [-] Pointer to EtwSiloDriverState is null");
        return Err(());
    }

    // SAFETY: Null pointer checked above
    if unsafe { *address }.is_null() {
        println!("[sanctum] [-] Address for EtwSiloDriverState is null");
        return Err(());
    }

    // SAFETY: Null pointer checked above
    let active_system_loggers = unsafe { &**address }.settings.active_system_loggers;

    let logger_offset = size_of::<EtwSiloDriverState>();
    let address_of_silo_driver_state_struct = unsafe { *address } as usize;
    let logger_addr = address_of_silo_driver_state_struct + logger_offset - size_of::<u32>();
    let addr = logger_addr as *const u32;

    // Add to the GRT so that we can access it in the monitoring thread
    Grt::register_fast_mutex("system_logger_bitmask_addr", (addr, active_system_loggers))
        .expect("[sanctum] [-] Could not register fast mutex system_logger_bitmask_addr");

    Ok(())
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_SILODRIVERSTATE
#[repr(C)]
struct EtwSiloDriverState {
    unused: [u8; 0x1087],
    settings: EtwSystemLoggerSettings,
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_SYSTEM_LOGGER_SETTINGS
#[repr(C)]
#[derive(Debug)]
struct EtwSystemLoggerSettings {
    unused: [u8; 0xf],
    active_system_loggers: u32,
}
