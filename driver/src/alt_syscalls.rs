use core::ffi::c_void;

use alloc::boxed::Box;
use wdk::println;
use wdk_sys::{
    ntddk::{ExAllocatePool2, IoGetCurrentProcess, IoThreadToProcess}, DISPATCHER_HEADER, DRIVER_OBJECT, KTRAP_FRAME, LIST_ENTRY, PETHREAD, PKTHREAD, PKTRAP_FRAME, POOL_FLAG_NON_PAGED_EXECUTE, _EPROCESS, _KTHREAD
};

use crate::utils::{get_module_base_and_sz, scan_module_for_byte_pattern, DriverError};

const SLOT_ID: u32 = 0;
const SSN_COUNT: usize = 0x500;

pub struct AltSyscalls;

#[repr(C)]
pub struct PspServiceDescriptorGroupTable {
    rows: [PspServiceDescriptorRow; 0x20],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PspServiceDescriptorRow {
    code_block_base:    *const c_void,
    ssn_dispatch_table: *const AltSyscallDispatchTable,
    _reserved:          *const c_void,
}

#[repr(C)]
struct PspSyscallProviderDispatchContext {
    level: u32,
    slot: u32,
}

#[repr(C)]
struct AltSyscallDispatchTable {
    pub count:       u32,
    pub pad:         u32,
    pub descriptors: [u32; SSN_COUNT],
}

#[derive(Copy, Clone)]
pub enum AltSyscallStatus {
    Enable,
    Disable,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AltServiceDescriptor {
    pub service:  *const c_void,
    pub metadata: u32,
    pub _pad:     u32,
}


impl AltSyscalls {
    /// Initialises the required tables in memory
    pub fn enable(driver: &mut DRIVER_OBJECT) {

        // todo improve function, return error state?

        const METADATA: u32 = 0x0;
        // These flags ensure we go the PspSyscallProviderServiceDispatchGeneric route
        const FLAGS: u32 = 0x10;

        // Enforce the SLOT_ID rules at compile time
        const _: () = assert!(SLOT_ID <= 20, "SLOT_ID for alt syscalls cannot be > 20");
        
        //
        // Allocate a non-paged executable region of memory for us to put our shellcode thunks which will
        // essentially 'bootstrap' our callback routine.
        // This thunk array contains 16 bytes per thunk, indexed by the SSN. We will write beyond the usual ntdll
        // SSNs (there are lots more. Not doing so results in system instability. I dont actually know the max number of
        // SSNs, so I've set this to a ridiculous number found in the constant: `SSN_COUNT`.
        //
        let thunk_bytes = SSN_COUNT * 16;
        let p_thunk_array = unsafe {
            ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE,
                thunk_bytes as _,
                b"stb!"[0] as _,
            )
        } as *mut u8;
        if p_thunk_array.is_null() {
            println!("[sanctum] [-] failed to alloc stubs");
            return;
        }

        //
        // For each syscall out of `SSN_COUNT`, we want to write our bootstrap thunk
        // so that we jump to our callback routine.
        //
        let callback_address = syscall_handler as usize as u64;

        for i in 0..SSN_COUNT {
            let dest = unsafe { p_thunk_array.add(i * 16) };

            unsafe {
                // mov rax, imm64
                *dest.offset(0) = 0x48;
                *dest.offset(1) = 0xB8;
                // write the 8-byte address of the callback routine
                core::ptr::write_unaligned(dest.offset(2) as *mut u64, callback_address);
                // jmp rax
                *dest.offset(10) = 0xFF;
                *dest.offset(11) = 0xE0;
                // pad to 16 bytes, write nps
                for pad in 12..16 {
                    *dest.offset(pad) = 0x90;
                }
            }
        }
    
        // 
        // Now build the 'mini dispatch table':  one per descriptor. Using multiple descriptor ID's should enable us to use different 
        // callback routines I think. I haven't experimented with it, but I imagine thats why. When the ID indexes into the table, the offset
        // of the thunk is where we would jump to a different callback routine.
        //
        // low–4 bits   = metadata (0x10 = generic path + N args to capture via a later memcpy),
        // high bits    = descriptor index<<4.
        //
        // Setting FLAGS |= (METADATA & 0xF) means generic path, capture N args
        //
        let mut metadata_table = Box::new(AltSyscallDispatchTable {
            count:       SSN_COUNT as u32,
            pad:         0,
            descriptors: [0; SSN_COUNT],
        });
        for i in 0..SSN_COUNT {
            metadata_table.descriptors[i] = ((i as u32) << 4)
                   | (FLAGS | (METADATA & 0xF));
        }
        // Leak the box so that we don't (for now) have to manage the memory; yes, this is a memory leak in the kernel, I'll fix it later.
        let p_metadata_table = Box::leak(metadata_table) as *const AltSyscallDispatchTable;
        println!("[sanctum] [+] Address of the alt syscalls metadata table: {:p}", p_metadata_table);

        // Get the address of PspServiceDescriptorGroupTable from the kernel by doing some pattern matching; I don't believe
        // we can link to the symbol.
        let kernel_service_descriptor_table = match lookup_global_table_address(driver) {
            Ok(t) => t as *mut PspServiceDescriptorGroupTable,
            Err(_) => {
                println!("[sanctum] failed to find kernel table");
                return;
            }
        };

        //
        // Insert a new row at index 0 in the PspServiceDescriptorGroupTable; in theory, if these were already occupied by other software 
        // using alt syscalls, we would want to find an unoccupied slot.
        // This is what the Slot field relates to on the _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT of _EPROCESS - essentially an index into which
        // syscall provider to use.
        // 
        let new_row = PspServiceDescriptorRow {
            code_block_base:    p_thunk_array as *const c_void,
            ssn_dispatch_table: p_metadata_table,
            _reserved:          core::ptr::null(),
        };

        // Write it to the table
        unsafe {
            (*kernel_service_descriptor_table).rows[SLOT_ID as usize] = new_row;
        }

        // Enumerate all active processes and threads, and enable the relevant bits so that the alt syscall 'machine' can work :)
        Self::walk_active_processes_and_set_bits(AltSyscallStatus::Enable);

    }

    /// Sets the required context bits in memory on thread and KTHREAD.
    pub fn configure_thread_for_alt_syscalls(
        p_k_thread: PKTHREAD,
        status: AltSyscallStatus,
    ) {
        if p_k_thread.is_null() {
            return;
        }

    // Check if is pico process, if it is, we don't want to mess with it, as I haven't spent time reversing the branch
    // for this in PsSyscallProviderDispatch.
    let dispatch_hdr = unsafe { &mut *(p_k_thread as *mut DISPATCHER_HEADER) };
    if unsafe {
        dispatch_hdr
            .__bindgen_anon_1
            .__bindgen_anon_6
            .__bindgen_anon_2
            .DebugActive
            & 4
    } == 4
    {
        return;
    }
    
    // Assuming now we are not a pico-process; set / unset the AltSyscall bit on the ETHREAD depending upon
    // the `status` argument to this function.
    unsafe {
        match status {
            AltSyscallStatus::Enable => {
                dispatch_hdr
                    .__bindgen_anon_1
                    .__bindgen_anon_6
                    .__bindgen_anon_2
                    .DebugActive |= 0x20
            },
            AltSyscallStatus::Disable => {
                dispatch_hdr
                    .__bindgen_anon_1
                    .__bindgen_anon_6
                    .__bindgen_anon_2
                    .DebugActive &= !0x20
            },
        }
    }
    }

    pub fn configure_process_for_alt_syscalls(p_k_thread: PKTHREAD) {
        // We can cast the KTHREAD* as a ETHREAD* as KTHREAD = ETHREAD bytes 0x0 - 0x4c0
        // so they directly map.
        // We will cast the resulting EPROCESS as a *mut u8 as EPROCESS is not defined by the Windows API, and we can just use
        // some pointer arithmetic to edit the fields we want.
        let p_eprocess = unsafe { IoThreadToProcess(p_k_thread as PETHREAD) } as *mut u8;
        let syscall_provider_dispatch_ctx: &mut PspSyscallProviderDispatchContext = if !p_eprocess
            .is_null()
        {
            unsafe {
                let addr = p_eprocess.add(0x7d0) as *mut PspSyscallProviderDispatchContext;
                // SAFETY: I think the dereference of this is fine; we are dereferencing an offset from the EPROCESS - it is not a double pointer.
                // We check the validity of the EPROCESS above before doing this, as that should always be valid. But this deref should be safe.
                &mut *addr
            }
        } else {
            return;
        };

        // Set slot id
        syscall_provider_dispatch_ctx.slot = SLOT_ID;
    }

    /// Uninstall the Alt Syscall handlers from the kernel.
    pub fn uninstall() {
        Self::walk_active_processes_and_set_bits(AltSyscallStatus::Disable);

        // todo clean up the allocated memory
    }

    /// Walk all processes and threads, and set the bits on the process & thread to either enable or disable the 
    /// alt syscall method.
    /// 
    /// # Args:
    /// - `status`: Whether you wish to enable, or disable the feature
    /// 
    /// # Note:
    /// This function is specifically crafted for W11 24H2; to generalise in the future after POC
    fn walk_active_processes_and_set_bits(status: AltSyscallStatus) {
        // Offsets in bytes for Win11 24H2
        const ACTIVE_PROCESS_LINKS_OFFSET: usize = 0x1d8;
        const UNIQUE_PROCESS_ID_OFFSET:  usize = 0x1d0;
        const THREAD_LIST_HEAD_OFFSET:   usize = 0x370;
        const THREAD_LIST_ENTRY_OFFSET:  usize = 0x578;
    
        let current_process = unsafe { IoGetCurrentProcess() };
        if current_process.is_null() {
            println!("[sanctum] [-] current_process was NULL");
            return;
        }
    
        // Get the starting head for the list
        let head = unsafe { (current_process as *mut u8)
            .add(ACTIVE_PROCESS_LINKS_OFFSET) }
            as *mut LIST_ENTRY;
        let mut entry = unsafe { (*head).Flink };
    
        while entry != head {
            // Get the record for the _EPROCESS
            let p_e_process = unsafe { (entry as *mut u8)
                .sub(ACTIVE_PROCESS_LINKS_OFFSET) }
                as *mut _EPROCESS;
            
            let pid = unsafe {
                let p = (p_e_process as *mut u8).add(UNIQUE_PROCESS_ID_OFFSET) as *const usize;
                *p
            };
    
            // Skip the Idle process (PID 0) as there are no threads present and it gave a null ptr deref
            if pid == 0 {
                entry = unsafe { (*entry).Flink };
                continue;
            }
    
            // Walk threads
            let thread_head = unsafe { (p_e_process as *mut u8)
                .add(THREAD_LIST_HEAD_OFFSET) }
                as *mut LIST_ENTRY;
            let mut thread_entry = unsafe { (*thread_head).Flink };
    
            while thread_entry != thread_head {
                // Here we have each thread, we can now go and set the bit on the thread and process to make 
                // alt syscalls work
                let p_k_thread = unsafe { (thread_entry as *mut u8)
                    .sub(THREAD_LIST_ENTRY_OFFSET) }
                    as *mut _KTHREAD;

                Self::configure_thread_for_alt_syscalls(p_k_thread, status);
                Self::configure_process_for_alt_syscalls(p_k_thread);
    
                thread_entry = unsafe { (*thread_entry).Flink };
            }
    
            // Move on to the next process
            entry = unsafe { (*entry).Flink };
        }
    }
}

/// The callback routine which we control to run when a system call is dispatched via my alt syscall technique.
/// 
/// # Args:
/// - `p_nt_function`: A function pointer to the real Nt* dispatch function (e.g. NtOpenProcess)
/// - `ssn`: The System Service Number of the syscall
/// - `args_base`: The base address of the args passed into the original syscall rcx, rdx, r8 and r9
/// - `p3_home`: The address of `P3Home` of the _KTRAP_FRAME
/// 
/// # Note:
/// We can use the `p3_home` arg that is passed into this callback to calculate the actual address of the 
/// `KTRAP_FRAME`, where we can get the address of the stack pointer, that we can use to gather any additional 
/// arguments which were passed into the syscall.
/// 
/// # Safety
/// This function is **NOT** compatible with the `PspSyscallProviderServiceDispatch` branch of alt syscalls, it 
/// **WILL** result in a bug check in that instance. This can only be used with 
/// `PspSyscallProviderServiceDispatchGeneric`.
pub unsafe extern "system" fn syscall_handler(
    _p_nt_function: PKTRAP_FRAME,
    ssn: u32,
    args_base: *const c_void,
    p3_home: *const c_void,
) -> i32 {

    if args_base.is_null() || p3_home.is_null() {
        println!("[sanctum] [-] Args base or arg4 was null??");
        return 1;
    }

    let k_trap = unsafe { p3_home.sub(0x10) } as *const KTRAP_FRAME;
    if k_trap.is_null() {
        println!("[sanctum] [-] KTRAP_FRAME was null");
        return 1;
    }

    const ARG_5_STACK_OFFSET: usize = 0x28;

    let k_trap = &unsafe { *k_trap };
    let rsp = k_trap.Rsp as *const c_void;
    let rcx  = unsafe { *(args_base as *const _ as *const usize) } as usize;

    // todo need to dynamically resolve the syscall for symbol
    match ssn {
        0x18 => {            
            let rcx_handle  = unsafe { 
                *(args_base as *const *const c_void)
             };
            let rdx_base_addr = unsafe { 
                *(args_base.add(0x8) as *const *const c_void)
            };
            let r8_zero_bit = unsafe { 
                *(args_base.add(0x10) as *const *const usize)
            };
            let r9_sz = unsafe {
                **(args_base.add(0x18) as *const *const usize)
            };
            let alloc_type = unsafe { *(rsp.add(ARG_5_STACK_OFFSET) as *const _ as *const u32) } as u32;
            let protect = unsafe { *(rsp.add(ARG_5_STACK_OFFSET + 8) as *const _ as *const u32) } as u32;

            println!("[VirtualAllocEx] [i] handle: {:p}, base: {:p}, zero bit: {:p}, Size: {}, alloc_type: {:#x}, protect: {:#x}", rcx_handle, rdx_base_addr, r8_zero_bit, r9_sz, alloc_type, protect);
        },
        0x26 => {
            println!("[NtOpenProcess] [i] Hook. SSN {:#x}, rcx as usize: {}. Stack ptr: {:p}", ssn, rcx, rsp);
        },
        0x3a => {
            println!("[Write virtual memory] [i] Hook. SSN {:#x}, rcx as usize: {}. Stack ptr: {:p}", ssn, rcx, rsp);
        },
        0x4e => {
            println!("[create thread] [i] Hook. SSN {:#x}, rcx as usize: {}. Stack ptr: {:p}", ssn, rcx, rsp);
        },
        0xc9 => {
            println!("[create thread ex] [i] Hook. SSN {:#x}, rcx as usize: {}. Stack ptr: {:p}", ssn, rcx, rsp);
        },
        _ => {
            // println!("SSN: {:#x}", ssn);
        },
    }

    1
}

/// Get the address of the non-exported kernel symbol: `PspServiceDescriptorGroupTable`
fn lookup_global_table_address(_driver: &DRIVER_OBJECT) -> Result<*mut c_void, DriverError> {
    let module = match get_module_base_and_sz("ntoskrnl.exe") {
        Ok(k) => k,
        Err(e) => {
            println!("[sanctum] [-] Unable to get kernel base address. {:?}", e);
            return Err(DriverError::ModuleNotFound);
        }
    };

    let fn_address =
        scan_module_for_byte_pattern(module.base_address, module.size_of_image, &[
            // from nt!PsSyscallProviderDispatch
            0x48, 0x89, 0x5c, 0x24, 0x08, //mov     qword ptr [rsp+8], rbx
            0x55, // push    rbp
            0x56, // push    rsi
            0x57, // push    rdi
            0x41, 0x56, // push    r14
            0x41, 0x57, // push    r15
            0x48, 0x83, 0xec, 0x30, // sub     rsp, 30h
            0x48, 0x83, 0x64, 0x24, 0x70, 0x00, // and     qword ptr [rsp+70h], 0
            0x48, 0x8b, 0xf1, // mov     rsi, rcx
            0x65, 0x48, 0x8b, 0x2c, 0x25, 0x88, 0x01, 0x00, 0x00, // mov     rbp, qword ptr gs:[188h]
            0xf6, 0x45, 0x03, 0x04, // test    byte ptr [rbp+3], 4
        ])? as *const u8;


    // offset from fn
    let instruction_address = unsafe { fn_address.add(0x77) };

    println!("Instruction address to get offset: {:p}", instruction_address);

    let disp32 = unsafe {
        core::ptr::read_unaligned((instruction_address.add(3)) as *const i32)
    } as isize;
    let next_rip = instruction_address as isize + 7;
    let absolute = (next_rip + disp32) as *const c_void;

    println!("Address of PspServiceDescriptorGroupTable: {:p}", absolute);

    Ok(absolute as *mut _)

}
