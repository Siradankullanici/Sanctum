//! Monitoring of the Events Tracing for Windows kernel structures for tampering by
//! rootkits or kernel mode exploitation.

use core::ffi::c_void;

use alloc::vec::Vec;
use wdk::println;
use wdk_sys::{
    ntddk::{MmGetSystemRoutineAddress, RtlInitUnicodeString},
    UNICODE_STRING,
};

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
pub fn resolve_relative_symbol_offset(
    function_name: &str,
    offset: usize,
) -> Result<*const c_void, ()> {
    let mut function_name_unicode = UNICODE_STRING::default();
    let string_wide: Vec<u16> = function_name.encode_utf16().collect();
    unsafe {
        RtlInitUnicodeString(&mut function_name_unicode, string_wide.as_ptr());
    }

    let function_address =
        unsafe { MmGetSystemRoutineAddress(&mut function_name_unicode) } as usize;
    if function_address == 0 {
        return Err(());
    }

    let offset_to_next_instruction = function_address + offset;
    let mut distance_to_symbol: u32 = 0;

    for i in 0..4 {
        // The starting point has us displaced immediately after the 4 byte offset; so we want to start with the
        // first byte and we then process each byte in the DWORD.
        // We calculate a pointer to the byte we want to read as a u32 (so it can be shifted into a u32). Then
        // shift it left by (i * 8) bits, and then OR them in place by setting the relevant bits.
        let ptr = unsafe { (offset_to_next_instruction as *const u8).sub(4 - i) };
        let byte = unsafe { core::ptr::read(ptr) } as u32;
        distance_to_symbol |= byte << (i * 8);
    }

    // Calculate the actual virtual address of the symbol we are hunting..
    let symbol = offset_to_next_instruction + distance_to_symbol as usize;

    Ok(symbol as *const c_void)
}
