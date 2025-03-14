//! Monitoring of the Events Tracing for Windows kernel structures for tampering by
//! rootkits or kernel mode exploitation.

use alloc::vec::Vec;
use wdk_sys::{
    ntddk::{MmGetSystemRoutineAddress, RtlInitUnicodeString},
    UNICODE_STRING,
};

/// Resolves the relative offset to a symbol being searched for by directly reading kernel memory.
///
/// # Args
///
/// - `function_name`: The name of the function contained in ntoskrnl you wish to search for the symbol
/// - `offset`: The pre-calculated offset to the symbol from manual disassembly. The offset should be the offset by number of
///   bytes at which the next 4 bytes are the address of the symbol.
fn resolve_relative_symbol_offset(function_name: &str, offset: usize) -> Result<(), ()> {
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

    let offset_to_instruction = function_address + offset;

    Ok(())
}