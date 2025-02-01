//! A basic event log module to log any errors / events in the Windows Event Log making debugging
//! easier.

use windows::{core::PCWSTR, Win32::System::EventLog::{DeregisterEventSource, RegisterEventSourceW, ReportEventW, REPORT_EVENT_TYPE}};

/// Logs an event to the Windows Event Log for the `SanctumPPLRunner` log directory.
/// 
/// # Args
/// - msg: A message you wish to log
/// - event_type: The event type to log
/// 
/// # Errors
/// If this function encounters an error, it will return with taking no action and thus, could silently 
/// fail. There is no real abstraction to be had to returning an error from the function; it will either 
/// work or it wont, it will not affect the caller.
pub fn event_log(msg: &str, event_type: REPORT_EVENT_TYPE) {
    // todo consider adding an enum which will exit on error or just return.
    let source: Vec<u16> = "SanctumPPLRunner\0".encode_utf16().collect();

    let handle = match unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(source.as_ptr())) } {
        Ok(h) => h,
        Err(_) => return,
    };

    let msg_wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    let msg_as_pcwstr = PCWSTR(msg_wide.as_ptr());

    // write the event into the event log
    let _ = unsafe {
        ReportEventW(
            handle, 
            event_type, 
            0,
            1, // todo change for prod https://learn.microsoft.com/en-us/windows/win32/eventlog/event-identifiers
            None, 
            0,
            Some([msg_as_pcwstr].as_ref()),
            None, // no binary data
        )
    };

    let _ = unsafe { DeregisterEventSource(handle) };
    
}