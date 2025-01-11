//! Processes.rs contains all functions associated with the process page UI in Tauri.
//! This module will handle state, requests, async, and events.

use shared_std::processes::Process;

use crate::ipc::IpcClient;

#[tauri::command]
pub async fn process_query_pid(pid: String) -> Result<String, ()> {
    match IpcClient::send_ipc::<Process, String>("process_query_pid", Some(pid)).await {
        Ok(response) => {
            return Ok(
                serde_json::to_string(&response).unwrap()
            )
        },
        Err(e) => {
            eprintln!("[-] Error with IPC: {e}");
            return Ok("IPC error".to_string());
        },
    };
}