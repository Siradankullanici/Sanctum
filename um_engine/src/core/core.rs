use std::sync::Arc;

use shared_no_std::ghost_hunting::Syscall;
use tokio::{
    sync::{Mutex, RwLock, mpsc},
    time::sleep,
};

use crate::{
    core::process_monitor::inject_edr_dll,
    driver_manager::SanctumDriverManager,
    utils::log::{Log, LogLevel},
};

use super::{
    ipc_etw_consumer::run_ipc_for_etw,
    ipc_injected_dll::run_ipc_for_injected_dll,
};

/// The core struct contains information on the core of the usermode engine where decisions are being made, and directly communicates
/// with the kernel.
///
/// # Components
///
/// - `driver_poll_rate`: the poll rate in milliseconds that the kernel will be (approximately) queried. The
/// approximation is because the polling / decision making loop is not asynchronous and other decision making
/// takes place prior to the poll rate sleep time.
/// - `driver_dbg_message_cache`: a temporary cache of messages which are returned from the kernel which the
/// GUI can request.
#[derive(Debug, Default)]
pub struct Core {
    driver_poll_rate: u64,
    driver_dbg_message_cache: Mutex<Vec<String>>,
    // process_monitor: RwLock<ProcessMonitor>,
}

impl Core {
    /// Initialises a new Core instance from a poll rate in **milliseconds**.
    pub fn from(poll_rate: u64) -> Self {
        let mut core = Core::default();

        core.driver_poll_rate = poll_rate;

        core
    }

    /// Starts the core of the usermode engine; kicking off the frequent polling of the driver, and conducts relevant decision making
    pub async fn start_core(&self, driver_manager: Arc<Mutex<SanctumDriverManager>>) -> ! {
        let logger = Log::new();

        //
        // To start with, we will snapshot all running processes and then add them to the active processes.
        // there is possible a short time window where processes are created / terminated, which may cause
        // a zone of 'invisibility' at this point in time, but this should be fixed in the future when
        // we receive handles / changes to processes, if they don't exist, they should be created then.
        // todo - marker for info re above.
        //
        // let snapshot_processes = snapshot_all_processes().await;

        // extend the newly created local processes type from the results of the snapshot
        // self.process_monitor
        //     .write()
        //     .await
        //     .extend_processes(snapshot_processes);

        let (tx, mut rx) = mpsc::channel(1000);
        let (tx_etw, mut rx_etw) = mpsc::channel(1000);

        // Start the IPC server for the injected DLL to communicate with the core
        tokio::spawn(async {
            run_ipc_for_injected_dll(tx).await;
        });

        // Start the IPC server for the ETW consumer
        tokio::spawn(async {
            run_ipc_for_etw(tx_etw).await;
        });

        //
        // Enter the polling & decision making loop, this here is the core / engine of the usermode engine.
        // todo: we need to actually inspect what these params are doing and if they are malicious.
        //
        loop {
            // See if there is a message from the injected DLL
            if let Ok(rx) = rx.try_recv() {
                // let mut lock = self.process_monitor.write().await;
                // lock.ghost_hunt_add_event(rx.clone());
                let mut mtx = driver_manager.lock().await;
                mtx.ioctl_dll_syscall(rx);
            }

            // Check for events from the ETW listener
            if let Ok(rx) = rx_etw.try_recv() {
                // let mut lock = self.process_monitor.write().await;
                // lock.ghost_hunt_add_event(rx);
            }

            // contact the driver and get any messages from the kernel
            // todo needing to unlock the driver manager is an unnecessary bottleneck
            let driver_response = {
                let mut mtx = driver_manager.lock().await;
                mtx.ioctl_get_driver_messages()
            };

            let image_loads = {
                let mut mtx = driver_manager.lock().await;
                mtx.ioctl_get_image_loads_for_injecting_sanc_dll()
            };

            //
            // If we have new message(s) / emissions from the driver or injected DLL, process them as appropriate
            //
            if driver_response.is_some() {
                // first deal with process terminations to prevent trying to add to an old process id if there is a duplicate
                let mut driver_messages = driver_response.unwrap();
                // let process_terminations = driver_messages.process_terminations;
                // if !process_terminations.is_empty() {
                //     for t in process_terminations {
                //         self.process_monitor
                //             .write()
                //             .await
                //             .remove_process(t.pid)
                //             .await;
                //     }
                // }

                // add a new process to the running process hashmap
                // let process_creations = driver_messages.process_creations;
                // if !process_creations.is_empty() {
                //     for p in process_creations {
                //         if self
                //             .process_monitor
                //             .write()
                //             .await
                //             .onboard_new_process(&p)
                //             .await
                //             .is_err()
                //         {
                //             logger.log(
                //                 LogLevel::Error,
                //                 &format!(
                //                     "Failed to add new process to live processes. Process: {:?}",
                //                     p
                //                 ),
                //             );
                //         }
                //     }
                // }

                // process all handles
                // if !driver_messages.handles.is_empty() {
                //     for item in driver_messages.handles {
                //         self.process_monitor
                //             .write()
                //             .await
                //             .add_handle_driver_notified(
                //                 item.source_pid,
                //                 item.dest_pid,
                //                 item.rights_given,
                //                 item.rights_desired,
                //             );
                //     }
                // }

                // cache messages
                {
                    let mut message_cache = self.driver_dbg_message_cache.lock().await;
                    if !driver_messages.messages.is_empty() {
                        message_cache.append(&mut driver_messages.messages);
                    }
                }

                //
                // Perform checks of process timers for Ghost Hunting
                // What is Ghost Hunting? https://fluxsec.red/edr-syscall-hooking
                //
                // self.process_monitor.write().await.poll_ghost_timer();

                /*
                    todo long term:
                        - thread creation
                        - change of handle type (e.g. trying to evade detection)
                        - is the process doing bad things itself (allocating foreign mem)

                    ^ to the abv hashmap
                */
            }

            if let Some(image_loads) = image_loads {
                for pid in image_loads {
                    println!("[i] Target process detected, injecting EDR DLL...");
                    if let Err(e) = inject_edr_dll(pid as _) {
                        logger.log(LogLevel::Error, &format!("Error injecting DLL: {:?}", e));
                    };
                }
            }
        }
    }

    /// Gets the cached driver messages for use in the GUI
    ///
    /// # Returns
    ///
    /// If there are no messages cached, None will be returned. Otherwise, a vector of the messages
    /// will be returned to the caller.
    pub async fn get_cached_driver_messages(&self) -> Option<Vec<String>> {
        let mut msg_lock = self.driver_dbg_message_cache.lock().await;

        if msg_lock.is_empty() {
            return None;
        }

        let tmp = msg_lock.clone();
        msg_lock.clear();

        Some(tmp)
    }

    // Query a given process by its Pid, returning information about the process
    // pub async fn query_process_by_pid(&self, pid: u64) -> Option<Process> {
    //     self.process_monitor.read().await.query_process_by_pid(pid)
    // }
}
