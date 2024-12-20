use std::sync::Arc;

use tokio::sync::Mutex;

use crate::{core::core::Core, driver_manager::SanctumDriverManager, filescanner::FileScanner, gui_communication::ipc::UmIpc, usermode_api::UsermodeAPI, utils::log::Log};

/// Engine is the central driver and control point for the Sanctum EDR. It is responsible for
/// managing the core features of the EDR, including:
/// 
/// - Communication with the driver
/// - Communication with the GUI
/// - Decision making
/// - Scanning
/// - Process monitoring
/// - File monitoring
/// - Driver management
pub struct Engine {}

impl Engine {
    /// Start the engine
    pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
        //
        // Start by instantiating the elements we will be using in the engine.
        // Once created; clone them as Arcs to share across the threads
        //

        // core
        let core = Arc::new(Core::from(60));
        let core_umipc = Arc::clone(&core);

        // file scanner
        let scanner = FileScanner::new().await;
        if let Err(e) = scanner {
            panic!("[-] Failed to initialise scanner: {e}.");
        }
        let file_scanner = Arc::new(scanner.unwrap());
        let file_scanner_clone = Arc::clone(&file_scanner);

        // GUI IPC receiver 
        let usermode_api = Arc::new(UsermodeAPI::new().await);
        let umapi_umipc = Arc::clone(&usermode_api);

        // driver manager
        // Happy the driver manager being wrapped in a mutex now; it isn't a high performance module and I
        // don't need necessarily to spend time refactoring that at the moment. The only place the mutex may
        // cause a bottleneck is when making IOCTL calls via SanctumDriverManager.
        // todo review
        let driver_manager = Arc::new(Mutex::new(SanctumDriverManager::new()));
        let drv_mgr_for_umipc = Arc::clone(&driver_manager);
        let drv_mgr_for_core = Arc::clone(&driver_manager);

        //
        // Spawn the core of the engine which will constantly talk to the driver and process any IO
        // from / to the driver and other working parts of the EDR, except for the GUI which will
        // be handled below.
        //
        // The `core` is passed into the start method as an Arc<Mutex<>> so we can share its data with
        // other threads from the engine / usermode IPC loops.
        //
        let core_handle = tokio::spawn(async move {
            core.start_core(drv_mgr_for_core).await;
        });

        // blocks indefinitely unless some error gets thrown up
        // todo review this; can this state ever crash the app?
        let gui_ipc_handle = tokio::spawn(async move {
            let error = UmIpc::listen(
                umapi_umipc, 
                core_umipc,
                file_scanner_clone,
                drv_mgr_for_umipc,
            ).await;
            
            let logger = Log::new();
            logger.log(crate::utils::log::LogLevel::NearFatal, &format!("A near fatal error occurred in Engine::start() causing the application to crash. {:?}", error));
        });

        // If one thread returns out an error of the runtime; we want to return out of the engine and
        // halt
        tokio::try_join!(core_handle, gui_ipc_handle)?;
        
        Ok(())
    }
}