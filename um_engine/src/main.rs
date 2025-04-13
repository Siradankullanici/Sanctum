//! The main entrypoint for the usermode engine for the Sanctum EDR. This will run as a service
//! on the host machine and is responsible for all EDR related activity in usermode, including
//! communicating with the driver, GUI, DLL's; performing scanning; and decision making.

#![feature(io_error_uncategorized)]

use engine::Engine;
use utils::log::Log;

mod core;
mod driver_manager;
mod engine;
mod filescanner;
mod gui_communication;
mod settings;
mod strings;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //
    // Start the engine, this will kick off and run the application; note this should never return,
    // unless an error occurred.
    //
    let error = Engine::start().await;

    let logger = Log::new();
    logger.panic(&format!(
        "A fatal error occurred in Engine::start() causing the application to crash. {:?}",
        error
    ));
}
