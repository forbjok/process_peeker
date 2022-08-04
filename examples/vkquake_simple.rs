use std::time::Duration;

use anyhow::Context;
use process_peeker::AddressPointer;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

const HP_POINTER_PATH: &[AddressPointer] = &[0x17c0658];

fn main() -> Result<(), anyhow::Error> {
    // Initialize logging
    initialize_logging();

    // Loop forever, trying to connect to the vkQuake process
    loop {
        let result = process_peeker::connect::<_, ()>("vkQuake", |p| {
            let module = p.module("vkQuake.exe").with_context(|| "Module not found")?;

            if module.size != 25260032 {
                return Err(anyhow::anyhow!(
                    "Unsupported executable version (module size: {})",
                    module.size
                ));
            }

            println!("vkQuake v1.20.3 detected.");

            let base_address = module.base_address;

            let hp = p.resolve_pointer_path(base_address, HP_POINTER_PATH)?;

            let mut prev_value: Option<i32> = None;

            loop {
                let value: i32 = p.peek(hp)?;

                if let Some(prev_value) = prev_value.take() {
                    if value != prev_value {
                        if prev_value > 0 {
                            // Player was alive on last update
                            if value < prev_value {
                                println!("You took {} damage!", prev_value - value);
                            }

                            if value > prev_value {
                                println!("You healed for {}.", value - prev_value);
                            }

                            if value <= 0 {
                                println!("LOL! You died!");
                            }
                        } else {
                            // Player was dead on last update
                            if value > 0 {
                                println!("You respawned with {} health.", value);
                            }
                        }
                    }
                }

                prev_value = Some(value);

                std::thread::sleep(Duration::from_millis(250));
            }
        });

        // If an error occurred, print it.
        if let Err(err) = result {
            eprintln!("Error: {}", err);
        }
    }
}

fn initialize_logging() {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
        .with_writer(std::io::stderr)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Setting default tracing subscriber failed!");
}
