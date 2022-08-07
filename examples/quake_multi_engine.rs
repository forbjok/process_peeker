use std::{collections::HashMap, time::Duration};

use anyhow::Context;
use once_cell::sync::Lazy;
use process_peeker::AddressPointer;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

struct ExeVersion {
    version: String,
    hp: Vec<AddressPointer>,
}

static GAME_EXECUTABLES: Lazy<HashMap<String, HashMap<u32, ExeVersion>>> = Lazy::new(|| {
    let mut ehm = HashMap::new();

    // --- glquake ---

    let mut hm = HashMap::new();

    // v1.09 (GL 0.95)
    // At the time of writing this code,
    // this is the current version of
    // "Quake (Original)" on steam.
    hm.insert(
        9859072,
        ExeVersion {
            version: "1.09 (GL 0.95) (Steam)".to_owned(),
            hp: vec![0x94c7bc],
        },
    );

    ehm.insert("glquake".to_owned(), hm);

    // --- vkQuake ---

    let mut hm = HashMap::new();

    // v1.05.2
    hm.insert(
        6221824,
        ExeVersion {
            version: "1.05.2".to_owned(),
            hp: vec![0x5d2eb4],
        },
    );

    // v1.20.3 (32-bit)
    hm.insert(
        23941120,
        ExeVersion {
            version: "1.20.3 (32-bit)".to_owned(),
            hp: vec![0x168e258],
        },
    );

    // v1.20.3 (64-bit)
    hm.insert(
        25260032,
        ExeVersion {
            version: "1.20.3 (64-bit)".to_owned(),
            hp: vec![0x17c0658],
        },
    );

    ehm.insert("vkQuake".to_owned(), hm);

    // --- ezQuake ---

    let mut hm = HashMap::new();

    // v3.2.3
    hm.insert(
        137560064,
        ExeVersion {
            version: "3.2.3".to_owned(),
            hp: vec![0xcbede0],
        },
    );

    ehm.insert("ezquake".to_owned(), hm);

    ehm
});

fn main() -> Result<(), anyhow::Error> {
    // Initialize logging
    initialize_logging();

    // Loop forever, trying to connect to any of the supported Quake engine processes
    loop {
        for (name, versions) in GAME_EXECUTABLES.iter() {
            if let Ok(v) = try_connect_game(name, versions) {
                v?;
            }
        }

        std::thread::sleep(Duration::from_secs(5));
    }
}

fn try_connect_game(
    name: &str,
    versions: &HashMap<u32, ExeVersion>,
) -> Result<Result<(), anyhow::Error>, anyhow::Error> {
    let result = process_peeker::try_connect::<_, ()>(name, |p| {
        let module = p.module(&format!("{name}.exe")).with_context(|| "Module not found")?;

        let exe_version = versions
            .get(&module.size)
            .with_context(|| format!("Unsupported executable version (module size: {})", module.size))?;

        println!("{name} v{} detected.", exe_version.version);

        let base_address = module.base_address;

        let hp = p.resolve_pointer_path(base_address, &exe_version.hp)?;

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
    })?;

    // If an error occurred, print it.
    if let Err(err) = result {
        eprintln!("Error: {}", err);
    }

    Ok(Ok(()))
}

fn initialize_logging() {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
        .with_writer(std::io::stderr)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Setting default tracing subscriber failed!");
}
