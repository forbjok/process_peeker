use std::{collections::HashMap, time::Duration};

use anyhow::Context;
use once_cell::sync::Lazy;
use process_peeker::AddressSpec;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

struct ExeVersion {
    version: String,
    hp: AddressSpec,
}

static GAME_EXECUTABLES: Lazy<HashMap<String, HashMap<String, ExeVersion>>> = Lazy::new(|| {
    let mut ehm = HashMap::new();

    // --- glquake ---

    let mut hm = HashMap::new();

    // v1.09 (GL 0.95)
    // At the time of writing this code,
    // this is the current version of
    // "Quake (Original)" on steam.
    hm.insert(
        "5bb6bb30d8f50f32785a80415b93d1572bada955ac64e91b91532be779a273c4".to_owned(),
        ExeVersion {
            version: "1.09 (GL 0.95) (Steam)".to_owned(),
            hp: AddressSpec::PointerPath(vec![0x94c7bc]),
        },
    );

    ehm.insert("glquake".to_owned(), hm);

    // --- vkQuake ---

    let mut hm = HashMap::new();

    // v1.05.2 (64-bit)
    hm.insert(
        "68e853667e3bd4db56ede3f186a9e791595f35f17c631405ab3fbd3f62980e8a".to_owned(),
        ExeVersion {
            version: "1.05.2".to_owned(),
            hp: AddressSpec::PointerPath(vec![0x5d2eb4]),
        },
    );

    // v1.20.3 (32-bit)
    hm.insert(
        "336a923ffc0d82f8b9c35c3d670d95bb9591c24bb993085092d248fc83abca9d".to_owned(),
        ExeVersion {
            version: "1.20.3 (32-bit)".to_owned(),
            hp: AddressSpec::PointerPath(vec![0x168e258]),
        },
    );

    // v1.20.3 (64-bit)
    hm.insert(
        "1a216ffc898be44143479de60570baeb32c7ea592b52fdd4d295d821400f61a5".to_owned(),
        ExeVersion {
            version: "1.20.3 (64-bit)".to_owned(),
            hp: AddressSpec::PointerPath(vec![0x17c0658]),
        },
    );

    ehm.insert("vkQuake".to_owned(), hm);

    // --- ezQuake ---

    let mut hm = HashMap::new();

    // v3.2.3
    hm.insert(
        "efa739ed7ab48ba088813d488370f33ed4ce9c87bed6d8dbaecabdd9ca2cb804".to_owned(),
        ExeVersion {
            version: "3.2.3".to_owned(),
            hp: AddressSpec::PointerPath(vec![0xcbede0]),
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
    versions: &HashMap<String, ExeVersion>,
) -> Result<Result<(), anyhow::Error>, anyhow::Error> {
    let result = process_peeker::try_connect::<_, ()>(name, |p| {
        let module = p.module(&format!("{name}.exe"))?.with_context(|| "Module not found")?;
        let hash = module.hash_sha256()?;

        let exe_version = versions
            .get(&hash)
            .with_context(|| format!("Unsupported executable version (SHA256: {})", hash))?;

        println!("{name} v{} detected.", exe_version.version);

        let hp = module.resolve::<i32>(&exe_version.hp)?;

        let mut prev_value: Option<i32> = None;

        loop {
            let value: i32 = hp.peek()?;

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
