fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ahpc <config.json>");
        std::process::exit(1);
    }

    let config_data = match std::fs::read_to_string(&args[1]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read config file '{}': {}", args[1], e);
            std::process::exit(1);
        }
    };

    if let Err(e) = ahpc::run_proxy_from_json(&config_data) {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}
