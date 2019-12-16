#[macro_use]
extern crate cfg_if;
extern crate common;
extern crate protobuf;

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        extern crate sabre_sdk;
    } else {
        #[macro_use]
        extern crate clap;
        #[macro_use]
        extern crate log;
        extern crate log4rs;
        extern crate sawtooth_sdk;
        use std::process;
        use log::LevelFilter;
        use log4rs::append::console::ConsoleAppender;
        use log4rs::config::{Appender, Config, Root};
        use log4rs::encode::pattern::PatternEncoder;
        use sawtooth_sdk::processor::TransactionProcessor;
        use handler::CertTransactionHandler;
    }
}

mod handler;
mod payload;
mod state;

/// Standard entry point
#[cfg(not(target_arch = "wasm32"))]
fn main() {
    let matches = clap_app!(item =>
        (version: crate_version!())
        (about: "Cert_registry Transaction Processor (Rust)")
        (@arg connect: -C --connect +takes_value
         "connection endpoint for validator")
        (@arg verbose: -v --verbose +multiple
         "increase output verbosity"))
    .get_matches();

    let endpoint = matches
        .value_of("connect")
        .unwrap_or("tcp://localhost:4004");

    let console_log_level;
    match matches.occurrences_of("verbose") {
        0 => console_log_level = LevelFilter::Warn,
        1 => console_log_level = LevelFilter::Info,
        2 => console_log_level = LevelFilter::Debug,
        3 | _ => console_log_level = LevelFilter::Trace,
    }

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{h({l:5.5})} | {({M}:{L}):20.20} | {m}{n}",
        )))
        .build();

    let config = match Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(console_log_level))
    {
        Ok(x) => x,
        Err(e) => {
            for err in e.errors().iter() {
                info!("Configuration error: {}", err.to_string());
            }
            process::exit(1);
        }
    };

    match log4rs::init_config(config) {
        Ok(_) => (),
        Err(e) => {
            info!("Configuration error: {}", e.to_string());
            process::exit(1);
        }
    }

    let handler = CertTransactionHandler::new();
    let mut processor = TransactionProcessor::new(endpoint);

    info!("Console logging level: {}", console_log_level);

    processor.add_handler(&handler);
    processor.start();
}

/// If the TP is compiled to WASM, so it can be executed as a Sabre smart contract, the entry point
/// is defined in the handler rather than here
#[cfg(target_arch = "wasm32")]
fn main() {}
