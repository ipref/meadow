/* Copyright (c) 2018 Waldemar Augustyn */

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
extern crate flexi_logger;
extern crate chrono;

use flexi_logger::Logger;
use std::io;
use chrono::Local;

mod config;

fn main() {

    /* Get config
     *
     *  Ideally, cfg would be acessible globally from any thread without locks
     *  and without fear.
     *
     *  Currently, rust makes such an arrangement very difficult to implement
     *  without degrading to 'unsafe'. For now, we're going to pass cfg around
     *  as a parameter.
     */

    let cfg = config::get();

    println!("configuration:");
    println!("    port:   {}", cfg.port);
    println!("    debug:  {}", cfg.debug);

    Logger::with_env_or_str(if cfg.debug {"meadow=debug"}else{"meadow=info"})
        .format(log_formt)
        .start()
        .unwrap();

    trace!("trace message");
    debug!("debug message");
    info!("info message");
    warn!("warn message");
    error!("error message");
}

fn log_formt(ww: &mut io::Write, rec: &log::Record) -> Result<(), io::Error> {

    write!(ww, "{} {:5} [{}] {}:{}: {}",
        Local::now().format("%H:%M:%S%.6f"),
        rec.level(),
        rec.module_path().unwrap_or("<unnamed>"),
        rec.file().unwrap_or("<unnamed>"),
        rec.line().unwrap_or(0),
        &rec.args()
    )
}
