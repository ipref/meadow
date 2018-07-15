/* Copyright (c) 2018 Waldemar Augustyn */

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
extern crate flexi_logger;
#[cfg(debug_assertions)]
extern crate chrono;

mod config;
mod logger;

fn main() {

    /* Get config
     *
     *  Ideally, cfg would be acessible globally from any thread without locks
     *  and without fear.
     *
     *  Currently, rust makes such an arrangement very difficult to implement. In
     *  truth, it makes it impossible. We're going to follow other implementations
     *  which opt for a mutable structure protected by mutex.
     */

    let cfg = config::get();
    logger::init(cfg.debug);

    println!("configuration:");
    println!("    port:   {}", cfg.port);
    println!("    debug:  {}", cfg.debug);

    trace!("trace message");
    debug!("debug message");
    info!("info message");
    warn!("warn message");
    error!("error message");
}
