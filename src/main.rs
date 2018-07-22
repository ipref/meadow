/* Copyright (c) 2018 Waldemar Augustyn */

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
#[cfg(debug_assertions)]
extern crate chrono;
extern crate flexi_logger;

mod config;
mod logger;
mod fwd;
mod mapper;

// concepts in progress

enum fill_type {
    LOCAL_UDP,
    LOCAL_ICMP,
}

// create a packet with known contents
fn fill(pb: &mut fwd::PktBuf, what:fill_type) {

    match what {
        fill_type::LOCAL_UDP => {
        }
        fill_type::LOCAL_ICMP => {
        }
    }
}

fn cip() {

    let mut pb = fwd::PktBuf::new();

    fill(&mut pb, fill_type::LOCAL_UDP);
    pb.fwd_to_gw();
    pb.fwd_to_tun();
}

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
    println!("    port:   {}", cfg.gw_port);
    println!("    debug:  {}", cfg.debug);

    trace!("trace message");
    debug!("debug message");
    info!("info message");
    warn!("warn message");
    error!("error message");

    cip()
}
