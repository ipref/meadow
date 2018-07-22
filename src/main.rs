/* Copyright (c) 2018 Waldemar Augustyn */

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
#[cfg(debug_assertions)]
extern crate chrono;
extern crate flexi_logger;

use std::sync::Arc;
use std::thread;

mod config;
mod fwd;
mod logger;
mod mapper;

enum FillType {
    LocalUDP,
    LocalICMP,
}

// create a packet with known contents
fn fill(pb: &mut fwd::PktBuf, what: FillType) {
    match what {
        FillType::LocalUDP => {}
        FillType::LocalICMP => {}
    }
}

fn cip(cfg: &config::Config) {
    let mut pb = fwd::PktBuf::new(cfg);

    fill(&mut pb, FillType::LocalUDP);
    pb.fwd_to_gw();
    pb.fwd_to_tun();
}

// Start threads then wait forever
fn main() {
    let cfg = Arc::new(config::new());
    logger::init(cfg.debug);

    let cip_cfg = cfg.clone();
    let cip_thread = thread::spawn(move || {
        cip(&cip_cfg);
    });

    cip_thread.join().unwrap();
}
