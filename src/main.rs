/* Copyright (c) 2018 Waldemar Augustyn */

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
extern crate byteorder;
#[cfg(debug_assertions)]
extern crate chrono;
extern crate flexi_logger;

use std::sync::Arc;
use std::thread;

mod config;
mod dns;
mod fwd;
mod logger;
mod mapper;

use mapper::Mapper;

// Start threads then wait forever
fn main() {
    //
    let cfg = Arc::new(config::new());
    logger::init(cfg.debug, cfg.trace);

    info!("start {}", crate_name!());

    let map = Arc::new(Mapper::new());

    let threads_to_run: Vec<(&str, fn(&config::Config, &Mapper))> = vec![
        ("fwd_to_gw", fwd::thread_fwd_to_gw),
        ("dns_watcher", dns::thread_dns_watcher),
    ];

    let mut threads_running = vec![];

    for (name, start) in threads_to_run {
        let cfg = cfg.clone();
        let map = map.clone();
        let name = name.to_string();
        threads_running.push(
            thread::Builder::new()
                .name(name)
                .spawn(move || {
                    info!("start thread {}", thread::current().name().unwrap());
                    start(&cfg, &map);
                    info!("finish thread {}", thread::current().name().unwrap());
                })
                .unwrap(),
        );
    }

    for thr in threads_running {
        thr.join().unwrap();
    }

    info!("finish {}", crate_name!());
}
