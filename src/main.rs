/* Copyright (c) 2018 Waldemar Augustyn */

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
#[cfg(debug_assertions)]
extern crate chrono;
extern crate flexi_logger;
extern crate byteorder;

use std::sync::Arc;
use std::thread;
use byteorder::{BigEndian, ByteOrder};

mod config;
mod fwd;
mod logger;
mod mapper;

enum FillType {
    LocalUDP,
    //LocalICMP,
}

// create a packet with known contents
#[allow(unused_variables)]
fn fill(pb: &mut fwd::PktBuf, what: FillType) {
    //
    match what {
        FillType::LocalUDP => {} //FillType::LocalICMP => {}
    }
}

fn modify(sub: &mut[u8]) {
    //
    for ix in 0..sub.len() {
        sub[ix] = ix as u8 + 50;
    }
}

fn cip(cfg: &config::Config) {
    //

    // --- slices

    let mut pkt: [u8; 32] = [0; 32];
    let off = 1;

    for ix in 0..pkt.len() {
        pkt[ix] = ix as u8;
    }

    pkt[off] = 0x45;  // make it valid IPv4

    info!("before: {}", pkt.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join(" "));

    modify(&mut pkt[off+3..off+7]);
    BigEndian::write_u32(&mut pkt[off+11..off+15], 0x01020304);
    BigEndian::write_u16(&mut pkt[off+15..off+17], 0xaabb);

    info!("unaligned read: {:08x}", BigEndian::read_u32(&pkt[off+2..off+6]));

    info!("after:  {}", pkt.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join(" "));

    // --- slices

    let mut pb = fwd::PktBuf::new(cfg);

    // let's send a small udp packet around

    pb.data = config::OPTLEN;
    pb.tail = pb.data + 64;

    fill(&mut pb, FillType::LocalUDP);
    pb.fwd_to_gw();
    pb.fwd_to_tun();
}

// Start threads then wait forever
fn main() {
    //
    let cfg = Arc::new(config::new());
    logger::init(cfg.debug);

    info!("Starting {}", crate_name!());

    let cip_cfg = cfg.clone();
    let cip_thread = thread::spawn(move || {
        cip(&cip_cfg);
    });

    cip_thread.join().unwrap();

    info!("Finishing {}", env!("CARGO_PKG_NAME"));
}
