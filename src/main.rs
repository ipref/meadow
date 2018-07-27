/* Copyright (c) 2018 Waldemar Augustyn */

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
extern crate byteorder;
#[cfg(debug_assertions)]
extern crate chrono;
extern crate flexi_logger;

use byteorder::{BigEndian, ByteOrder};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use log::Level;

mod config;
mod fwd;
mod logger;
mod mapper;

// pretty print raw packet
fn pp_raw(pkt: &[u8]) {
    trace!(
        "RAW  {}",
        pkt.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(" ")
    );
}

// pretty print network header
fn pp_net(pkt: &[u8]) {
    // IP[udp] 4500  192.168.84.93  10.254.22.202  len(64) id(1) ttl(64) frag:4000 csum:0000
    if (pkt[0] & 0xf0) != 0x40 {
        trace!("NON-IP {:04x}", BigEndian::read_u16(&pkt[0..2]));
        return;
    }
    let proto;
    trace!(
        "IP[{}] {:04x}  {}  {}  len({}) id({}) ttl({}) frag:{:04x} csum:{:04x}",
        match pkt[9] {
            6 => "tcp",
            17 => "udp",
            1 => "icmp",
            _ => {
                proto = pkt[9].to_string();
                &proto
            }
        },
        BigEndian::read_u16(&pkt[0..2]), // ip ver/hdrlen + dscp
        Ipv4Addr::from(BigEndian::read_u32(&pkt[12..16])), // src
        Ipv4Addr::from(BigEndian::read_u32(&pkt[16..20])), // dst
        BigEndian::read_u16(&pkt[2..4]), // len
        BigEndian::read_u16(&pkt[4..6]), // id
        pkt[8],                          // ttl
        BigEndian::read_u16(&pkt[6..8]), // flags + fragment
        BigEndian::read_u16(&pkt[10..12]), // hdr csum
    );
}

// pretty print transport header
fn pp_trn(pkt: &[u8]) {
    //
    let off = ((pkt[0] & 0xf) * 4) as usize;
    match pkt[9] {
        //6 => {},
        17 => {
            // UDP  1045  1045  len(96) csum 0
            trace!(
                "UDP  {}  {}  len({}) csum:{:04x}",
                BigEndian::read_u16(&pkt[off + 0..off + 2]), // src port
                BigEndian::read_u16(&pkt[off + 2..off + 4]), // dst port
                BigEndian::read_u16(&pkt[off + 4..off + 6]), // len
                BigEndian::read_u16(&pkt[off + 6..off + 8]), // csum
            );
        }
        //1 => {},
        _ => trace!("PROTO[{}]", pkt[9]),
    }
}

enum FakePkt {
    UDP,
    //ICMP,
}

fn fill_iphdr(pkt: &mut [u8], pktlen: usize) {
    //
    BigEndian::write_u16(&mut pkt[0..2], 0x4500);
    BigEndian::write_u16(&mut pkt[2..4], pktlen as u16);
    BigEndian::write_u16(&mut pkt[4..6], 0x0001); // id
    BigEndian::write_u16(&mut pkt[6..8], 0x4000); // DF + fragment offset
    pkt[8] = 64; // ttl
    pkt[9] = 0; // protocol
    BigEndian::write_u16(&mut pkt[10..12], 0x0000); // hdr csum
    pkt[12..16].copy_from_slice(&[192, 168, 84, 93]);
    pkt[16..20].copy_from_slice(&[10, 254, 22, 202]);
}

fn fill_udphdr(pkt: &mut [u8], datalen: usize) {
    //
    BigEndian::write_u16(&mut pkt[0..2], 44123);
    BigEndian::write_u16(&mut pkt[2..4], 2177);
    BigEndian::write_u16(&mut pkt[4..6], datalen as u16);
    BigEndian::write_u16(&mut pkt[6..8], 0x0000); // udp csum
}

fn fill_payload(pkt: &mut [u8]) {
    //
    let mut val: u8 = 0x07;
    for bb in pkt.iter_mut() {
        *bb = val;
        val = val.wrapping_add(1);
    }
}

// create a packet with known contents
fn fill(pb: &mut fwd::PktBuf, what: FakePkt) {
    //
    match what {
        FakePkt::UDP => {
            let mut off = pb.data;
            let pktlen = pb.tail - pb.data;
            fill_iphdr(&mut pb.pkt[off..off + 20], pktlen);
            pb.pkt[off + 9] = 17; // UDP
            off += 20;
            fill_udphdr(&mut pb.pkt[off..off + 8], pktlen - 20);
            off += 8;
            fill_payload(&mut pb.pkt[off..pb.tail]);
        }
    }
}

// testing concepts
fn cip(cfg: &config::Config) {
    //
    let mut pb = fwd::PktBuf::new(cfg);

    // let's send a small udp packet around

    pb.data = config::OPTLEN;
    pb.tail = pb.data + 64;

    debug!("ifc: tun");
    fill(&mut pb, FakePkt::UDP);
    if log_enabled!(Level::Trace) {
        pp_net(&pb.pkt[pb.data..pb.tail]);
        pp_trn(&pb.pkt[pb.data..pb.tail]);
        pp_raw(&pb.pkt[pb.data..pb.tail]);
    }

    debug!("add ipref option");
    pb.fwd_to_gw();
    if log_enabled!(Level::Trace) {
        pp_net(&pb.pkt[pb.data..pb.tail]);
        pp_trn(&pb.pkt[pb.data..pb.tail]);
        pp_raw(&pb.pkt[pb.data..pb.tail]);
    }

    debug!("rem ipref option");
    pb.fwd_to_tun();
    if log_enabled!(Level::Trace) {
        pp_net(&pb.pkt[pb.data..pb.tail]);
        pp_trn(&pb.pkt[pb.data..pb.tail]);
        pp_raw(&pb.pkt[pb.data..pb.tail]);
    }
}

// Start threads then wait forever
fn main() {
    //
    let cfg = Arc::new(config::new());
    logger::init(cfg.debug, cfg.trace);

    info!("Starting {}", crate_name!());

    let cip_cfg = cfg.clone();
    let cip_thread = thread::spawn(move || {
        cip(&cip_cfg);
    });

    cip_thread.join().unwrap();

    info!("Finishing {}", env!("CARGO_PKG_NAME"));
}
