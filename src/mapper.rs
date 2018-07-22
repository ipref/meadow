/* Copyright (c) 2018 Waldemar Augustyn */

use std::net::Ipv4Addr;

pub struct Arec {
    pub ea: Ipv4Addr,
    pub ip: Ipv4Addr,
    pub gw: Ipv4Addr,
    pub rff: u128, // we want 'ref' but it's a reserved keyword, rff is pronounced ref
}

pub fn get_dst_ipref(daddr: Ipv4Addr) -> (Ipv4Addr, u128) {

    (Ipv4Addr::new(192, 168, 84, 94), 2222)
}

pub fn get_src_ipref(saddr: Ipv4Addr) -> (Ipv4Addr, u128) {

    (Ipv4Addr::new(192, 168, 84, 93), 1111)
}

pub fn get_dst_ip(gw: Ipv4Addr, rff: u128) -> Ipv4Addr {

    Ipv4Addr::new(192, 168, 71, 135)
}

pub fn get_src_ea(gw: Ipv4Addr, rff: u128) -> Ipv4Addr {

    Ipv4Addr::new(10, 244, 4, 202)
}
