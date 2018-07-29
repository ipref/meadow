/* Copyright (c) 2018 Waldemar Augustyn */

use byteorder::{BigEndian, ByteOrder};
use std::net::Ipv4Addr;

use config;
use mapper::Mapper;

pub struct PktBuf {
    // a la skbuf
    pub pkt: Vec<u8>,
    pub data: usize, // ix to start of pkt
    pub tail: usize, // ix to end of pkt
}

impl PktBuf {
    //
    pub fn new(cfg: &config::Config) -> Self {
        PktBuf {
            pkt: vec![0; cfg.gw_mtu as usize + cfg.tun_hdrlen], // typically 1504
            data: 0,
            tail: 0,
        }
    }

    pub fn add_ipref_option(&mut self, map: &Mapper) {
        //
        let ea = Ipv4Addr::from(BigEndian::read_u32(
            &self.pkt[self.data + 16..self.data + 20],
        ));
        let ip = Ipv4Addr::from(BigEndian::read_u32(
            &self.pkt[self.data + 12..self.data + 16],
        ));

        let (dst_gw, dst_ref) = map.get_their_ipref(ea);
        if dst_gw.is_unspecified() {
            error!("cannot get their gw+ref for {}, sending icmp()", ea);
            return;
        }
        let (src_gw, src_ref) = map.get_our_ipref(ip);
        if src_gw.is_unspecified() {
            error!("cannot get our gw+ref for {}, sending icmp()", ip);
            return;
        }
        self.data -= config::OPTLEN;
    }
    /*
    pub fn remove_ipref_option(&mut self) {
        let dst_gw = Ipv4Addr::new(192, 168, 84, 94);
        let dst_rff = 0x6622;
        let src_gw = Ipv4Addr::new(192, 168, 84, 93);
        let src_rff = 0x5511;

        let dst_ip = mapper::get_dst_ip(dst_gw, dst_rff);
        let src_ip = mapper::get_src_ea(src_gw, src_rff);
        self.data += config::OPTLEN;
    }
*/
}
