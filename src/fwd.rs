/* Copyright (c) 2018 Waldemar Augustyn */

use std::net::Ipv4Addr;

use config;
use mapper;

pub struct PktBuf {
    // a la skbuf
    pub pkt: Vec<u8>,
    pub data: usize, // ix to start of pkt
    pub tail: usize, // ix to end of pkt
}

impl PktBuf {
    pub fn new(cfg: &config::Config) -> Self {
        PktBuf {
            pkt: vec![0; cfg.gw_mtu as usize + cfg.tun_hdrlen], // typically 1504
            data: 0,
            tail: 0,
        }
    }

    pub fn fwd_to_gw(&mut self) {
        self.add_ipref_option()
    }

    pub fn fwd_to_tun(&mut self) {
        self.remove_ipref_option()
    }

    fn add_ipref_option(&mut self) {
        let daddr = Ipv4Addr::new(10, 254, 4, 44);
        let saddr = Ipv4Addr::new(192, 168, 71, 135);

        let (dst_gw, dst_rff) = mapper::get_dst_ipref(daddr);
        let (src_gw, src_rff) = mapper::get_src_ipref(saddr);
        self.data -= config::OPTLEN;
    }

    fn remove_ipref_option(&mut self) {
        let dst_gw = Ipv4Addr::new(192, 168, 84, 94);
        let dst_rff = 0x6622;
        let src_gw = Ipv4Addr::new(192, 168, 84, 93);
        let src_rff = 0x5511;

        let dst_ip = mapper::get_dst_ip(dst_gw, dst_rff);
        let src_ip = mapper::get_src_ea(src_gw, src_rff);
        self.data += config::OPTLEN;
    }
}
