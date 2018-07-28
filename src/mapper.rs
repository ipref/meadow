/* Copyright (c) 2018 Waldemar Augustyn */

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

/* Data organization

    ea  - encoding address
    ip  - real ip address of a host
    gw  - geteway representing a local network (our or their)
    ref - reference assigned by related local network (our or their)

Conceptualy, every address record is a relation between four elements:

    (ea, ip, gw, ref)

In the meadow implementation of IPREF, where local network host addresses are
never aliased by encoding addresses, the quad can be decomposed into two
disjoined relations comprised of three elements:

    (ea,     gw, ref)     implemented with:      our_eas  their_gws:their_refs
    (    ip, gw, ref)     implemented with:      our_ips  our_gws:our_refs

These relations must be maintained across all Hash/BTree maps used in the
implementation.

    (ea,     gw, ref) relation:

        our_ea      ->      (their_gw, their_ref)
        their_gw    ->      their_ref   ->   our_ea

    (    ip, gw, ref) relation:

        our_ip      ->      (our_gw, our_ref)
        our_gw      ->      our_ref     ->   our_ip
*/

struct AddrRec {
    gw: Ipv4Addr,
    rff: u128, // we want 'ref' but it's reserved, 'rff' is pronounced 'ref'
    expire: u32,
}

pub struct Mapper {
    our_eas: Arc<Mutex<HashMap<Ipv4Addr, AddrRec>>>,
    our_ips: Arc<Mutex<HashMap<Ipv4Addr, AddrRec>>>,
    /*
    our_gws:   HashMap<Ipv4Addr, HashMap<u128, Ipv4Addr>>,
    their_gws: HashMap<Ipv4Addr, HashMap<u128, Ipv4Addr>>,
    */
    rec_zero: AddrRec,
}

impl Mapper {
    //
    pub fn new() -> Mapper {
        Mapper {
            our_eas: Arc::new(Mutex::new(HashMap::new())),
            our_ips: Arc::new(Mutex::new(HashMap::new())),
            rec_zero: AddrRec {
                gw: Ipv4Addr::new(0, 0, 0, 0),
                rff: 0,
                expire: 0,
            },
        }
    }

    pub fn get_their_ipref(&self, our_ea: Ipv4Addr) -> (Ipv4Addr, u128) {
        // our_ea -> their_gw + their_ref
        let eas = self.our_eas.lock().unwrap();
        let rec = eas.get(&our_ea).unwrap_or(&self.rec_zero);
        (rec.gw, rec.rff)
    }

    pub fn get_our_ipref(&self, our_ip: Ipv4Addr) -> (Ipv4Addr, u128) {
        // our_ip -> our_gw + our_ref
        let ips = self.our_ips.lock().unwrap();
        let rec = ips.get(&our_ip).unwrap_or(&self.rec_zero);
        (rec.gw, rec.rff)
    }
}

/*
pub fn get_our_ip(our_gw: Ipv4Addr, our_ref: u128) -> Ipv4Addr {
    // our_gw + our_ref -> our_ip
    Ipv4Addr::new(192, 168, 71, 135)
}

pub fn get_our_ea(their_gw: Ipv4Addr, their_ref: u128) -> Ipv4Addr {
    // their_gw + their_ref -> our_ea
    Ipv4Addr::new(10, 244, 4, 202)
}
*/
