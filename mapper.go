/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"time"
)

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

These relations must be maintained across all maps used in the implementation.

    (ea,     gw, ref) relation:

        our_ea      ->      (their_gw, their_ref)
        their_gw    ->      their_ref   ->   our_ea

    (    ip, gw, ref) relation:

        our_ip      ->      (our_gw, our_ref)
        our_gw      ->      our_ref     ->   our_ip

The result is four maps. These maps are read by forwarders for every packet. It
is important to make these reads efficient. Updates to the maps come at a far
slower pace, therefore efficiency of updates is not a factor.

In this design, forwarders have exclusive access to their related maps. There
is no locking. Updates to the maps are performed by the forwardes when prompted
by DNS watchers or timers.
*/

type Ref struct {
	h uint64
	l uint64
}

type IpRefRec struct {
	ip     uint32
	ref    Ref
	expire time.Duration
}

type IpRec struct {
	ip     uint32
	expire time.Duration
}

type IpToIpRef map[uint32]IpRefRec
type IpRefToIp map[uint32]map[Ref]IpRec

var their_ipref IpToIpRef
var our_ipref IpToIpRef
var our_ip IpRefToIp
var our_ea IpRefToIp