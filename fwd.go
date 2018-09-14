/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

/* Packet flow

               ╭──────────╮     ┏━━━━━━━━━━━━┓     ╭──────────╮
       ╭────▷──┤ recv_tun ├──▷──┨ fwd_to_gw  ┠──▷──┤ send_gw  ├──▷────╮
       │       ╰──────────╯     ┗━━━━━━━━━━━━┛     ╰──────────╯       │
    ┏━━┷━━┓                                                        ┏━━┷━━┓
 ─▷─┨ tun ┃                                                        ┃ gw  ┠─▷─
 ─◁─┨ ifc ┃                                                        ┃ ifc ┠─◁─
    ┗━━┯━━┛                                                        ┗━━┯━━┛
       │       ╭──────────╮     ┏━━━━━━━━━━━━┓     ╭──────────╮       │
       ╰────◁──┤ send_tun ├──◁──┨ fwd_to_tun ┠──◁──┤ recv_gw  ├──◁────╯
               ╰──────────╯     ┗━━━━━━━━━━━━┛     ╰──────────╯
*/

var be = binary.BigEndian

/* PktBuf helper functions */

func ip_proto(proto byte) string {

	switch proto {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	case ICMP:
		return "icmp"
	}
	return fmt.Sprintf("%v", proto)
}

func (pb *PktBuf) pp_pkt() (ss string) {

	// IP(udp)  192.168.84.97  192.168.84.98  len(60)  data/tail(0/60)
	// IPREF(udp)  192.168.84.97 + 8af2819566  192.168.84.98 + 31fba013c  len(60) data/tail(48/158)
	// V1 SET_MARK(1)  mapper(1)  mark(12342)  data/tail(12/68)
	// PKT 0532ab04 data/tail(18/20)

	pkt := pb.pkt[pb.data:] // note: for debug it's from data to end (not from data to tail)

	// data too far into the buffer

	if len(pkt) < MIN_PKT_LEN {

		ss = fmt.Sprintf("PKT  short  data/tail(%v/%v)", pb.data, pb.tail)
		return
	}

	reflen := pb.reflen(pb.data)

	// IPREF packet

	if reflen != 0 {

		var sref Ref
		var dref Ref

		udp := int(pkt[IP_VER]&0xf) * 4
		encap := udp + 8
		opt := encap + 4

		if reflen == IPREF_OPT128_LEN {
			sref.h = be.Uint64(pkt[opt+OPT_SREF128 : opt+OPT_SREF128+8])
			sref.l = be.Uint64(pkt[opt+OPT_SREF128+8 : opt+OPT_SREF128+8+8])
			dref.h = be.Uint64(pkt[opt+OPT_DREF128 : opt+OPT_DREF128+8])
			dref.l = be.Uint64(pkt[opt+OPT_DREF128+8 : opt+OPT_DREF128+8+8])
		} else if reflen == IPREF_OPT64_LEN {
			sref.h = 0
			sref.l = be.Uint64(pkt[opt+OPT_SREF64 : opt+OPT_SREF64+8])
			dref.h = 0
			dref.l = be.Uint64(pkt[opt+OPT_DREF64 : opt+OPT_DREF64+8])
		}

		ss = fmt.Sprintf("IPREF(%v)  %v + %v  %v + %v  len(%v)  data/tail(%v/%v)",
			ip_proto(pkt[encap+ENCAP_PROTO]),
			net.IP(pkt[IP_SRC:IP_SRC+4]),
			&sref,
			net.IP(pkt[IP_DST:IP_DST+4]),
			&dref,
			be.Uint16(pkt[IP_LEN:IP_LEN+2]),
			pb.data, pb.tail)

		return
	}

	// IP packet

	if pkt[IP_VER]&0xf0 == 0x40 && len(pkt) >= 20 {

		ss = fmt.Sprintf("IP(%v)  %v  %v  len(%v)  data/tail(%v/%v)",
			ip_proto(pkt[IP_PROTO]),
			net.IP(pkt[IP_SRC:IP_SRC+4]),
			net.IP(pkt[IP_DST:IP_DST+4]),
			be.Uint16(pkt[IP_LEN:IP_LEN+2]),
			pb.data, pb.tail)

		return
	}

	// V1 packet

	if pkt[V1_VER] == V1_SIG && len(pkt) >= V1_HDR_LEN {

		ss = "V1"

		cmd := pkt[V1_CMD]
		switch cmd {
		case V1_SET_AREC:
			ss += fmt.Sprintf(" SET_AREC(%v)", cmd)
		case V1_SET_MARK:
			ss += fmt.Sprintf(" SET_MARK(%v)", cmd)
		case V1_SET_SOFT:
			ss += fmt.Sprintf(" SET_SOFT(%v)", cmd)
		case V1_PURGE:
			ss += fmt.Sprintf(" PURGE(%v)", cmd)
		default:
			ss += fmt.Sprintf(" cmd(%v)", cmd)
		}

		oid := O32(be.Uint32(pkt[V1_OID : V1_OID+4]))
		mark := M32(be.Uint32(pkt[V1_MARK : V1_MARK+4]))
		ss += fmt.Sprintf("  %v(%v)  mark(%v)  data/tail(%v/%v)",
			owners.name(oid), oid, mark, pb.data, pb.tail)

		return
	}

	// unknown or invalid packet

	ss = fmt.Sprintf("PKT  %08x  data/tail(%v/%v)", be.Uint32(pkt[0:4]), pb.data, pb.tail)

	return
}

func (pb *PktBuf) pp_raw(pfx string) {

	// RAW  45 00 00 74 2e 52 40 00 40 11 d0 b6 0a fb 1b 6f c0 a8 54 5e 04 15 04 15 00 ..

	const max = 128
	var sb strings.Builder

	pkt := pb.pkt[pb.data:pb.tail]
	sb.WriteString(pfx)
	sb.WriteString("RAW ")
	for ii := 0; ii < len(pkt); ii++ {
		if ii < max {
			sb.WriteString(" ")
			sb.WriteString(hex.EncodeToString(pkt[ii : ii+1]))
		} else {
			sb.WriteString("  ..")
			break
		}
	}
	log.trace(sb.String())
}

func (pb *PktBuf) pp_net(pfx string) {

	// IP(udp) 4500  192.168.84.93  10.254.22.202  len(64) id(1) ttl(64) csum:0000
	// IPREF(udp) 4500  192.168.84.93 + 8af2819566  10.254.22.202 + 31fba013c  len(64) id(1) ttl(64) csum:0000

	pkt := pb.pkt[pb.iphdr:pb.tail]

	// Non-IP

	if (len(pkt) < 20) || (pkt[IP_VER]&0xf0 != 0x40) || (len(pkt) < int(pkt[IP_VER]&0xf)*4) {
		log.trace(pfx + pb.pp_pkt())
		return
	}

	reflen := pb.reflen(pb.iphdr)

	// IPREF

	if reflen == IPREF_OPT128_LEN || reflen == IPREF_OPT64_LEN {

		var sref Ref
		var dref Ref

		udp := int(pkt[IP_VER]&0xf) * 4
		encap := udp + 8
		opt := encap + 4

		if reflen == IPREF_OPT128_LEN {
			sref.h = be.Uint64(pkt[opt+OPT_SREF128 : opt+OPT_SREF128+8])
			sref.l = be.Uint64(pkt[opt+OPT_SREF128+8 : opt+OPT_SREF128+8+8])
			dref.h = be.Uint64(pkt[opt+OPT_DREF128 : opt+OPT_DREF128+8])
			dref.l = be.Uint64(pkt[opt+OPT_DREF128+8 : opt+OPT_DREF128+8+8])
		} else if reflen == IPREF_OPT64_LEN {
			sref.h = 0
			sref.l = be.Uint64(pkt[opt+OPT_SREF64 : opt+OPT_SREF64+8])
			dref.h = 0
			dref.l = be.Uint64(pkt[opt+OPT_DREF64 : opt+OPT_DREF64+8])
		}

		log.trace("%vIPREF(%v)  %v + %v  %v + %v  len(%v) id(%v) ttl(%v) csum: %04x",
			pfx,
			ip_proto(pkt[encap+ENCAP_PROTO]),
			IP32(be.Uint32(pkt[IP_SRC:IP_SRC+4])),
			&sref,
			IP32(be.Uint32(pkt[IP_DST:IP_DST+4])),
			&dref,
			be.Uint16(pkt[IP_LEN:IP_LEN+2]),
			be.Uint16(pkt[IP_ID:IP_ID+2]),
			pkt[IP_TTL],
			be.Uint16(pkt[IP_CSUM:IP_CSUM+2]))

		return
	}

	// IP

	log.trace("%vIP(%v)  %v  %v  len(%v) id(%v) ttl(%v) csum: %04x",
		pfx,
		ip_proto(pkt[IP_PROTO]),
		IP32(be.Uint32(pkt[IP_SRC:IP_SRC+4])),
		IP32(be.Uint32(pkt[IP_DST:IP_DST+4])),
		be.Uint16(pkt[IP_LEN:IP_LEN+2]),
		be.Uint16(pkt[IP_ID:IP_ID+2]),
		pkt[IP_TTL],
		be.Uint16(pkt[IP_CSUM:IP_CSUM+2]))
}

func (pb *PktBuf) pp_tran(pfx string) {

	pkt := pb.pkt[pb.iphdr:pb.tail]

	// Non-IP

	if (len(pkt) < 20) || (pkt[IP_VER]&0xf0 != 0x40) || (len(pkt) < int(pkt[IP_VER]&0xf)*4) {
		return
	}

	l4 := int(pkt[IP_VER]&0xf) * 4
	reflen := pb.reflen(pb.iphdr)
	if reflen != 0 {
		l4 += 8 + 4 + reflen
	}

	switch pkt[IP_PROTO] {
	case TCP:
	case UDP:

		// UDP  1045  1045  len(96) csum 0

		if len(pkt) < l4+8 {
			return
		}
		log.trace("%vUDP  %v  %v  len(%v) csum: %04x",
			pfx,
			be.Uint16(pkt[l4+UDP_SPORT:l4+UDP_SPORT+2]),
			be.Uint16(pkt[l4+UDP_DPORT:l4+UDP_DPORT+2]),
			be.Uint16(pkt[l4+UDP_LEN:l4+UDP_LEN+2]),
			be.Uint16(pkt[l4+UDP_CSUM:l4+UDP_CSUM+2]))

	case ICMP:
	}
}

func insert_ipref_option(pb *PktBuf) int {

	pkt := pb.pkt

	if (be.Uint16(pkt[pb.iphdr+IP_FRAG:pb.iphdr+IP_FRAG+2]) & 0x1fff) != 0 {
		log.debug("inserting opt: pkt is a fragment, dropping")
		return DROP
	}

	src := IP32(be.Uint32(pkt[pb.iphdr+IP_SRC : pb.iphdr+IP_SRC+4]))
	dst := IP32(be.Uint32(pkt[pb.iphdr+IP_DST : pb.iphdr+IP_DST+4]))

	iprefdst := map_gw.get_dst_ipref(dst)
	if iprefdst.ip == 0 {
		log.err("inserting opt: unknown dst address: %v %v , sending icmp", src, dst)
		pb.icmp.typ = ICMP_DEST_UNREACH
		pb.icmp.code = ICMP_NET_UNREACH
		pb.icmp.mtu = 0
		icmpreq <- pb
		return STOLEN
	}

	iprefsrc := map_gw.get_src_ipref(src)
	if iprefsrc.ip == 0 {
		log.err("inserting opt: unknown src address: %v %v , dropping", src, dst)
		return DROP // couldn't get src ipref for some reason
	}

	// get soft state

	soft, ok := map_gw.soft[iprefdst.ip]
	if !ok {
		soft.init(iprefdst.ip) // missing soft state, use defaults
	}

	// insert option

	if pb.iphdr < OPTLEN {
		log.err("inserting opt: no space for ipref option, dropping")
		return DROP
	}

	var csum uint16
	var optlen int

	iphdrlen := pb.iphdr_len()

	if iprefsrc.ref.h == 0 && iprefdst.ref.h == 0 {
		pb.data = pb.iphdr - OPTLEN + 16 // both refs 64 bit
		optlen = IPREF_OPT64_LEN
	} else {
		pb.data = pb.iphdr - OPTLEN // at least one 128 bit ref
		optlen = IPREF_OPT128_LEN
	}

	copy(pkt[pb.data:pb.data+iphdrlen], pkt[pb.iphdr:pb.iphdr+iphdrlen])
	pb.set_iphdr()

	udp := pb.iphdr + iphdrlen
	be.PutUint16(pkt[udp+UDP_SPORT:udp+UDP_SPORT+2], soft.port)
	be.PutUint16(pkt[udp+UDP_DPORT:udp+UDP_DPORT+2], IPREF_PORT)
	be.PutUint16(pkt[udp+UDP_LEN:udp+UDP_LEN+2], uint16(pb.tail-udp))
	be.PutUint16(pkt[udp+UDP_CSUM:udp+UDP_CSUM+2], 0)

	encap := udp + 8
	pkt[encap+ENCAP_TTL] = pkt[pb.iphdr+8]
	pkt[encap+ENCAP_PROTO] = pkt[pb.iphdr+IP_PROTO]
	pkt[encap+ENCAP_HOPS] = soft.hops
	pkt[encap+ENCAP_RSVD] = 0

	opt := encap + 4
	pkt[opt+OPT_OPT] = IPREF_OPT
	pkt[opt+OPT_LEN] = byte(optlen)
	if optlen == IPREF_OPT128_LEN {
		be.PutUint64(pkt[opt+OPT_SREF128:opt+OPT_SREF128+8], iprefsrc.ref.h)
		be.PutUint64(pkt[opt+OPT_SREF128+8:opt+OPT_SREF128+16], iprefsrc.ref.l)
		be.PutUint64(pkt[opt+OPT_DREF128:opt+OPT_DREF128+8], iprefdst.ref.h)
		be.PutUint64(pkt[opt+OPT_DREF128+8:opt+OPT_DREF128+16], iprefdst.ref.l)
	} else {
		be.PutUint64(pkt[opt+OPT_SREF64:opt+OPT_SREF64+8], iprefsrc.ref.l)
		be.PutUint64(pkt[opt+OPT_DREF64:opt+OPT_DREF64+8], iprefdst.ref.l)
	}

	// adjust layer 4 headers

	l4 := opt + optlen

	switch pkt[encap+ENCAP_PROTO] {

	case TCP: // subtract ip src/dst addresses from csum

		csum = be.Uint16(pkt[l4+TCP_CSUM : l4+TCP_CSUM+2])

		if csum != 0 {
			csum = csum_subtract(csum^0xffff, pkt[pb.iphdr+IP_SRC:pb.iphdr+IP_DST+4])
			be.PutUint16(pkt[l4+TCP_CSUM:l4+TCP_CSUM+2], csum^0xffff)
		}

	case UDP: // subtract ip src/dst addresses from csum

		csum = be.Uint16(pkt[l4+UDP_CSUM : l4+UDP_CSUM+2])

		if csum != 0 {
			csum = csum_subtract(csum^0xffff, pkt[pb.iphdr+IP_SRC:pb.iphdr+IP_DST+4])
			be.PutUint16(pkt[l4+UDP_CSUM:l4+UDP_CSUM+2], csum^0xffff)
		}

	case ICMP: // replace inner ip addresses with their ipref equivalents

		if pkt[l4+ICMP_TYPE] != ICMP_DEST_UNREACH &&
			pkt[l4+ICMP_TYPE] != ICMP_TIME_EXCEEDED &&
			pkt[l4+ICMP_TYPE] != ICMP_REDIRECT &&
			pkt[l4+ICMP_TYPE] != ICMP_SOURCE_QUENCH {
			break
		}

		inner := l4 + ICMP_DATA

		inner_src := IP32(be.Uint32(pkt[inner+IP_SRC : inner+IP_SRC+4]))
		inner_dst := IP32(be.Uint32(pkt[inner+IP_DST : inner+IP_DST+4]))

		if (pkt[inner+IP_VER] & 0x0f) != 5 {
			log.err("inserting opt: icmp inner header has options  %v  %v, leaving as is", src, dst)
			break
		}

		inner_dstipref := map_gw.get_dst_ipref(inner_src)

		if inner_dstipref.ip == 0 {
			log.err("inserting opt:  cannot find ipref addr for icmp inner src %v  %v, leaving as is", src, dst)
			break
		}

		inner_srcipref := map_gw.get_src_ipref(inner_dst)

		if inner_srcipref.ip == 0 {
			log.err("inserting opt:  cannot find ipref addr for icmp inner dst %v  %v, leaving as is", src, dst)
			break
		}

		var inner_optlen int

		if inner_srcipref.ref.h == 0 && inner_dstipref.ref.h == 0 {
			inner_optlen = IPREF_OPT64_LEN
		} else {
			inner_optlen = IPREF_OPT128_LEN
		}

		if len(pkt)-pb.tail < inner_optlen {
			log.err("inserting opt:  not enough room to expand inner header %v  %v, leaving as is", src, dst)
			break
		}

		// insert inner ipref option

		inner_opt := inner + 5*4

		copy(pkt[inner_opt+inner_optlen:], pkt[inner_opt:pb.tail])
		pb.tail += inner_optlen

		pkt[inner_opt+OPT_OPT] = IPREF_OPT
		pkt[inner_opt+OPT_LEN] = byte(inner_optlen)
		be.PutUint16(pkt[inner_opt+OPT_RSVD:inner_opt+OPT_RSVD+2], 0)
		if inner_optlen == IPREF_OPT128_LEN {
			be.PutUint64(pkt[inner_opt+OPT_SREF128:inner_opt+OPT_SREF128+8], inner_srcipref.ref.h)
			be.PutUint64(pkt[inner_opt+OPT_SREF128+8:inner_opt+OPT_SREF128+16], inner_srcipref.ref.l)
			be.PutUint64(pkt[inner_opt+OPT_DREF128:inner_opt+OPT_DREF128+8], inner_dstipref.ref.h)
			be.PutUint64(pkt[inner_opt+OPT_DREF128+8:inner_opt+OPT_DREF128+16], inner_dstipref.ref.l)
		} else {
			be.PutUint64(pkt[inner_opt+OPT_SREF64:inner_opt+OPT_SREF64+8], inner_srcipref.ref.l)
			be.PutUint64(pkt[inner_opt+OPT_DREF64:inner_opt+OPT_DREF64+8], inner_dstipref.ref.l)
		}

		// adjust csum, in calculations ignore option because it will be removed

		var inner_csum uint16

		inner_csum = be.Uint16(pkt[inner+IP_CSUM:inner+IP_CSUM+2]) ^ 0xffff
		inner_csum = csum_subtract(inner_csum, pkt[inner+IP_VER:inner+IP_VER+2])
		inner_csum = csum_subtract(inner_csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		csum = be.Uint16(pkt[l4+ICMP_CSUM:l4+ICMP_CSUM+2]) ^ 0xffff
		csum = csum_subtract(csum, pkt[inner+IP_VER:inner+IP_VER+2])
		csum = csum_subtract(csum, pkt[inner+IP_CSUM:inner+IP_CSUM+2])
		csum = csum_subtract(csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		pkt[inner+IP_VER] += byte(inner_optlen / 4)
		be.PutUint32(pkt[inner+IP_SRC:inner+IP_SRC+4], uint32(inner_srcipref.ip))
		be.PutUint32(pkt[inner+IP_DST:inner+IP_DST+4], uint32(inner_dstipref.ip))
		inner_csum = csum_add(inner_csum, pkt[inner+IP_VER:inner+IP_VER+2])
		inner_csum = csum_add(inner_csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		be.PutUint16(pkt[inner+IP_CSUM:inner+IP_CSUM+2], inner_csum^0xffff)

		csum = csum_add(csum, pkt[inner+IP_VER:inner+IP_VER+2])
		csum = csum_add(csum, pkt[inner+IP_CSUM:inner+IP_CSUM+2])
		csum = csum_add(csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		be.PutUint16(pkt[l4+ICMP_CSUM:l4+ICMP_CSUM+2], csum^0xffff)
	}

	// adjust ip header

	be.PutUint16(pkt[pb.iphdr+IP_LEN:pb.iphdr+IP_LEN+2], uint16(pb.len()))
	pkt[pb.iphdr+IP_PROTO] = UDP
	be.PutUint16(pkt[pb.iphdr+IP_CSUM:pb.iphdr+IP_CSUM+2], 0)
	be.PutUint32(pkt[pb.iphdr+IP_SRC:pb.iphdr+IP_SRC+4], uint32(iprefsrc.ip))
	be.PutUint32(pkt[pb.iphdr+IP_DST:pb.iphdr+IP_DST+4], uint32(iprefdst.ip))

	csum = csum_add(0, pkt[pb.iphdr:pb.iphdr+iphdrlen])
	be.PutUint16(pkt[pb.iphdr+IP_CSUM:pb.iphdr+IP_CSUM+2], csum^0xffff)

	if cli.debug["fwd"] || cli.debug["all"] {
		log.debug("inserting opt: %v", pb.pp_pkt())
	}

	return ACCEPT
}

func remove_ipref_option(pb *PktBuf) int {

	pkt := pb.pkt[pb.iphdr:pb.tail]
	reflen := pb.reflen(pb.iphdr)

	if reflen == 0 {
		log.err("removing opt:  not an ipref packet, dropping")
		return DROP
	}

	// map addresses

	var sref Ref
	var dref Ref

	udp := pb.iphdr_len()
	encap := udp + 8
	opt := encap + 4

	src := IP32(be.Uint32(pkt[IP_SRC : IP_SRC+4]))
	dst := IP32(be.Uint32(pkt[IP_DST : IP_DST+4]))

	if reflen == IPREF_OPT128_LEN {
		sref.h = be.Uint64(pkt[opt+OPT_SREF128 : opt+OPT_SREF128+8])
		sref.l = be.Uint64(pkt[opt+OPT_SREF128+8 : opt+OPT_SREF128+8+8])
		dref.h = be.Uint64(pkt[opt+OPT_DREF128 : opt+OPT_DREF128+8])
		dref.l = be.Uint64(pkt[opt+OPT_DREF128+8 : opt+OPT_DREF128+8+8])
	} else if reflen == IPREF_OPT64_LEN {
		sref.h = 0
		sref.l = be.Uint64(pkt[opt+OPT_SREF64 : opt+OPT_SREF64+8])
		dref.h = 0
		dref.l = be.Uint64(pkt[opt+OPT_DREF64 : opt+OPT_DREF64+8])
	} else {
		log.err("removing opt: invalid ipref option length: %v, dropping", reflen)
		return DROP
	}

	dst_ip := map_tun.get_dst_ip(dst, dref)
	if dst_ip == 0 {
		log.err("removing opt:  unknown local destination  %v + %v  %v + %v, dropping",
			src, &sref, dst, &dref)
		return DROP // drop silently
	}

	src_ea := map_tun.get_src_ea(src, sref)
	if src_ea == 0 {
		log.err("removing opt:  unknown src ipref address  %v + %v  %v + %v, dropping",
			src, &sref, dst, &dref)
		return DROP // couldn't assign ea for some reason
	}

	// update soft state and tell the other forwarder if changed

	soft, ok := map_tun.soft[src]
	if !ok {
		soft.init(src)
		soft.port = 0 // force change
	}

	if soft.gw != src {
		log.err("removing opt:  soft record gw %v does not match src %v, resetting", soft.gw, src)
		soft.init(src)
		soft.port = 0 // force change
	}

	if soft.ttl != pkt[encap+ENCAP_HOPS] ||
		soft.hops != pkt[encap+ENCAP_TTL] ||
		soft.port != be.Uint16(pkt[udp+UDP_SPORT:udp+UDP_SPORT+2]) {

		soft.ttl = pkt[encap+ENCAP_HOPS]
		soft.hops = pkt[encap+ENCAP_TTL]
		soft.port = be.Uint16(pkt[udp+UDP_SPORT : udp+UDP_SPORT+2])

		map_tun.set_soft(src, soft)
	}

	// adjust ip header

	pktlen := be.Uint16(pkt[IP_LEN : IP_LEN+2])
	pktlen -= 8 + 4 + uint16(reflen)

	be.PutUint16(pkt[IP_LEN:IP_LEN+2], pktlen)
	pkt[IP_PROTO] = pkt[encap+ENCAP_PROTO]
	be.PutUint32(pkt[IP_SRC:IP_SRC+4], uint32(src_ea))
	be.PutUint32(pkt[IP_DST:IP_DST+4], uint32(dst_ip))

	// strip option

	iphdrlen := pb.iphdr_len()
	pb.iphdr += 8 + 4 + reflen // udp header + encap + opt
	copy(pb.pkt[pb.iphdr:pb.iphdr+iphdrlen], pb.pkt[pb.data:pb.data+iphdrlen])
	pb.data = pb.iphdr

	// adjust layer 4 headers

	pkt = pb.pkt[pb.iphdr:pb.tail]
	l4 := pb.iphdr_len()

	var csum uint16

	switch pkt[IP_PROTO] {

	case TCP: // add ip src/dst addresses to csum

		csum = be.Uint16(pkt[l4+TCP_CSUM : l4+TCP_CSUM+2])

		if csum != 0 {
			csum = csum_add(csum^0xffff, pkt[IP_SRC:IP_DST+4])
			be.PutUint16(pkt[l4+TCP_CSUM:l4+TCP_CSUM+2], csum^0xffff)
		}

	case UDP: // add ip src/dst addresses to csum

		csum = be.Uint16(pkt[l4+UDP_CSUM : l4+UDP_CSUM+2])

		if csum != 0 {
			csum = csum_add(csum^0xffff, pkt[IP_SRC:IP_DST+4])
			be.PutUint16(pkt[l4+UDP_CSUM:l4+UDP_CSUM+2], csum^0xffff)
		}

	case ICMP: // replace inner ipref addresses with their ea/ip equivalents

		if pkt[l4+ICMP_TYPE] != ICMP_DEST_UNREACH &&
			pkt[l4+ICMP_TYPE] != ICMP_TIME_EXCEEDED &&
			pkt[l4+ICMP_TYPE] != ICMP_REDIRECT &&
			pkt[l4+ICMP_TYPE] != ICMP_SOURCE_QUENCH {
			break
		}

		inner := l4 + ICMP_DATA

		if (pkt[inner+IP_VER] & 0x0f) == 5 {
			log.err("removing opt: icmp inner header has no options  %v %v, leaving as is", src, dst)
			break
		}

		inner_opt := inner + 5*4

		if pkt[inner_opt+OPT_OPT] != IPREF_OPT {
			log.err("removing opt: icmp inner header option is not ipref  %v %v, leaving as is", src, dst)
			break
		}

		var inner_srcipref IpRefRec
		var inner_dstipref IpRefRec

		inner_srcipref.ip = IP32(be.Uint32(pkt[inner+IP_SRC : inner+IP_SRC+4]))
		inner_dstipref.ip = IP32(be.Uint32(pkt[inner+IP_DST : inner+IP_DST+4]))

		inner_optlen := int(pkt[inner_opt+OPT_LEN])

		if inner_optlen == IPREF_OPT128_LEN {
			inner_srcipref.ref.h = be.Uint64(pkt[inner_opt+OPT_SREF128 : inner_opt+OPT_SREF128+8])
			inner_srcipref.ref.l = be.Uint64(pkt[inner_opt+OPT_SREF128+8 : inner_opt+OPT_SREF128+16])
			inner_dstipref.ref.h = be.Uint64(pkt[inner_opt+OPT_DREF128 : inner_opt+OPT_DREF128+8])
			inner_dstipref.ref.l = be.Uint64(pkt[inner_opt+OPT_DREF128+8 : inner_opt+OPT_DREF128+16])
		} else if inner_optlen == IPREF_OPT64_LEN {
			inner_srcipref.ref.h = 0
			inner_srcipref.ref.l = be.Uint64(pkt[inner_opt+OPT_SREF64 : inner_opt+OPT_SREF64+8])
			inner_dstipref.ref.h = 0
			inner_dstipref.ref.l = be.Uint64(pkt[inner_opt+OPT_DREF64 : inner_opt+OPT_DREF64+8])
		} else {
			log.err("removing opt: invalid inner ipref option length: %v, dropping", inner_optlen)
			return DROP
		}

		// remove inner ipref option

		copy(pkt[inner:], pkt[inner_opt+inner_optlen:])
		pb.tail -= inner_optlen
		pkt = pb.pkt[pb.iphdr:pb.tail]

		// get addresses

		inner_dst := map_tun.get_src_ea(inner_srcipref.ip, inner_srcipref.ref)
		if inner_dst == 0 {
			log.err("removing opt: cannot find ea for icmp inner src ipref: %v + %v, leaving as is",
				inner_srcipref.ip, &inner_srcipref.ref)
			break
		}
		inner_src := map_tun.get_dst_ip(inner_dstipref.ip, inner_dstipref.ref)
		if inner_src == 0 {
			log.err("removing opt: cannot find ip for icmp inner dst ipref: %v + %v, leaving as is",
				inner_dstipref.ip, &inner_dstipref.ref)
			break
		}

		// adjust csum

		var inner_csum uint16

		inner_csum = be.Uint16(pkt[inner+IP_CSUM:inner+IP_CSUM+2]) ^ 0xffff
		inner_csum = csum_subtract(inner_csum, pkt[inner+IP_VER:inner+IP_VER+2])
		inner_csum = csum_subtract(inner_csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		csum = be.Uint16(pkt[l4+ICMP_CSUM:l4+ICMP_CSUM+2]) ^ 0xffff
		csum = csum_subtract(csum, pkt[inner+IP_VER:inner+IP_VER+2])
		csum = csum_subtract(csum, pkt[inner+IP_CSUM:inner+IP_CSUM+2])
		csum = csum_subtract(csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		pkt[inner+IP_VER] -= byte(inner_optlen / 4)
		be.PutUint32(pkt[inner+IP_SRC:inner+IP_SRC+4], uint32(inner_src))
		be.PutUint32(pkt[inner+IP_DST:inner+IP_DST+4], uint32(inner_dst))
		inner_csum = csum_add(inner_csum, pkt[inner+IP_VER:inner+IP_VER+2])
		inner_csum = csum_add(inner_csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		be.PutUint16(pkt[inner+IP_CSUM:inner+IP_CSUM+2], inner_csum^0xffff)

		csum = csum_add(csum, pkt[inner+IP_VER:inner+IP_VER+2])
		csum = csum_add(csum, pkt[inner+IP_CSUM:inner+IP_CSUM+2])
		csum = csum_add(csum, pkt[inner+IP_SRC:inner+IP_DST+4])

		be.PutUint16(pkt[l4+ICMP_CSUM:l4+ICMP_CSUM+2], csum^0xffff)
	}

	// adjust ip header csum

	be.PutUint16(pkt[IP_CSUM:IP_CSUM+2], 0)
	csum = csum_add(0, pkt[:iphdrlen])
	be.PutUint16(pkt[IP_CSUM:IP_CSUM+2], csum^0xffff)

	if cli.debug["fwd"] || cli.debug["all"] {
		log.debug("removing opt:  %v", pb.pp_pkt())
	}

	return ACCEPT
}

func fwd_to_gw() {

	for pb := range recv_tun {

		if cli.debug["fwd"] || cli.debug["all"] {
			log.debug("fwd_to_gw  in: %v", pb.pp_pkt())
		}

		verdict := DROP

		switch {

		case pb.pkt[pb.data]&0xf0 == 0x40:

			pb.set_iphdr()
			verdict = insert_ipref_option(pb)
			if verdict == ACCEPT {
				send_gw <- pb
			}

		case pb.pkt[pb.data] == V1_SIG:

			pb.set_v1hdr()
			switch pb.pkt[pb.v1hdr+V1_CMD] {
			case V1_SET_AREC:
				verdict = map_gw.set_new_address_records(pb)
			case V1_SET_MARK:
				verdict = map_gw.set_new_mark(pb)
			case V1_SET_SOFT:
				verdict = map_gw.update_soft(pb)
			case V1_PURGE:
				verdict = map_gw.timer(pb)
			default:
				log.err("fwd_to_gw: unknown address records command: %v, ignoring", pb.pkt[pb.v1hdr+V1_CMD])
			}

		default:
			log.err("fwd_to_gw: unknown packet signature: 0x%02x, dropping", pb.pkt[pb.data])
		}

		if verdict == DROP {
			retbuf <- pb
		}
	}
}

func fwd_to_tun() {

	for pb := range recv_gw {

		if cli.debug["fwd"] || cli.debug["all"] {
			log.debug("fwd_to_tun in: %v", pb.pp_pkt())
		}

		verdict := DROP

		switch {

		case len(pb.pkt)-pb.data < MIN_PKT_LEN:

			log.err("fwd_to_tun in: short packet data/end(%v/%v), dropping", pb.data, len(pb.pkt))

		case pb.pkt[pb.data]&0xf0 == 0x40:

			verdict = remove_ipref_option(pb)
			if verdict == ACCEPT {
				send_tun <- pb
			}

		case pb.pkt[pb.data] == V1_SIG:

			pb.set_v1hdr()
			switch pb.pkt[pb.v1hdr+V1_CMD] {
			case V1_SET_AREC:
				verdict = map_tun.set_new_address_records(pb)
			case V1_SET_MARK:
				verdict = map_tun.set_new_mark(pb)
			case V1_PURGE:
				verdict = map_tun.timer(pb)
			default:
				log.err("fwd_to_tun: unknown address records command: %v, ignoring", pb.pkt[pb.v1hdr+V1_CMD])
			}

		default:
			log.err("fwd_to_tun: unknown packet signature: 0x%02x, dropping", pb.pkt[pb.data])
		}

		if verdict == DROP {
			retbuf <- pb
		}
	}
}
