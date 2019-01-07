/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"crypto/rand"
	prng "math/rand" // we don't need crypto rng for time delays
	"time"
)

/* Markers and owner ids

Every mapper record has a marker and an owner id (oid) associated with it. An
oid is an arbitrary integer identifying the owner of the record.  A marker is
a time value which determines whether a record is active. Each marker has a
corresponding cur_mark value per each oid. A record is active if its mark is
not less than the related cur_mark.

Mapper records that are dynamically created by the forwarders expire after a set
amount of time. This is accomplished by incrementing cur_mark value as time
passes. In this way mark values of dynamic records eventually fall below the
cur_mark values. If a record is used in mapping, its expiration is extended,
ie. its mark is incremented. If a record is not used for an extened amount of
time, it expires.

Mapper records that are created by DNS agents also use mark values to determine
their status. Unlike dynamic mapper records, their curr_mark values are not
incremented with time but with successive updates. Each new update carries a new
mark value which is then set as the new curr_mark. In this way, old records are
immediately expired whenever a new set becomes available.

Expired records are collected by a purge timer. A purge timer periodically scans
mapper records and removes those whose mark is less than the related curr_mark
regardless of whether they are dynamic records created by forwarders or static
records created by DNS agents.
*/

const (
	TIMER_TICK = 16811          // [ms] avg  16.811 [s]
	TIMER_FUZZ = TIMER_TICK / 7 // [ms]       2.401 [s]

	ARP_TICK = TIMER_TICK / 3 // [ms] avg 5.603 [s]
	ARP_FUZZ = ARP_TICK / 7   // [ms] avg 0.800 [s]

	PURGE_TICK = TIMER_TICK / 11 // [ms] avg   1.528 [s]
	PURGE_FUZZ = PURGE_TICK / 7  // [ms]       0.218 [s]
	PURGE_NUM  = 17              // num of records to purge at a time
)

type Mark struct {
	base time.Time
}

var marker Mark

func (m *Mark) init() {

	// init prng for non-critical random number use

	creep := make([]byte, 4)
	_, err := rand.Read(creep)
	if err != nil {
		log.fatal("mark: cannot seed pseudo random number generator")
	}
	prng.Seed(int64(be.Uint32(creep)))

	// init marker making sure it's always > 0

	m.base = time.Now().Add(-time.Second)
}

func (m *Mark) now() M32 {

	return M32(time.Now().Sub(m.base) / time.Second)

}

func get_timer_packet(cmd byte, mark M32) *PktBuf {

	pb := <-getbuf

	pb.set_iphdr()
	pb.write_v1_header(cmd, mapper_oid, mark)

	pb.tail = pb.iphdr + V1_HDR_LEN

	return pb
}

func arp_tick() {

	for {
		time.Sleep(time.Duration(ARP_TICK-ARP_FUZZ/2+prng.Intn(ARP_FUZZ)) * time.Millisecond)

		mark := marker.now()
		pb := get_timer_packet(V1_SET_MARK, mark)
		send_gw <- pb
	}
}

func purge_tick() {

	for {
		time.Sleep(time.Duration(PURGE_TICK-PURGE_FUZZ/2+prng.Intn(PURGE_FUZZ)) * time.Millisecond)

		pb := get_timer_packet(V1_PURGE, 0)
		pbb := <-getbuf
		pbb.copy_from(pb)

		recv_gw <- pb
		recv_tun <- pbb
	}
}

func timer_tick() {

	for {
		time.Sleep(time.Duration(TIMER_TICK-TIMER_FUZZ/2+prng.Intn(TIMER_FUZZ)) * time.Millisecond)

		mark := marker.now() // the same mark for both timers

		pb := get_timer_packet(V1_SET_MARK, mark)
		pbb := <-getbuf
		pbb.copy_from(pb)

		recv_gw <- pb
		recv_tun <- pbb
	}
}
