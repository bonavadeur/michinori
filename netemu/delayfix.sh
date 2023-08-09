#!/bin/bash

delay=$(($1 / 2))"ms"

interface=vnet2
tc qdisc add dev $interface root handle 1: prio
tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.100 flowid 2:1
tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.101 flowid 2:1
tc qdisc add dev $interface parent 1:1 handle 2: netem delay $delay

interface=vnet0
tc qdisc add dev $interface root handle 1: prio
tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
tc qdisc add dev $interface parent 1:1 handle 2: netem delay $delay

interface=vnet1
tc qdisc add dev $interface root handle 1: prio
tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
tc qdisc add dev $interface parent 1:1 handle 2: netem delay $delay
