#!/bin/bash

delay=$(($2 / 2))"ms"
jitter=$(($3 * 1000 / 1414))"ms"
bandwidth=$1"mbit"


# delay=$2"ms"
# jitter=$3"ms"
burst=$(($1 * 1000 / 250))"kb"
# burst=$burst"Kb"

# It's worked but i dont know .__.
interface=vnet2
tc qdisc add dev $interface root handle 1: htb default 30
tc class add dev $interface parent 1: classid 1:1 htb rate $bandwidth
tc qdisc add dev $interface parent 1:1 handle 10: netem delay $delay $jitter
# tc qdisc add dev $interface parent 10:1 handle 20: tbf rate $bandwidth burst $burst latency $jitter
tc filter add dev $interface parent 1: protocol all prio 1 u32 match u32 0 0 flowid 1:1

interface=vnet0
tc qdisc add dev $interface root handle 1: htb default 30
tc class add dev $interface parent 1: classid 1:1 htb rate $bandwidth
tc qdisc add dev $interface parent 1:1 handle 10: netem delay $delay $jitter
# tc qdisc add dev $interface parent 10:1 handle 20: tbf rate $bandwidth burst $burst latency $jitter
tc filter add dev $interface parent 1: protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 1:1

interface=vnet1
tc qdisc add dev $interface root handle 1: htb default 30
tc class add dev $interface parent 1: classid 1:1 htb rate $bandwidth
tc qdisc add dev $interface parent 1:1 handle 10: netem delay $delay $jitter
# tc qdisc add dev $interface parent 10:1 handle 20: tbf rate $bandwidth burst $burst latency $jitter
tc filter add dev $interface parent 1: protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 1:1



sleep 1
bandwidth=20"mbit"
tc class change dev vnet2 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet0 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet1 parent 1: classid 1:1 htb rate $bandwidth
echo "changed"

sleep 1
bandwidth=14"mbit"
tc class change dev vnet2 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet0 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet1 parent 1: classid 1:1 htb rate $bandwidth
echo "changed"

sleep 1
bandwidth=34"mbit"
tc class change dev vnet2 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet0 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet1 parent 1: classid 1:1 htb rate $bandwidth
echo "changed"

sleep 1
bandwidth=14"mbit"
tc class change dev vnet2 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet0 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet1 parent 1: classid 1:1 htb rate $bandwidth
echo "changed"

sleep 1
bandwidth=65"mbit"
tc class change dev vnet2 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet0 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet1 parent 1: classid 1:1 htb rate $bandwidth
echo "changed"

sleep 1
bandwidth=12"mbit"
tc class change dev vnet2 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet0 parent 1: classid 1:1 htb rate $bandwidth
tc class change dev vnet1 parent 1: classid 1:1 htb rate $bandwidth
echo "changed"









# testing
# interface=vnet2
# tc qdisc add dev $interface root handle 1: htb default 30
# tc qdisc add dev $interface parent 1:1 handle 10: netem delay 25ms 5ms distribution normal
# tc class add dev $interface parent 1: classid 1:1 htb rate 40mbit burst 15k

# tc class add dev $interface parent 1:1 classid 1:10 htb rate 20mbit ceil 40mbit burst 15k
# tc class add dev $interface parent 1:1 classid 1:20 htb rate 20mbit ceil 40mbit burst 15k

# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip dst 192.168.122.100 flowid 1:10
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.100 flowid 1:10
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip dst 192.168.122.101 flowid 1:20
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.101 flowid 1:20

# interface=vnet0
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
# tc qdisc add dev $interface parent 1:1 handle 10: tbf rate $bandwidth burst 2Mb latency $jitter

# interface=vnet1
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
# tc qdisc add dev $interface parent 1:1 handle 10: tbf rate $bandwidth burst 2Mb latency $jitter






# in no traffic, latency = 0
# interface=vnet2
# tc qdisc add dev $interface root handle 1: htb default 30
# tc qdisc add dev $interface parent 2: netem delay $delay $jitter distribution normal
# tc class add dev $interface parent 1: classid 1:1 htb rate 40mbit burst 15k

# tc class add dev $interface parent 1:1 classid 1:10 htb rate 20mbit ceil 40mbit burst 15k
# tc class add dev $interface parent 1:1 classid 1:20 htb rate 20mbit ceil 40mbit burst 15k

# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip dst 192.168.122.100 flowid 1:10
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.100 flowid 1:10
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip dst 192.168.122.101 flowid 1:20
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.101 flowid 1:20

# interface=vnet0
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
# tc qdisc add dev $interface parent 1:1 handle 10: tbf rate $bandwidth burst 2Mb latency $jitter

# interface=vnet1
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
# tc qdisc add dev $interface parent 1:1 handle 10: tbf rate $bandwidth burst 2Mb latency $jitter





# worked, but from 3 to 1
# delay=$2"ms"
# jitter=$3"ms"
# interface=vnet2
# tc qdisc add dev $interface root handle 1: netem delay $delay $jitter distribution normal
# tc qdisc add dev $interface parent 1: handle 10: tbf rate $bandwidth burst 100Kb latency $jitter

# interface=vnet0
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1: protocol ip prio 1 u32 match ip dst 192.168.122.102 flowid 1:1
# tc qdisc add dev $interface parent 1:1 handle 10: tbf rate $bandwidth burst 100Kb latency $jitter

# interface=vnet1
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1: protocol ip prio 1 u32 match ip dst 192.168.122.102 flowid 1:1
# tc qdisc add dev $interface parent 1:1 handle 10: tbf rate $bandwidth burst 100Kb latency $jitter





# work, but latency
# interface=vnet2
# tc qdisc add dev $interface root handle 1: netem delay $delay $jitter distribution normal
# tc qdisc add dev $interface parent 1: handle 2: tbf rate $bandwidth burst 1Mb lat 1ms

# interface=vnet0
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
# tc qdisc add dev $interface parent 1:1 handle 10: tbf rate $bandwidth burst 2Mb latency $jitter

# interface=vnet1
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
# tc qdisc add dev $interface parent 1:1 handle 10: tbf rate $bandwidth burst 2Mb latency $jitter





# old 1
# interface=vnet1
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.100 flowid 2:1
# tc filter add dev $interface parent 1:0 protocol ip prio 2 u32 match ip src 192.168.122.101 flowid 2:2
# tc qdisc add dev $interface parent 1:1 handle 10: netem delay $delay $jitter distribution normal
# tc qdisc add dev $interface parent 1:2 handle 20: tbf rate $bandwidth burst 1Mb limit 500kbit

# interface=vnet0
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
# tc qdisc add dev $interface parent 1:1 handle 10: netem delay $delay $jitter distribution normal
# tc qdisc add dev $interface parent 1:2 handle 20: tbf rate $bandwidth burst 2Mb latency $jitter

# interface=vnet2
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
# tc qdisc add dev $interface parent 1:1 handle 10: netem delay $delay $jitter distribution normal
# tc qdisc add dev $interface parent 1:2 handle 20: tbf rate $bandwidth burst 2Mb latency $jitter





## old
# interface=vnet2
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.100 flowid 2:1
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.101 flowid 2:1
# tc qdisc add dev $interface parent 1:1 handle 2: netem delay $delay $jitter distribution normal

# interface=vnet0
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
# tc qdisc add dev $interface parent 1:1 handle 2: netem delay $delay $jitter distribution normal

# interface=vnet1
# tc qdisc add dev $interface root handle 1: prio
# tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 2:1
# tc qdisc add dev $interface parent 1:1 handle 2: netem delay $delay $jitter distribution normal
