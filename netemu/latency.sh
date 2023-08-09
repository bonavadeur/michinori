#!/bin/bash

ssh root@192.168.122.100 "ping 192.168.122.102 -c 60 -i 2"
sleep 5

for latency in 100 70 190 210 100 140 170 150 20 50 190 60 40 60 110
do
    ./delay.sh $latency distribution normal
    ssh root@192.168.122.100 "ping 192.168.122.102 -c 300 -i 2"
    sleep 5
    ./undelay.sh
done