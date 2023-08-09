import os
import time
import csv
import sys

########## CONFIG HERE ##########
SLEEP = 1
#################################


bandwidth = sys.argv[1] # bandwidth
delay = sys.argv[2] # latency
jitter = sys.argv[3] # jitter


delay = int(float(delay) / 2) # ms
jitter = int(float(jitter) * 1000 / 1414) # ms
burst = 140 # kbit
bandwidth = int(bandwidth) # mbit


os.system(f'tc qdisc del dev vnet0 root')
os.system(f'tc qdisc del dev vnet1 root')
os.system(f'tc qdisc del dev vnet2 root')



os.system(f"tc qdisc add dev vnet2 root handle 1: htb default 30")
os.system(f"tc class add dev vnet2 parent 1: classid 1:1 htb rate {bandwidth}mbit")
os.system(f"tc qdisc add dev vnet2 parent 1:1 handle 10: netem delay {delay}ms {jitter}ms")
# os.system(f"tc qdisc add dev vnet2 parent 10:1 handle 20: tbf rate {bandwidth}kbit burst {burst}kbit latency {jitter}ms")
os.system(f"tc filter add dev vnet2 parent 1: protocol all prio 1 u32 match u32 0 0 flowid 1:1")

os.system(f"tc qdisc add dev vnet0 root handle 1: htb default 30")
os.system(f"tc class add dev vnet0 parent 1: classid 1:1 htb rate {bandwidth}mbit")
os.system(f"tc qdisc add dev vnet0 parent 1:1 handle 10: netem delay {delay}ms {jitter}ms")
# os.system(f"tc qdisc add dev vnet0 parent 10:1 handle 20: tbf rate {bandwidth}kbit burst {burst}kbit latency {jitter}ms")
os.system(f"tc filter add dev vnet0 parent 1: protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 1:1")

os.system(f"tc qdisc add dev vnet1 root handle 1: htb default 30")
os.system(f"tc class add dev vnet1 parent 1: classid 1:1 htb rate {bandwidth}mbit")
os.system(f"tc qdisc add dev vnet1 parent 1:1 handle 10: netem delay {delay}ms {jitter}ms")
# os.system(f"tc qdisc add dev vnet1 parent 10:1 handle 20: tbf rate {bandwidth}kbit burst {burst}kbit latency {jitter}ms")
os.system(f"tc filter add dev vnet1 parent 1: protocol ip prio 1 u32 match ip src 192.168.122.102 flowid 1:1")


with open('B_2018.01.19_07.31.48.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
        if line_count == 0:
            line_count +=1
            time.sleep(SLEEP)
            continue
        bandwidth = int(float(row[12]) / 1000)
        print(f"konnichiwa {line_count} {bandwidth}mbit")
        
        os.system(f"tc class change dev vnet2 parent 1: classid 1:1 htb rate {bandwidth}mbit")
        # # os.system(f"tc qdisc change dev vnet2 parent 10:1 handle 20: tbf rate {bandwidth}mbit burst {burst}kbit latency {jitter}ms")

        os.system(f"tc class change dev vnet0 parent 1: classid 1:1 htb rate {bandwidth}mbit")
        # #os.system(f"tc qdisc change dev vnet0 parent 10:1 handle 20: tbf rate {bandwidth}mbit burst {burst}kbit latency {jitter}ms")

        os.system(f"tc class change dev vnet1 parent 1: classid 1:1 htb rate {bandwidth}mbit")
        # #os.system(f"tc qdisc change dev vnet1 parent 10:1 handle 20: tbf rate {bandwidth}mbit burst {burst}kbit latency {jitter}ms")

        line_count += 1
        time.sleep(SLEEP)
