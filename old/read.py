from scapy.layers.inet import *
from scapy.all import *
from datetime import datetime
import os, json

os.system("cls")


# check whether a pkt has one addr
def filter_one_addr(pkt, ip):
    try:
        if pkt[IP].src == ip or pkt[IP].dst == ip:
            return True
    except:
        return False
    return False


# check whether a pkt has both two addr
def filter_two_ip(pkt, ip1, ip2):
    try:
        if filter_one_addr(pkt, ip1) and filter_one_addr(pkt, ip2):
            return True
    except:
        return False
    return False


# check whether a pkt has one of this addrs
def filter_mul_ip(pkt, ips):
    try:
        for ip in ips:
            if filter_one_addr(pkt, ip) or filter_one_addr(pkt, ip):
                return True
    except:
        return False
    return False


def datetime2ms(dtime):
    return datetime.strptime(dtime, "%Y-%m-%d %H:%M:%S.%f").timestamp()



# read .pcap file
node1pcap = [_ for _ in PacketList(rdpcap("pcap/michinori/in_hello_0ms_node1.pcap"))]
# node2pcap = [_ for _ in PacketList(rdpcap("pcap/michinori/internal_hello_0ms_node2.pcap"))]
# node3pcap = [_ for _ in PacketList(rdpcap("pcap/michinori/internal_hello_0ms_node3.pcap"))]

# read .json file
with open('pcap/michinori/in_hello_0ms.json', 'r') as f:
    info = json.load(f)



ips = [pod["ip"] for pod in info["pods"]]
ips.extend(["192.168.122.100", "192.168.122.101", "192.168.122.102"])

startTime = datetime2ms("2023-07-10 11:23:37.230000")
endTime = datetime2ms("2023-07-10 11:23:43.350000")

count = 0
for pkt in node1pcap:        
    if(pkt.time >= startTime and pkt.time <= endTime and filter_mul_ip(pkt, ips)):
        if(str(pkt).find("http") != -1):
            print(pkt)

print(count)
    
    # try:
    #     if(filter_mul_ip(pkt, ["10.233.71.50", "10.233.102.190"]) and
    #        str(pkt).find("DNS") != -1 and 
    #        str(pkt).find("hello.default") != -1):
    #         print(pkt[IP].src, pkt[IP].dst)
    # except:
    #     continue


    # if(str(pkt).find("DNS") != -1 and
    #    str(pkt).find("hello.default") != -1):
    #     print(pkt.time, pkt.payload)
#     try:
#         if(str(pkt).find("ICMP") != -1 and filter_two_ip(pkt, IP_PRIVATE_SERVER, IP_HUST)):
#             serverTime.append(float(pkt.time))                  
#     except:
#         continue
