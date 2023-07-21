from scapy.layers.inet import *
from scapy.all import *


# check whether a pkt has one addr
def filter_one_addr(pkt, ip):
    if pkt[IP].src == ip or pkt[IP].dst == ip:
        return True
    return False


# check whether a pkt has both two addr
def filter_two_ip(pkt, ip1, ip2):
    if filter_one_addr(pkt, ip1) and filter_one_addr(pkt, ip2):
        return True
    return False



IP_HUST = "202.191.58.171"
IP_FILVR = "192.168.101.117"
IP_PRIVATE_SERVER = "172.31.32.124"
IP_PUBLIC_SERVER = "122.248.237.40"


# read .pcap file and get pkt.time
serverFile = [_ for _ in PacketList(rdpcap("pcap/clock/bonaserver_600.pcap"))]
filvrFile = [_ for _ in PacketList(rdpcap("pcap/clock/filvr_600.pcap"))]
serverTime = []
filvrTime = []
for pkt in serverFile:
    try:
        if(str(pkt).find("ICMP") != -1 and filter_two_ip(pkt, IP_PRIVATE_SERVER, IP_HUST)):
            serverTime.append(float(pkt.time))                  
    except:
        continue

for pkt in filvrFile:
    try:
        if(str(pkt).find("ICMP") != -1 and filter_two_ip(pkt, IP_FILVR, IP_PUBLIC_SERVER)):      
            filvrTime.append(float(pkt.time))                  
    except:
        continue


# analyse
i = 0
chigai = 0
while(i < len(serverTime)):
    try:
        chigai += (serverTime[i] - filvrTime[i] - filvrTime[i+1] + serverTime[i+1]) / 2
        i += 2
    except:
        break

print(chigai / len(serverTime) * 2)
