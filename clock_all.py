import pyshark, os
import matplotlib.pyplot as plt

os.system("cls")



# check whether a pkt has one addr
def filter_one_addr(pkt, ip):
    if pkt.ip.src == ip or pkt.ip.dst == ip:
        return True
    return False


# check whether a pkt has both two addr
def filter_two_ip(pkt, ip1, ip2):
    if filter_one_addr(pkt, ip1) and filter_one_addr(pkt, ip2):
        return True
    return False


def filterCap(file, expression):
    cap = pyshark.FileCapture(file, display_filter=expression)
    packets = [pkt for pkt in cap]
    cap.close()
    return packets



IP_NODE1 = "192.168.122.100"
IP_NODE2 = "192.168.122.102"


# read .pcap file and get pkt.time
_latency = 300
node1Cap = filterCap("pcap/clock/ping131.pcapng", "icmp")
node2Cap = filterCap("pcap/clock/ping133.pcapng", "icmp")

# node1Cap = filterCap(f"pcap/hello/{_latency}/node2.pcapng", "icmp")
# node2Cap = filterCap(f"pcap/hello/{_latency}/node3.pcapng", "icmp")

node1Time = []
node2Time = []
results = []

for pkt in node1Cap:
    try:
        if(filter_two_ip(pkt, IP_NODE1, IP_NODE2)):
            node1Time.append(float(pkt.frame_info.time_epoch))
    except:
        continue

for pkt in node2Cap:
    try:
        if(filter_two_ip(pkt, IP_NODE2, IP_NODE1)):
            node2Time.append(float(pkt.frame_info.time_epoch))
    except:
        continue

# analyse
i = 0
chigai = 0
while(i < len(node1Time)):
    try:
        result = round((node2Time[i] - node1Time[i] - node1Time[i+1] + node2Time[i+1]) / 2 * 1000, 3)
        results.append(result)
        chigai += (node2Time[i] - node1Time[i] - node1Time[i+1] + node2Time[i+1]) / 2
        i += 2
    except:
        break

print(round(chigai / (len(node1Time) / 2) * 1000, 3))
# print(len(results), len(node1Time))

# plt.plot(results)
# plt.show()
# exit()
