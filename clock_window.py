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
node1Cap_original = filterCap("pcap/clock/ping131_mix.pcapng", "")
node2Cap_original = filterCap("pcap/clock/ping133_mix.pcapng", "")

results = []

step = 60

for a in range(2*step, len(node1Cap_original), step):
    node1Cap = node1Cap_original[a-2*step:a+2*step]
    node2Cap = node2Cap_original[a-2*step:a+2*step]
    node1Time = []
    node2Time = []

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
            chigai += (node2Time[i] - node1Time[i] - node1Time[i+1] + node2Time[i+1]) / 2
            i += 2
        except:
            break

    result = round(chigai / (len(node1Cap) / 2) * 1000, 3)
    results.append(result)

    # print(a / 60, round(chigai / (len(node1Cap) / 2) * 1000, 3))

plt.plot(results)
plt.show()
exit()
