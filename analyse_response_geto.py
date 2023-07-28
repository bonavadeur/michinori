import pyshark, os, json, csv, platform
from datetime import datetime

if(platform.system() == "Windows"):
    os.system("cls")
elif(platform.system() == "Linux"):
    os.system("clear")



def filterCap(file, expression):
    cap = pyshark.FileCapture(file, display_filter=expression)
    packets = [pkt for pkt in cap]
    cap.close()
    return packets



def s2dtime(seconds: float) -> str:
    seconds = float(seconds)
    return datetime.fromtimestamp(seconds).strftime('%Y-%m-%d %H:%M:%S.%f')



def detectIP(components, componentIPs, pkt):
    """
    detect that a packet from which component and which node
    
    return ["srcComponent, dstComponent, srcNode, dstNode"]
    """
    components = ["3scale", "activator", app]
    src = "user"
    dst = ""
    srcNode = userNode
    dstNode = ""
    for svc in components:
        try:
            if(str(pkt[5].src) in componentIPs[svc]):
                src = svc
                srcNode = clusterInfo["pods"][str(pkt[5].src)]["node_name"]
        except:
            if(str(pkt[1].src) in componentIPs[svc]):
                src = svc
                srcNode = clusterInfo["pods"][str(pkt[1].src)]["node_name"]
        try:
            if(str(pkt[5].dst) in componentIPs[svc]):
                dst = svc
                dstNode = clusterInfo["pods"][str(pkt[5].dst)]["node_name"]
        except:
            if(str(pkt[1].dst) in componentIPs[svc]):
                dst = svc
                dstNode = clusterInfo["pods"][str(pkt[1].dst)]["node_name"]
    return [src, dst, srcNode, dstNode]



#################### CONFIG HERE ####################

latency = "30_25_10"
app = "hello"
userNode = "node3"
components = ["3scale", "activator", app]

dir = f"pcap/default/hello/0/"

with open(f'{dir}clusterinfo.json', 'r') as f:
    clusterInfo = json.load(f)

node1cap = f"{dir}node1.pcapng"
node2cap = f"{dir}node2.pcapng"
node3cap = f"{dir}node3.pcapng"
nodecaps = [node1cap, node2cap, node3cap]
usercap = f"{dir}node3.pcapng"

#####################################################


DNSTime = []
# get DNS-timestamps
cap = filterCap(usercap, f'dns.qry.name contains "{app}.default"')
dnsTimes = [float(p.frame_info.time_epoch) for p in cap] # seconds
DNSTime.append(dnsTimes[0])
diffTimes = []
for i in range(len(dnsTimes) - 1):
    if(i == 0):
        currentDiff = dnsTimes[i+1] - dnsTimes[i]
        continue
    else:
        lastDiff = currentDiff
        currentDiff = dnsTimes[i+1] - dnsTimes[i]
        if(currentDiff - lastDiff > 2):
            DNSTime.append(dnsTimes[i])
            DNSTime.append(dnsTimes[i+1])
DNSTime.append(dnsTimes[-1])
# print(([s2dtime(t) for t in DNSTime]))
# print(len(DNSTime))



componentIPs = {}
for c in components:
    componentIPs[c] = {}
for obj in components:
    for podip, podSpec in clusterInfo["pods"].items():
        if(podSpec["name"].find(obj) != -1):
            componentIPs[obj][podip] = podSpec["node_name"]
# print(componentIPs)
# {
#     "3scale": {
#         '10.233.75.22': 'node2',
#         '10.233.71.4': 'node3',
#         '10.233.102.150': 'node1'
#     },
#     "activator": {
#         '10.233.102.142': 'node1'
#     },
#     "hello": {
#         '10.233.102.191': 'node1'
#     }
# }
appIPs = [podip for podip, podSpec in clusterInfo["pods"].items() if podSpec["name"].find(app) != -1]
# ['10.233.102.191']





records = []
for n in range(0, int(len(DNSTime) / 2 - 1)):
# n = 0
    start = DNSTime[n*2]
    end = DNSTime[n*2+2]
    _timeEx = f'frame.time>="{s2dtime(start)}" && frame.time<="{s2dtime(end)}"'
    _appEx = ""
    for appip in appIPs:
        _appEx += f'|| http.host contains "{appip}"'

    filter = f'{_timeEx} \
    && http \
    && !(http.user_agent contains "kube-probe") \
    && http.request.uri != "/healthz" \
    && http.request.uri != "/metrics" \
    && (http.host contains "{app}.default" {_appEx}) \
    '
    # print(filter)
    # cap = filterCap(node1cap, filter)

    record = []
    detects = []
    for i in range(0, len(clusterInfo["nodes"])):
        node = list(clusterInfo["nodes"].values())[i]
        cap = filterCap(nodecaps[i], filter)
        for p in cap:
            detect = detectIP(components, componentIPs, p)
            if(detect[2] == node):
                try:
                    responsePkt = filterCap(nodecaps[i], f"http.request_in=={p.frame_info.number}")[0]
                except:
                    continue
                responseTime = (float(responsePkt.frame_info.time_epoch) - float(p.frame_info.time_epoch)) * 1000
                detect.append(responseTime)
                if(detect[0] == "user"):
                    detect.append(-1)
                else:
                    detect.append(components.index(detect[0]))
                detects.append(detect)

    detects.sort(key=lambda x : x[5])

    for i in range(len(detects)):
        if(i != len(detects) - 1):
            detects[i][4] -= detects[i+1][4]
    record = [detect[0] for detect in detects]
    if record == []:
        records.append(record)
        print(record)
        continue
    record.append(detects[-1][1])
    record.extend([detect[2] for detect in detects])
    record.append(detects[-1][3])
    time = [round(detect[4], 3) for detect in detects]
    record.extend(time)
    record.append(round(sum(time), 3))

    records.append(record)
    print(n, record)

with open('pcap/response.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    for record in records:
        writer.writerow(record)

# print(records)