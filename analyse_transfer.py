import pyshark, os, json
from datetime import datetime

os.system("cls")



def filterCap(file, expression):
    cap = pyshark.FileCapture(file, display_filter=expression)
    packets = [pkt for pkt in cap]
    cap.close()
    return packets



def s2dtime(seconds: float) -> str:
    seconds = float(seconds)
    return datetime.fromtimestamp(seconds).strftime('%Y-%m-%d %H:%M:%S.%f')



#################### CONFIG HERE ####################

latency = 0
app = "hello"
userNode = "node3"
components = ["3scale", "activator", app]
delta = {
    "node1": 0 / 1000,
    "node2": -12 / 1000,
    "node3": 4 / 1000
}

dir = f"pcap/{app}/fix/{latency}/"

with open(f'{dir}clusterinfo.json', 'r') as f:
    clusterInfo = json.load(f)

nodeCaps = {
    "node1": f"{dir}node1.pcapng",
    "node2": f"{dir}node2.pcapng",
    "node3": f"{dir}node3.pcapng"
}
userCap = f"{dir}node3.pcapng"

#####################################################


DNSTime = []
# get DNS-timestamps
cap = filterCap(userCap, f'dns.qry.name contains "{app}.default"')
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



def detectIP(pkt):
    """
    detect that a packet from which component and which node
    
    return [srcComponent, dstComponent, srcNode, dstNode]
    """
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

    record = []
    packets = []
    for i in range(0, len(clusterInfo["nodes"])):
        node = list(clusterInfo["nodes"].values())[i]
        cap = filterCap(nodeCaps[node], filter) # apply filter to cpfile of node i
        for pkt in cap:
            detect = detectIP(pkt) # [srcComponent, dstComponent, srcNode, dstNode]
            try:
                responsePkt = filterCap(nodeCaps[node], f"http.request_in=={pkt.frame_info.number}")[0]
            except:
                continue
            responseTime = (float(responsePkt.frame_info.time_epoch) - float(pkt.frame_info.time_epoch)) * 1000 # ms
            # print(responseTime)
            packets.append({
                "fromNode": detect[2],
                "toNode": detect[3],
                "fromComponent": detect[0],
                "toComponent": detect[1],
                "onNode": node,
                "time": float(pkt.frame_info.time_epoch)
            })
            packets.append({
                "fromNode": detect[3],
                "toNode": detect[2],
                "fromComponent": detect[1],
                "toComponent": detect[0],
                "onNode": node,
                "time": float(responsePkt.frame_info.time_epoch)
            })

    # print("packets")
    # print(packets)
    # exit()

    segmentTimes = []
    while(len(packets) != 0):
        p1 = packets[0]
        p2 = ""
        for i in range(1, len(packets)):
            if(packets[i]["fromComponent"] == p1["fromComponent"] and
            packets[i]["toComponent"] == p1["toComponent"]):
                p2 = packets[i]
                break
        if(p2 == ""):
            segmentTimes.append([p1["fromNode"], p1["toNode"], p1["fromComponent"], p1["toComponent"], 0])
            packets.remove(p1)
        else:
            if(p1["onNode"] == p1["fromNode"]):
                time = (p2["time"] - delta[p2["onNode"]]) - (p1["time"] - delta[p1["onNode"]])
            if(p1["onNode"] == p1["toNode"]):
                time = (p1["time"] - delta[p1["onNode"]]) - (p2["time"] - delta[p2["onNode"]])
            segmentTimes.append([p1["fromNode"], p1["toNode"], p1["fromComponent"], p1["toComponent"], round(time * 1000, 3)])
            packets.remove(p1)
            packets.remove(p2)

    route = ["user"]
    route.extend(components)

    for p in segmentTimes:
        if(route.index(p[2]) < route.index(p[3])):
            p.append(route.index(p[2]))
        else:
            p.append(len(segmentTimes) - route.index(p[3]))
    segmentTimes.sort(key = lambda arr : arr[5])
    for p in segmentTimes:
        p.pop(-1)

    for p in segmentTimes:
        print(p)
    print()
    records.append(segmentTimes)
