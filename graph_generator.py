import pyshark
from matplotlib import pyplot as plt

cap = pyshark.FileCapture('TRACES/TRACE_call_without_camera.pcapng')
cap_cam = pyshark.FileCapture('TRACES/TRACE_call_with_camera.pcapng')

time_0 = cap[4].sniff_timestamp #car l'appel commence au 5e paquet
time_cam_0 = cap_cam[3].sniff_timestamp #car l'appel commence au 4e paquet


x = []
y = []

x_cam = []
y_cam = []

pkt_nbr = 0

for pkt in cap :
    t = float(pkt.sniff_timestamp) - float(time_0)
    # print(t)
    if(t < 0):
        continue
    if(t > 20):
        break
    else:
        pkt_nbr+=1
        x.append(t)
        y.append(pkt_nbr)


pkt_nbr = 0

for pkt in cap_cam :
    # print(t)
    t = float(pkt.sniff_timestamp) - float(time_cam_0)
    if(t < 0):
        continue
    if(t > 20):
        break
    else:
        pkt_nbr+=1
        x_cam.append(t)
        y_cam.append(pkt_nbr)


# fig, (ax1, ax2) = plt.subplots(1, 2)
# fig.suptitle('Number of packet exchanged')
# ax1.title("Call without camera")
# ax1.plot(x, y)
# ax2.plot(x, -y)

plt.plot(x, y, color='r', label="Appel sans caméra")
plt.plot(x_cam, y_cam, color='b', label="Appel avec caméra")
plt.xlabel("t [s]")
plt.ylabel("Number of packet")
plt.legend()
plt.show()


# pkt = cap[3]
