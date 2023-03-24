import pyshark
from matplotlib import pyplot as plt

cap = pyshark.FileCapture('TRACES/TRACE_call_without_camera.pcapng')
cap_cam = pyshark.FileCapture('TRACES/TRACE_call_with_camera.pcapng')
cap_exch = pyshark.FileCapture('TRACES/TRACE_ECHANGE_MSG.pcapng')

time_0 = cap[33].sniff_timestamp  # car l'appel commence au 34e paquet
time_cam_0 = cap_cam[8].sniff_timestamp  # car l'appel commence au 9e paquet
time_exch_0 = cap_exch[2].sniff_timestamp # car l'envoi de message commence au 2e paquet

x = []
y = []

x_cam = []
y_cam = []

x_exch = []
y_exch = []

pkt_nbr = 0

for pkt in cap:
    t = float(pkt.sniff_timestamp) - float(time_0)
    # print(t)
    if(t < 0):
        continue
    if(t > 30):
        break
    else:
        pkt_nbr += 1
        x.append(t)
        y.append(pkt_nbr)

pkt_nbr = 0

for pkt in cap_exch:
    t = float(pkt.sniff_timestamp) - float(time_exch_0)
    # print(t)
    if(t < 0):
        continue
    if(t > 30):
        break
    else:
        pkt_nbr += 1
        x_exch.append(t)
        y_exch.append(pkt_nbr)


pkt_nbr = 0

for pkt in cap_cam:
    # print(t)
    t = float(pkt.sniff_timestamp) - float(time_cam_0)
    if(t < 0):
        continue
    if(t > 30):
        break
    else:
        pkt_nbr += 1
        x_cam.append(t)
        y_cam.append(pkt_nbr)


# fig, (ax1, ax2) = plt.subplots(1, 2)
# fig.suptitle('Number of packet exchanged')
# ax1.title("Call without camera")
# ax1.plot(x, y)
# ax2.plot(x, -y)

print("Call without camera has " + str(y[-1]) + " packets after 30s of call")
print("Call with camera has " + str(y_cam[-1]) + " packets after 30s of call")
print(y_exch)
print("Scenario exchange of messages has " + str(y_exch[-1]) + " packets after 30s of messages exchanging")

plt.plot(x, y, color='r', label="Appel sans caméra")
plt.plot(x_cam, y_cam, color='b', label="Appel avec caméra")
plt.plot(x_exch, y_exch, color='g', label='Échange de message toutes les 5s')
plt.xlabel("t [s]")
plt.ylabel("Number of packet")
plt.legend()
plt.savefig("plot_packets_call.png")
plt.show()


# pkt = cap[3]
