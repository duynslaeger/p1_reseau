import pyshark

cap = pyshark.FileCapture('TRACES/TRACE_call_without_camera.pcapng')

# pkt = cap[3]

# # print(pkt.ipv6)  # = pkt.layer[1]
# print(pkt.ipv6.addr)
# print(pkt.ipv6.src)
# print(pkt.ipv6.src_host)
# print(pkt.ipv6.dst)

# i = 0
# for pkt in cap:
#     i += 1
#     if "IP" in pkt:
#         print("Packet n" + str(i) + " uses IPv4")
#         print("Source address : " + pkt.ip.src)
#         print("Destination address : " + pkt.ip.dst)
#         print("\n")

i = 0
# for pkt in cap:
#     i += 1
#     if "IPV6" in pkt:
#         print("Packet n" + str(i) + " uses IPv6")
#         print("Source address : \t" + pkt.ipv6.src)
#         print("Destination address : \t" + pkt.ipv6.dst)
#         print("\n")

# pkt = cap[291]
# print(pkt.layers)
# print(pkt.tls.record)

for pkt in cap:
    i += 1
    if "TLS" in pkt :
        print(i)
        print(pkt.tls)
        print(pkt.tls.record)
        if(pkt.tls.record == "TLSv1.2 Record Layer: Handshake Protocol: Certificate"):
            print("Packet "+str(i)+" is a Certificate exchange")
# print(pkt.tls)
# print(pkt)