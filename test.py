import pyshark

cap = pyshark.FileCapture('/tmp/mycapture.cap')

pkt = cap[1]

print(pkt)
