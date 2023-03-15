import pyshark

cap = pyshark.FileCapture('TRACES/TRACE_msg_and_answer.pcapng')

pkt = cap[3]

print(pkt)
