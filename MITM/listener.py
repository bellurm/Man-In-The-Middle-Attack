import scapy.all as scapy
from scapy_http import http



def listen_packets(interface):
	scapy.sniff(iface = get_iface, store = False, prn = analyzed_packets)

def analyzed_packets(packet):
	#packet.show()
	if packet.haslayer(http.HTTPRequest):
		if packet.haslayer(scapy.Raw):
			print(packet[scapy.Raw].load)

try:
	get_iface = input("[!] What's your iface? -> ")
	print("Sniffing...\n")
except OSError:
	print("[!] Invalid interface")

listen_packets(get_iface)
