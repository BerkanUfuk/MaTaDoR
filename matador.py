#!/usr/bin/python

import socket
import requests
from scapy.all import *
from Crypto.Hash import HMAC, MD5

key="SharedSecretKey"

soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
soc.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
soc.bind(("lo",0x0003))

while True:
	a = soc.recvfrom(1600)
	print("A client has initiated a connection...")
	print("Here is the incoming request:")
	print (":".join("{:02x}".format(ord(c)) for c in a[0][:]))
	print ("TCPAOOO")
	#tcpao = ":".join("{:02x}".format(ord(c)) for c in a[0][28:92])
	tcpao = a[0][28:92]
	print (tcpao)
	#get the hostname of the client connected
	hostname = socket.gethostname()
	#get the IP of the client
	local_ip = socket.gethostbyname(hostname)
	print("Client IP is...")
	print(local_ip)
	#after this till the end, the TCP payload is the request
	msg = a[0][132:]
	#print (req.replace(':', ''))
	print ("req")
	print (msg)

	h = hmac.new(key, msg, digestmod=hashlib.sha256)
	print h.hexdigest()

	if (tcpao == h.hexdigest()):

		print("Access granted...")
		#Message is authenticated, forward the request to the genuine server

		#os.system("iptables -F")#clean all
		#os.system("iptables -X")
		#os.system("iptables -t nat -F")
		#os.system("iptables -t nat -X")
		#"iptables -P INPUT DROP",#forbid all
		#os.system("iptables -A INPUT -i lo -j ACCEPT") #accept all localhost
		#os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.99:80")
		#os.system("iptables -t nat -A POSTROUTING -j MASQUERADE")
		#os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j MARK --set-mark 0x400")

		os.system("iptables -t mangle -A PREROUTING -p tcp --dport 80  -j MARK --set-mark 0x400")

	else:
		print("Access Denied, you need to have the correct TCP-AO header to initiate a connection...")
		#os.system("iptables -F")#clean all
		#os.system("iptables -X")
		#os.system("iptables -t nat -F")
		#os.system("iptables -t nat -X")
    #"iptables -P INPUT DROP",#forbid all
		#os.system("iptables -A INPUT -i lo -j ACCEPT") #accept all localhost
		#os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.99:80")
		#os.system("iptables -t nat -A POSTROUTING -j MASQUERADE")
		#os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j MARK --set-mark 0x400")
		os.system("iptables -t mangle -A PREROUTING -p tcp --dport 80  -j MARK --set-mark 0x401")
		#iptables -A PREROUTING -i eth0 -t mangle -p tcp --dport 80 -j MARK --set-mark 1

