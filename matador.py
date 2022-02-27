#!/usr/bin/python

import socket
import requests
from scapy.all import *
#https://stackoverflow.com/questions/38300753/python-tcp-raw-socket-not-listening-on-lo-localhost-127-0-0-1
soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
soc.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
soc.bind(("lo",0x0003))

while True:
	a = soc.recvfrom(1600)
	print("A client has initiated a connection...")
	print("Here is the incoming request:")
	print (":".join("{:02x}".format(ord(c)) for c in a[0][:]))
	tcpao = ":".join("{:02x}".format(ord(c)) for c in a[0][28:29])
	print("TCP AO")
	print(tcpao)
	hostname = socket.gethostname()
	local_ip = socket.gethostbyname(hostname)
	print("Client IP is...")
	print(local_ip)
	if (tcpao == "00"):
		print("Access granted...")
		#burada tcp ao dogrulandi normal siteye yonlendir iletisimi baslat
		print("This is the request that will be forwarded to the actual server")
		req = a[0][68:].rstrip('\x00')
		#req = a[0][84:].rstrip('\x00')
		headers = {"User-Agent": req}
		print("saaa")
		print(req)
		
		#https://www.datacamp.com/community/tutorials/making-http-requests-in-python
		#eger http devam ettirilecekse...
		#bu normalde farkli bir hostta olacak
		response = requests.get("http://127.0.0.1")
		print("Here is the response that is made to ORIGINAL SITE")
		print(response)
		#bu response u client a ilet
		#dport u tekrar hesapla (client tan gelen sport u al)
		response = "sa"
		pk = Ether()/IP(dst=local_ip, src="127.0.0.1") / TCP(sport=8090, dport=80) / response
		send(pk)
		#soc.close()
		
	else:
		print("Access Denied, you need to have the correct TCP-AO header to initiate a connection...")
		#burada gelen istek dogrulanmadigi icin direkt olarak fake siteye istek yapacak.
		print("THE REQUEST:")
		print(a[0][68:])
		req = a[0][84:].rstrip('\x00')
		headers = {"User-Agent": req}
		#fake site de normalde ic agda farkli bir yerde olacak.
		response = requests.get("http://127.0.0.1")
		#response = requests.get("http://127.0.0.1", headers=headers)
		print("Here is the response that is made to FAKE SITE")
		print(response)
		#bu response u client a ilet
		#soc.close()
