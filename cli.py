from scapy.all import *
import csv
import pandas
from Crypto.Hash import HMAC, MD5

key="SharedSecretKey"

class Test(Ether):
	name = "Test"

	@classmethod
	def add_XByteField(cls, name, value):
		cls.fields_desc.append(XByteField(name, value))

#Adds hex byte field to the protocol in use
Test.add_XByteField('TCPAO', 0)
Test.add_XByteField('TCPAO2', 0)
Test.add_XByteField('TCPAO3', 0)
Test.add_XByteField('TCPAO4', 0)
Test.add_XByteField('TCPAO5', 0)
Test.add_XByteField('TCPAO6', 0)
Test.add_XByteField('TCPAO7', 0)
Test.add_XByteField('TCPAO8', 0)
Test.add_XByteField('TCPAO9', 0)
Test.add_XByteField('TCPAO10', 0)
Test.add_XByteField('TCPAO11', 0)
Test.add_XByteField('TCPAO12', 0)
Test.add_XByteField('TCPAO13', 0)
Test.add_XByteField('TCPAO14', 0)
Test.add_XByteField('TCPAO15', 0)
Test.add_XByteField('TCPAO16', 0)

#generic payload
payl = "GET / HTTP/1.1 Host: 192.168.19.128 User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 Accept-Encoding: gzip, deflate Connection: keep-alive Upgrade-Insecure-Requests: 1"

#different datasets for testing purposes
#loc = ("/root/Desktop/deneme/suee2.csv")
#loc = ("/home/kali/Desktop/deneme/sueeNormal.csv")
loc = ("/home/kali/Desktop/deneme/sueAttack.csv")

df = pandas.read_csv(loc)

for index, row in df.iterrows():
	#p = row["Request"][0:row["Length"] ]
	p = payl[0:row["Length"]].rstrip()
	#print (p)
	#valid
	#pk = Ether()/IP(dst="127.0.0.1", src="127.0.0.1") / TCP(sport=80, dport=80)
	#normal
	#pk = Test(TCPAO=11)/IP(dst="127.0.0.1", src="127.0.0.1") / TCP(sport=8080, dport=8080) / p	
	
	#h = HMAC.new(key, msg="", digestmod='')

	h = hmac.new(key, p, digestmod=hashlib.sha256)

	print h.hexdigest()

	#pk = Test( TCPAO=int(h.hexdigest()[0:2], 16), 
	#		 TCPAO2=int(h.hexdigest()[2:4], 16), TCPAO3=int(h.hexdigest()[4:6], 16), 
	#		 TCPAO4=int(h.hexdigest()[6:8], 16), TCPAO5=int(h.hexdigest()[8:10], 16),
	#		 TCPAO6=int(h.hexdigest()[10:12], 16), TCPAO7=int(h.hexdigest()[12:14], 16),  
	#		 TCPAO8=int(h.hexdigest()[14:16], 16), TCPAO9=int(h.hexdigest()[16:18], 16),  
	#		 TCPAO10=int(h.hexdigest()[18:20], 16), TCPAO11=int(h.hexdigest()[20:22], 16),  
	#		 TCPAO12=int(h.hexdigest()[22:24], 16), TCPAO13=int(h.hexdigest()[24:26], 16), 
	#		 TCPAO14=int(h.hexdigest()[26:28], 16), TCPAO15=int(h.hexdigest()[28:30], 16),
	#		 TCPAO16=int(h.hexdigest()[30:32], 16)) / str(h.hexdigest()) / IP(dst="127.0.0.1", src="127.0.0.1") /  TCP(sport=8080, dport=8080)/ p 
	pk = Ether() / str(h.hexdigest()) / IP(dst="127.0.0.1", src="127.0.0.1") /  TCP(sport=8080, dport=8080)/ p

	send(pk)


