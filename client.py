from scapy.all import *
import csv
import pandas

class Test(Ether):
	name = "Test"
#fields_desc = [ IntField("Number",0) ]

#Burasi var olan bir fields description a yeni bir alan ekler
#Neden gerekli> cunku en bastan paketi kendim olusturdugumda
#yani tum fieldlari kendim tek tek tanimladigimda paket gitmedi...
# @classmethod
# def add_IntField(cls, name, value):
# cls.fields_desc.append(IntField(name, value))

#TCP AO kismini hex byte olarak pakete ekler
#	@classmethod
#	def add_XByteField(cls, name, value):
#		cls.fields_desc.append(XByteField(name, value))

	@classmethod
	def add_ByteField(cls, name, value):
		cls.fields_desc.append(ByteField(name, value))



#Test.add_IntField('X', 1)
#default degeri 0x000a olan bir alan ekle
#bu degeri boyle yollayinca wireshark bunu optionsmus gibi algiliyor.
#Test.add_XByteField('TCPAO', 0x000a)
#Test.add_XByteField('TCPAO', 16)
Test.add_ByteField('TCPAO', 1024)

#class Test2(Packet):
#name = "test protocol"
#fields_desc = [
#BitField("version", "4 bits", 4),
#BitField("ihl", None, 4),
#XByteField("tos", 0),
#ShortField("len", None),
#ShortField("id", 1),
#FlagsField("flags", 0, 8, ['S', 'A', 'F', 'R', 'P', 'U']),
#BitField("frag", "13 bits", 0),
#ByteField("ttl", 64),
#ByteEnumField("proto", 0, {1:"one", 10:"ten"}),
#XShortField("chksum", None),
#SourceIPField("src", None),
#DestIPField("dst", None),
#PacketListField("options", None),
#XByteField("AO", 0x000000000000000a),
#]


payl = "GET / HTTP/1.1 Host: 192.168.19.128 User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 Accept-Encoding: gzip, deflate Connection: keep-alive Upgrade-Insecure-Requests: 1"

payload = "GET / HTTP/1.1 Host: 192"

payl2 = "AAAAAAAAA"

loc = ("/root/Desktop/deneme/suee2.csv")
#loc = ("/home/kali/Desktop/deneme/sueeNormal.csv")
#loc = ("/home/kali/Desktop/deneme/sueAttack.csv")
df = pandas.read_csv(loc)

for index, row in df.iterrows():
	#p = row["Request"][0:row["Length"] ]
	p = payl[0:row["Length"]].rstrip()
	print (p)
	#valid
	#pk = Ether()/IP(dst="127.0.0.1", src="127.0.0.1") / TCP(sport=80, dport=80) / p
	#normal
	pk = Test(TCPAO=0)/IP(dst="127.0.0.1", src="127.0.0.1") / TCP(sport=8080, dport=8080) / p	
	send(pk)

#pk2 = Ether(dst="08:00:27:02:c5:5f") / IP(dst="127.0.0.1") / TCP(dport=80) / payload
#pk2 = Test(TCPAO=255)/IP(dst="127.0.0.1", src="127.0.0.1") / TCP(sport=80, dport=80) / payload
#pk2 = Test(TCPAO=0)
#pk2 = "AAA"/Test(TCPAO=32)
#pk2 = IP()/TCP()
#print(ls(pk2))
#send(pk2)


# Create Raw Socket
#s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

#pkt = EtherPacket()
#pkt1 = IPPacket()

#s.sendto(pkt.raw+pkt1.raw, ('127.0.0.1' , 0 ))

#packet = Test(TCPAO=0x000b) / payload
#ls(packet)
#send(packet) """ 
