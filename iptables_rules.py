#!/usr/bin/python

import os

os.system("iptables --policy FORWARD accept")
os.system("iptables -A FORWARD -m mark --mark 0x400 -p TCP --dport 80 -j DNAT --to-destination 192.168.1.100:80")
os.system("iptables -A FORWARD -m mark --mark 0x401 -p TCP --dport 80 -j DNAT --to-destination 192.168.1.100:80")
os.system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")

