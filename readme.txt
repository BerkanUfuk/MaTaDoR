MATADOR is a transparent proxy. You need to place matador in between clients and servers.
It checks the message authentication bytes then it forwards the request depending on whether the message was authenticated or not.

MATADOR employs iptables rules. To start correctly, first run the iptables_rules.py file. 
Then start the server, lastly start the client.
