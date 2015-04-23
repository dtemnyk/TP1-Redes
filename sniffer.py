#! /usr/bin/env python
from scapy.all import *
 
sniff(iface="eth0", prn=lambda x: x.show())