#!/usr/bin/env python

import os;
import sys;
import argparse;
import logging; logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
if os.getuid() == 0: import scapy.all;

args = None

def main():
  global args
  check_privileges()
  parse_args()
  start_listener()
  
def check_privileges():
  if os.getuid() != 0:
    print "Please, run again with sudo privileges."
    exit()

def parse_args():
  global args
  parser = argparse.ArgumentParser(description='ARP packet listener.',
    epilog='Example usage: {script} --only-who-has --only-ips --count 100'.format(script=__file__))
  parser.add_argument('--only-who-has', action='store_true',
    help = 'listen only to who-has ARP packets.')
  parser.add_argument('--only-ips', action='store_true',
    help = 'output only psrc, pdst fields from incoming ARP packets.')
  parser.add_argument('--timeout', type=int, default=7200,
    help = 'stop listener after `TIMEOUT` seconds have passed')
  parser.add_argument('--count', type=int, default=2000,
    help = 'stop listener after `COUNT` packets have been received')
  args = vars(parser.parse_args())

def start_listener():
  scapy.all.sniff(prn=monitor_callback, filter = "arp",
    timeout = args.get('timeout'), count = args.get('count'))

def monitor_callback(pkt):
  global args
  if scapy.all.ARP in pkt:
    if not(args.get('only_who_has')) or pkt[scapy.all.ARP].op == 1: # who-has
      if args.get('only_ips'):
        print pkt[scapy.all.ARP].psrc, ",", pkt[scapy.all.ARP].pdst
      else:
        pkt[scapy.all.ARP].show()

if __name__ == '__main__':
  main()