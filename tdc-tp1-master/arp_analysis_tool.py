#!/usr/bin/env python

import sys;
import time;
import math;
import collections;
import os;
import re;
import argparse;
import matplotlib.pyplot as plt;
import pydot;

def main():
  args = parse_args()
  s_src, s_dst = read_data(args)
  basename = os.path.basename(args.get('datafile')).split('.')[0]
  hist, info, entropy = compute_source_indicators(s_src)
  print_indicators('S_src', hist, info, entropy, basename)
  plot_histogram('S_src', hist, basename)
  plot_info('S_src', info, entropy, basename)
  hist, info, entropy = compute_source_indicators(s_dst)
  print_indicators('S_dst', hist, info, entropy, basename)
  plot_histogram('S_dst', hist, basename)
  plot_info('S_dst', info, entropy, basename)
  plot_network(s_src, s_dst, basename)

def parse_args():
  parser = argparse.ArgumentParser(description='ARP packet analysis.',
    epilog='Example usage: {script} data/datafile.txt'.format(script=__file__))
  parser.add_argument('datafile', type=str,
    help = 'data file path (lines in data file must be of the form IP_SRC , IP_DST). For example: 192.168.4.139 , 192.168.4.1')
  args = vars(parser.parse_args())
  return args

def read_data(args):
  s_src, s_dst = [], []
  with open(args.get('datafile')) as f:
    for line in f:
      if not re.match('^\s*#', line):
        pieces = line.split(",")
        ip_src, ip_dst = pieces[0].strip(), pieces[1].strip()
        s_src.append(ip_src)
        s_dst.append(ip_dst)
  return s_src, s_dst

def compute_source_indicators(source):
  hist = compute_histogram(source)
  info = compute_information(hist, len(source))
  entropy = compute_entropy(hist, info, len(source))
  return hist, info, entropy
  
def print_indicators(source, hist, info, entropy, basename):
  print '{basename}: {source}'.format(basename=basename, source=source)
  print "  - hist: ", hist
  print "  - info: ", info
  print "  - entropy: ", entropy
  print "  - max possible entropy: ", math.log(len(hist.keys()), 2)
  print "  - ratio: ", (entropy / math.log(len(hist.keys()), 2))
  print ""

def plot_histogram(source, hist, basename):
  x, y = [20 * i for i in range(len(hist))], hist.values()
  labels = hist.keys()
  f = plt.figure('hist_{source}'.format(source=source), [16, 9])
  f.subplots_adjust(bottom=0.2)
  plt.xlim([-2, x[-1] + 2])
  plt.bar(x, y, align='center')
  plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
  plt.title('Cant. paquetes vs IP: {source}'.format(source=source), fontsize=18)
  plt.xlabel("IP", fontsize=15)
  plt.ylabel("Cantidad de paquetes", fontsize=18)
  f.savefig('imgs/{basename}_{source}_hist.png'.format(basename=basename, source=source))

def plot_info(source, info, entropy, basename):
  x, y = [20 * i for i in range(len(info))], info.values()
  labels = info.keys()
  f = plt.figure('info_{source}'.format(source=source), [16, 9])
  f.subplots_adjust(bottom=0.2)
  plt.xlim([-2, x[-1] + 2])
  plt.bar(x, y, align='center', color="green")
  plt.axhline(entropy, color='r',label='entropia')
  plt.xticks(x, labels, size='small',rotation='vertical', fontsize=18)
  plt.title('Informacion vs IP: {source}'.format(source=source), fontsize=18)
  plt.xlabel("IP", fontsize=15)
  plt.ylabel("Informacion", fontsize=18)
  f.savefig('imgs/{basename}_{source}_info.png'.format(basename=basename, source=source))

def plot_network(s_src, s_dst, basename):
  graph = pydot.Dot(graph_type='digraph')
  nodes = {}
  for ip in set(s_src + s_dst):
    pieces = ip.split('.')
    label = '.'.join(pieces[0:2]) + '\n' + '.'.join(pieces[2:4])
    nodes[ip] = pydot.Node(label)
  edges = {}
  for i in range(len(s_src)):
    if not (s_src[i], s_dst[i]) in edges:
      edges[(s_src[i], s_dst[i])] = 0
    edges[(s_src[i], s_dst[i])] += 1
  for (src_ip, dst_ip) in edges:
    graph.add_edge(pydot.Edge(nodes[src_ip], nodes[dst_ip],
      label=edges[(src_ip, dst_ip)], fontsize="8.0", color="blue", len=3.0))
  graph.write_png('imgs/{basename}_red.png'.format(basename=basename), prog='neato')

def compute_histogram(ips):
  hist = collections.OrderedDict()
  for ip in ips: hist[ip] = hist.get(ip, 0) + 1
  return hist

def compute_information(hist, total):
  info = collections.OrderedDict()
  for ip in hist: info[ip] = math.log(total, 2) - math.log(hist[ip], 2)
  return info

def compute_entropy(hist, info, total):
  entropy = 0
  for ip in hist: entropy = entropy + float(hist[ip]) / total * info[ip]
  return entropy

if __name__ == '__main__':
  main()
