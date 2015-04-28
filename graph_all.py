#!/usr/bin/env python
# -*- coding: utf-8 -*-
import math
import pydot
import pickle
import matplotlib.pyplot as plt
import collections

type_dictionary = {}
dist_dictionary = {}
dst_dictionary = {}
packet_count = 0


def graph_all():
    global packet_count
    global type_dictionary
    global dist_dictionary
    global dst_dictionary

    type_dictionary = pickle.load(open("type_dictionary.p", "rb"))
    dist_dictionary = pickle.load(open("dist_dictionary.p", "rb"))

    dst_dictionary = {}
    for tuple_info in dist_dictionary:
        dst = tuple_info.split('-')[1]
        cant = dist_dictionary.get(tuple_info)
        if dst in dst_dictionary:
            original = dst_dictionary.get(dst)
            dst_dictionary[dst] = cant + original
        else:
            dst_dictionary[dst] = cant

    for packet_type in type_dictionary:
        packet_count += type_dictionary.get(packet_type)

    entropy = calculate_packet_entropy()
    entropy_dst = calculate_dst_entropy()
    plot_histogram_types()
    plot_histogram_dst()
    plot_histogram_types_information(entropy)
    plot_histogram_dst_information(entropy_dst)
    plot_network()


def calculate_packet_entropy():
    entropy = 0
    for packet in type_dictionary:
        probability = float(type_dictionary.get(packet)) / packet_count
        log_of_prob = math.log(probability, 2)
        entropy += probability * log_of_prob
    entropy = -entropy
    return entropy


def calculate_dst_entropy():
    entropy = 0
    for dst in dst_dictionary:
        probability = float(dst_dictionary.get(dst)) / type_dictionary.get('2054')
        log_of_prob = math.log(probability, 2)
        entropy += probability * log_of_prob
    entropy = -entropy
    return entropy


def compute_types_information_histogram():
    hist = collections.OrderedDict()
    for packet_type in type_dictionary:
        probability = float(type_dictionary.get(packet_type)) / packet_count
        log_of_prob = math.log(probability, 2) * (-1)
        if packet_type == '2048':
            packet_name = 'IP'
        elif packet_type == '2054':
            packet_name = 'ARP'
        elif packet_type == '34525':
            packet_name = 'IPV6'
        else:
            packet_name = str(packet_type)
        hist[packet_name] = log_of_prob
    return hist


def compute_types_histogram():
    hist = collections.OrderedDict()
    for packet_type in type_dictionary:
        if packet_type == '2048':
            packet_name = 'IP'
        elif packet_type == '2054':
            packet_name = 'ARP'
        elif packet_type == '34525':
            packet_name = 'IPV6'
        else:
            packet_name = str(packet_type)
        hist[packet_name] = type_dictionary.get(packet_type)
    return hist


def compute_dst_information_histogram():
    hist = collections.OrderedDict()
    for dst in dst_dictionary:
        probability = float(dst_dictionary.get(dst)) / type_dictionary.get('2054')
        log_of_prob = math.log(probability, 2) * (-1)
        hist[dst] = log_of_prob
    return hist


def compute_dst_histogram():
    hist = collections.OrderedDict()
    for dst in dst_dictionary:
        hist[dst] = dst_dictionary.get(dst)
    return hist


def plot_histogram_types():
    hist = compute_types_histogram()
    source = 'Source1_' + str(packet_count)
    x, y = [20 * i for i in range(len(hist))], hist.values()
    labels = hist.keys()
    f = plt.figure('hist_{source}'.format(source=source), [16, 9])
    f.subplots_adjust(bottom=0.2)
    plt.xlim([-2, x[-1] + 2])
    plt.bar(x, y, align='center')
    plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
    plt.title('Cantidad de Paquetes Versus Tipos de Paquete:', fontsize=18)
    plt.xlabel("Tipos de Paquete", fontsize=15)
    plt.ylabel("Cantidad de Paquetes", fontsize=18)
    filename = 'histogram_types.png'.format()
    f.savefig(filename)


def plot_histogram_types_information(entropy):
    hist = compute_types_information_histogram()
    source = 'Source2_' + str(packet_count)
    x, y = [20 * i for i in range(len(hist))], hist.values()
    labels = hist.keys()
    f = plt.figure('hist_{source}'.format(source=source), [16, 9])
    f.subplots_adjust(bottom=0.2)
    plt.xlim([-2, x[-1] + 2])
    plt.bar(x, y, align='center', color='green')
    plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
    plt.title('Informacion de Paquete Versus Tipos de Paquete:', fontsize=18)
    plt.xlabel("Tipos de Paquete", fontsize=15)
    plt.ylabel("Informacion de Paquete", fontsize=18)
    plt.axhline(entropy, color='g', label='entropia')
    filename = 'histogram_types_information.png'.format()
    f.savefig(filename)


def plot_histogram_dst_information(entropy):
    hist = compute_dst_information_histogram()
    source = 'Source5_' + str(packet_count)
    x, y = [20 * i for i in range(len(hist))], hist.values()
    labels = hist.keys()
    f = plt.figure('hist_{source}'.format(source=source), [16, 9])
    f.subplots_adjust(bottom=0.2)
    plt.bar(x, y, align='center')
    plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
    plt.title('Informacion de Paquete Versus IPs Destino:', fontsize=18)
    plt.xlabel("IPs Destino", fontsize=15)
    plt.ylabel("Informacion de Paquete", fontsize=18)
    plt.axhline(entropy, color='g', label='entropia')
    filename = 'histogram_dst_information.png'.format()
    f.savefig(filename)


def plot_histogram_dst():
    hist = compute_dst_histogram()
    source = 'Source6_' + str(packet_count)
    x, y = [20 * i for i in range(len(hist))], hist.values()
    labels = hist.keys()
    f = plt.figure('hist_{source}'.format(source=source), [16, 9])
    f.subplots_adjust(bottom=0.2)
    plt.bar(x, y, align='center')
    plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
    plt.title('Cantidad de Paquetes Versus IPs Destino:', fontsize=18)
    plt.xlabel("IPs Destino", fontsize=15)
    plt.ylabel("Cantidad de Paquetes", fontsize=18)
    filename = 'histogram_dst.png'.format()
    f.savefig(filename)


def plot_network():
    graph = pydot.Dot(graph_type='digraph', size="7.75,10.25", fontsize="15.0")
    for dist in dist_dictionary:
        n_from = str(dist.split('-')[0])
        n_to = str(dist.split('-')[1])
        pieces = n_from.split('.')
        n_from = '.'.join(pieces[0:2]) + '\n' + '.'.join(pieces[2:4])
        pieces = n_to.split('.')
        n_to = '.'.join(pieces[0:2]) + '\n' + '.'.join(pieces[2:4])
        label = str(dist_dictionary.get(dist))
        node_from = pydot.Node(n_from, fontsize="20.0")
        node_to = pydot.Node(n_to, fontsize="20.0")
        graph.add_node(node_from)
        graph.add_node(node_to)
        edge = pydot.Edge(n_from, n_to, label=label, color="red", fontsize="18.0", len='3.0')
        graph.add_edge(edge)
    filename = 'network.png'.format(basename='test')
    graph.write_png(filename, prog='neato')


graph_all()
