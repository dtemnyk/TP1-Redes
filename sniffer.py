## Import Scapy module
from scapy.all import *
import pydot
import pickle
import matplotlib.pyplot as plt
import collections

## Create a Packet Count var
packetCount = 0
type_dictionary = {}
dist_dictionary = {}
dst_dictionary = {}
source_dictionary = {}


## Define our Custom Action function
def action_only_type(my_packet):
    global packetCount
    global type_dictionary
    global dist_dictionary
    global dst_dictionary
    global source_dictionary
    packetCount += 1

    if hasattr(my_packet[0], 'type'):
        packet_type = str(my_packet[0].type)
        return_value = "Packet #%s: Type %s" % (packetCount, my_packet[0].type)
    else:
        packet_type = 'LLC'
        return_value = 'LLC'

    if packet_type in type_dictionary:
        type_dictionary[packet_type] += 1
    else:
        type_dictionary[packet_type] = 1

    if packet_type == '2054':  # ARP
        src = my_packet[ARP].psrc
        dst = my_packet[ARP].pdst
        distinguished_field = src + '-' + dst

        if distinguished_field in dist_dictionary:
            dist_dictionary[distinguished_field] += 1
        else:
            dist_dictionary[distinguished_field] = 1

    if packetCount % 1000 == 0:
        string_dictionary = ', '.join("{!s}={!r}".format(k, v) for (k, v) in type_dictionary.items())
        with open('types.txt', 'w') as file_:
            file_.write(string_dictionary)
        pickle.dump(type_dictionary, open("type_dictionary.p", "wb"))

        string_dist_dictionary = ', '.join("{!s}={!r}".format(k, v) for (k, v) in dist_dictionary.items())
        with open('dist.txt', 'w') as file_:
            file_.write(string_dist_dictionary)
        pickle.dump(dist_dictionary, open("dist_dictionary.p", "wb"))

#calculo source dictionary
        
        for dist in dist_dictionary:
            source = dist.split('-')[0]
            if source in source_dictionary:
                source_dictionary[source] += dist_dictionary.get(dist)
            else:
                source_dictionary[source] = dist_dictionary.get(dist)

#calculo dst dictionary
        
        for dist in dist_dictionary:
            dst = dist.split('-')[1]
            if dst in dst_dictionary:
                dst_dictionary[dst] += dist_dictionary.get(dist)
            else:
                dst_dictionary[dst] = dist_dictionary.get(dist)

        plot_network()
        entropy = calculate_entropy(type_dictionary)
        entropy_source = calculate_entropy(source_dictionary)
        entropy_dst = calculate_entropy(dst_dictionary)
        plot_histogram_types()
        plot_histogram_source()
        plot_histogram_dst()
        plot_histogram_types_information(entropy)
        plot_histogram_source_information(entropy_source)
        plot_histogram_dst_information(entropy_dst)

    return return_value


def calculate_entropy(dictionary):
    entropy = 0
    for packet in dictionary:
        probability = float(dictionary.get(packet)) / packetCount
        log_of_prob = math.log(probability, 2)
        entropy += probability * log_of_prob
    entropy = -entropy
    print('Entropy: ' + str(entropy))
    return entropy


def compute_types_information_histogram():
    hist = collections.OrderedDict()
    for packet_type in type_dictionary:
        probability = float(type_dictionary.get(packet_type)) / packetCount
        log_of_prob = math.log(probability, 2) * (-1)
        hist[packet_type] = log_of_prob
    return hist


def compute_types_histogram():
    hist = collections.OrderedDict()
    for packet_type in type_dictionary:
        hist[packet_type] = type_dictionary.get(packet_type)
    return hist


def compute_source_information_histogram():
    hist = collections.OrderedDict()
    for source in source_dictionary:
        probability = float(source_dictionary.get(source)) / packetCount
        log_of_prob = math.log(probability, 2) * (-1)
        hist[source] = log_of_prob
    return hist


def compute_source_histogram():
    hist = collections.OrderedDict()
    for source in source_dictionary:
        hist[source] = source_dictionary.get(source)
    return hist


def compute_dst_information_histogram():
    hist = collections.OrderedDict()
    for dst in dst_dictionary:
        probability = float(dst_dictionary.get(dst)) / packetCount
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
    basename = 'TiposCantidad'
    source = 'Source1_' + str(packetCount)
    x, y = [20 * i for i in range(len(hist))], hist.values()
    labels = hist.keys()
    f = plt.figure('hist_{source}'.format(source=source), [16, 9])
    f.subplots_adjust(bottom=0.2)
    plt.xlim([-2, x[-1] + 2])
    plt.bar(x, y, align='center')
    plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
    plt.title('Cant. Tipos: {source}'.format(source=source), fontsize=18)
    plt.xlabel("Tipos", fontsize=15)
    plt.ylabel("Cantidad", fontsize=18)
    filename = 'imgs/{basename}_hist.png'.format(basename=basename)
    f.savefig(filename)


def plot_histogram_types_information(entropy):
    hist = compute_types_information_histogram()
    basename = 'TiposInformacion'
    source = 'Source2_' + str(packetCount)
    x, y = [20 * i for i in range(len(hist))], hist.values()
    labels = hist.keys()
    f = plt.figure('hist_{source}'.format(source=source), [16, 9])
    f.subplots_adjust(bottom=0.2)
    plt.xlim([-2, x[-1] + 2])
    plt.bar(x, y, align='center')
    plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
    plt.title('Cant. Tipos: {source}'.format(source=source), fontsize=18)
    plt.xlabel("Tipos", fontsize=15)
    plt.ylabel("Informacion", fontsize=18)
    plt.axhline(entropy, color='r', label='entropia')
    filename = 'imgs/{basename}_hist.png'.format(basename=basename)
    f.savefig(filename)


def plot_histogram_source():
    hist = compute_source_histogram()
    basename = 'CantIPFuenteCantidad'
    source = 'Source3_' + str(packetCount)
    x, y = [20 * i for i in range(len(hist))], hist.values()
    labels = hist.keys()
    f = plt.figure('hist_{source}'.format(source=source), [16, 9])
    f.subplots_adjust(bottom=0.2)
    plt.bar(x, y, align='center')
    plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
    plt.title('Cant. IPs Fuente: {source}'.format(source=source), fontsize=18)
    plt.xlabel("IPs Fuente", fontsize=15)
    plt.ylabel("Cantidad", fontsize=18)
    filename = 'imgs/{basename}_hist.png'.format(basename=basename)
    f.savefig(filename)


def plot_histogram_source_information(entropy):
    hist = compute_source_information_histogram()
    basename = 'CantIPFuenteInformacion'
    source = 'Source4_' + str(packetCount)
    x, y = [20 * i for i in range(len(hist))], hist.values()
    labels = hist.keys()
    f = plt.figure('hist_{source}'.format(source=source), [16, 9])
    f.subplots_adjust(bottom=0.2)
    plt.bar(x, y, align='center')
    plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
    plt.title('Cant. IPs Fuente: {source}'.format(source=source), fontsize=18)
    plt.xlabel("IPs Fuente", fontsize=15)
    plt.ylabel("Informacion", fontsize=18)
    plt.axhline(entropy, color='r', label='entropia')
    filename = 'imgs/{basename}_hist.png'.format(basename=basename)
    f.savefig(filename)


def plot_histogram_dst_information(entropy):
    hist = compute_dst_information_histogram()
    basename = 'CantIPDestinoInformacion'
    source = 'Source5_' + str(packetCount)
    x, y = [20 * i for i in range(len(hist))], hist.values()
    labels = hist.keys()
    f = plt.figure('hist_{source}'.format(source=source), [16, 9])
    f.subplots_adjust(bottom=0.2)
    plt.bar(x, y, align='center')
    plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
    plt.title('Cant. IPs Destino: {source}'.format(source=source), fontsize=18)
    plt.xlabel("IPs Destino", fontsize=15)
    plt.ylabel("Informacion", fontsize=18)
    plt.axhline(entropy, color='r', label='entropia')
    filename = 'imgs/{basename}_hist.png'.format(basename=basename)
    f.savefig(filename)


def plot_histogram_dst():
    hist = compute_dst_histogram()
    basename = 'CantIPDestinoCantidad'
    source = 'Source6_' + str(packetCount)
    x, y = [20 * i for i in range(len(hist))], hist.values()
    labels = hist.keys()
    f = plt.figure('hist_{source}'.format(source=source), [16, 9])
    f.subplots_adjust(bottom=0.2)
    plt.bar(x, y, align='center')
    plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
    plt.title('Cant. IPs Destino: {source}'.format(source=source), fontsize=18)
    plt.xlabel("IPs Destino", fontsize=15)
    plt.ylabel("Cantidad", fontsize=18)
    filename = 'imgs/{basename}_hist.png'.format(basename=basename)
    f.savefig(filename)


def plot_network():
    graph = pydot.Dot(graph_type='digraph', size="7.75,10.25")
    for dist in dist_dictionary:
        n_from = str(dist.split('-')[0])
        n_to = str(dist.split('-')[1])
        pieces = n_from.split('.')
        n_from = '.'.join(pieces[0:2]) + '\n' + '.'.join(pieces[2:4])
        pieces = n_to.split('.')
        n_to = '.'.join(pieces[0:2]) + '\n' + '.'.join(pieces[2:4])
        label = str(dist_dictionary.get(dist))
        edge = pydot.Edge(n_from, n_to, label=label, color="blue", fontsize="6.0", len='3.0')
        graph.add_edge(edge)
    filename = 'imgs/Network.png'.format(basename='test')
    graph.write_png(filename, prog='neato')

## Setup sniff
sniff(prn=action_only_type, store=0)