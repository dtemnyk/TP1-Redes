## Import Scapy module
from scapy.all import *
import pydot
import pickle
import matplotlib.pyplot as plt

## Create a Packet Count var
packetCount = 0
type_dictionary = {}
dist_dictionary = {}


## Define our Custom Action function
def action_only_type(my_packet):
    global packetCount
    global type_dictionary
    global dist_dictionary
    packetCount += 1

    if hasattr(my_packet[0], 'type'):
        packet_type = str(my_packet[0].type)
        return_value = "Packet #%s: Type %s" % (packetCount, my_packet[0].type)
    else:
        packet_type = 'LLC'
        return_value = my_packet.show()

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

        plot_network()
        calculate_entropy()
        plot_histogram()

    return return_value


def calculate_entropy():
    entropy = 0
    for packet_type in type_dictionary:
        probability = float(type_dictionary.get(packet_type)) / packetCount
        log_of_prob = math.log(probability, 2)
        entropy += probability * log_of_prob
    entropy = -entropy
    print('Entropy: ' + str(entropy))
    return entropy


def compute_histogram():
    hist = collections.OrderedDict()
    for packet_type in type_dictionary:
        hist[packet_type] = type_dictionary.get(packet_type)
    return hist


def plot_histogram():
    hist = compute_histogram()
    basename = 'Basename'
    source = 'Source'
    x, y = [20 * i for i in range(len(hist))], hist.values()
    labels = hist.keys()
    f = plt.figure('hist_{source}'.format(source=source), [16, 9])
    f.subplots_adjust(bottom=0.2)
    plt.xlim([-2, x[-1] + 2])
    plt.bar(x, y, align='center')
    plt.xticks(x, labels, size='small', rotation='vertical', fontsize=18)
    plt.title('Cant. Tipos: {source}'.format(source=source), fontsize=18)
    plt.xlabel("IP", fontsize=15)
    plt.ylabel("Cantidad de Tipos", fontsize=18)
    f.savefig('imgs/{basename}_{source}_hist.png'.format(basename=basename, source=source))


def plot_network():
    graph = pydot.Dot(graph_type='digraph')
    for dist in dist_dictionary:
        n_from = str(dist.split('-')[0])
        n_to = str(dist.split('-')[1])
        label = str(dist_dictionary.get(dist))
        edge = pydot.Edge(n_from, n_to, label=label, color="blue")
        graph.add_edge(edge)
    graph.write_png('imgs/test.png'.format(basename='test'), prog='neato')

## Setup sniff
sniff(prn=action_only_type)