## Import Scapy module
from scapy.all import *
import pydot

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

    # Saves to a file the dictionary where it counts the appearences for each type
    string_dictionary = ', '.join("{!s}={!r}".format(k, v) for (k, v) in type_dictionary.items())
    with open('types.txt', 'w') as file_:
        file_.write(string_dictionary)

    if packet_type == '2054':  # ARP
        src = my_packet[ARP].psrc
        dst = my_packet[ARP].pdst
        distinguished_field = src + '-' + dst

        if distinguished_field in dist_dictionary:
            dist_dictionary[distinguished_field] += 1
        else:
            dist_dictionary[distinguished_field] = 1

        # Saves to a file the dictionary where it counts the appearences for each distinguished field
        string_dist_dictionary = ', '.join("{!s}={!r}".format(k, v) for (k, v) in dist_dictionary.items())
        with open('dist.txt', 'w') as file_:
            file_.write(string_dist_dictionary)

    if packetCount == 5000:
        plot_network()

    return return_value


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