## Import Scapy module
from scapy.all import *
import pickle

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
        with open('output/types.txt', 'w') as file_:
            file_.write(string_dictionary)
        pickle.dump(type_dictionary, open("output/type_dictionary.p", "wb"))

        string_dist_dictionary = ', '.join("{!s}={!r}".format(k, v) for (k, v) in dist_dictionary.items())
        with open('output/dist.txt', 'w') as file_:
            file_.write(string_dist_dictionary)
        pickle.dump(dist_dictionary, open("output/dist_dictionary.p", "wb"))

    return return_value


## Setup sniff
sniff(prn=action_only_type, store=0)