## Import Scapy module
from scapy.all import *
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
        distinguished_field = my_packet[ARP].pdst

        if distinguished_field in dist_dictionary:
            dist_dictionary[distinguished_field] += 1
        else:
            dist_dictionary[distinguished_field] = 1

        # Saves to a file the dictionary where it counts the appearences for each distinguished field
        string_dist_dictionary = ', '.join("{!s}={!r}".format(k, v) for (k, v) in dist_dictionary.items())
        with open('dist.txt', 'w') as file_:
            file_.write(string_dist_dictionary)

    return return_value

## Setup sniff
sniff(prn=action_only_type)