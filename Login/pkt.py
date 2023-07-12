#pip install seaborn
#pip install scapy

from scapy.all import *
import pandas as pd
import numpy as np
import binascii
import seaborn as sns
import django.db
import models


def manipulation(request):
    sns.set(color_codes=True)
    #%matplotlib inline

    '''Use common fields in IP Packet to perform exploratory analysis on PCAP'''

    num_of_packets_to_sniff = 100
    pcap = sniff(count=num_of_packets_to_sniff)

    # rdpcap returns packet list
    ## packetlist object can be enumerated
    print(type(pcap))
    print(len(pcap))
    print(pcap[0])

    #from google.colab import files
    #uploaded = files.upload()

    # rdpcap used to Read Pcap
    pcap = pcap + rdpcap("example1.pcap")
    print(pcap)

    # ETHERNET -> Internet Protocol -> Layer 4 Segments
    # We're only interested in Layers 3 (IP) and 4 (TCP AND UDP)
    ## We'll parse those two layers and the layer 4 payload
    ## When capturing we capture layer 2 frames and beyond

    # Retrieving a single item from packet list
    ethernet_frame = pcap[101]
    ip_packet = ethernet_frame.payload
    segment = ip_packet.payload
    data = segment.payload # Retrieve payload that comes after layer 4

    # Observe that we just popped off previous layer header
    print(ethernet_frame.summary())
    print(ip_packet.summary())
    print(segment.summary())
    print(data.summary()) # If blank, empty object

    # Complete depiction of packet
    ethernet_frame.show()

    # Understanding the object types in Scapy
    print(type(ethernet_frame))
    print(type(ip_packet))
    print(type(segment))

    # Packets can be filtered on layers, e.g., ethernet_frame[scapy.layers.l2.Ether]
    ethernet_type = type(ethernet_frame)
    ip_type = type(ip_packet)
    tcp_type = type(segment)
    print("Ethernet", pcap[ethernet_type])
    print("IP", pcap[ip_type])
    print("TCP", pcap[tcp_type])

    # Scapy provides this via import statements
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP
    print("UDP", pcap[UDP])

    # Collect field names from IP/TCP/UDP (These will be columns in DF)
    ip_fields = [field.name for field in IP().fields_desc]
    tcp_fields = [field.name for field in TCP().fields_desc]
    udp_fields = [field.name for field in UDP().fields_desc]
    dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload', 'payload_raw', 'payload_hex']

    # Create blank DataFrame
    df = pd.DataFrame(columns=dataframe_fields)

    for packet in pcap[IP]:
        # Field array for each row of DataFrame
        field_values = []
        
        # Add all IP fields to dataframe
        for field in ip_fields:
            if field == 'options':
                # Retrieving number of options defined in IP Header
                field_values.append(len(packet[IP].fields[field]))
            else:
                field_values.append(packet[IP].fields[field])
                
        field_values.append(packet.time)
        layer_type = type(packet[IP].payload)
        
        for field in tcp_fields:
            try:
                if field == 'options':
                    field_values.append(len(packet[layer_type].fields[field]))
                else:
                    field_values.append(packet[layer_type].fields[field])
            except:
                field_values.append(None)
        
        # Append payload
        field_values.append(len(packet[layer_type].payload))
        field_values.append(packet[layer_type].payload.original)
        field_values.append(binascii.hexlify(packet[layer_type].payload.original))

        # Append the field values as a new row in the DataFrame
        df = df.append(pd.DataFrame([field_values], columns=dataframe_fields), ignore_index=True)