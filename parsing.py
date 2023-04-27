import sys
import re
from scapy.all import *

pcap_file_path = ""
output_file_path = "./clean_data.txt"

clean_counter = 0
dirty_counter = 0

def parse_pcap(pcap_path):
    global clean_counter
    global dirty_counter
    output_file = open(output_file_path,'wb')
    for packet in PcapReader(pcap_file_path):
        dirty_counter += 1
        fields = []
        try:
            if IP not in packet:
                continue
            fields = [str(packet[IP].src), str(packet[IP].dst), str(packet[IP].proto)]
            if UDP in packet:
                fields.append(str(packet[UDP].sport))
                fields.append(str(packet[UDP].dport))
            elif TCP in packet:
                fields.append(str(packet[TCP].sport))
                fields.append(str(packet[TCP].dport))
            elif ICMP in packet:
                pass
            else: 
                continue            
        except Exception as e:
            pass
        output_file.write(','.join(fields))
        clean_counter += 1
    output_file.close()

if __name__ == "__main__":
    counts = {}
    parse_pcap(pcap_path=pcap_file_path)

    