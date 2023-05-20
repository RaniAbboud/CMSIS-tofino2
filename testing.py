from scapy.all import *
import time
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
import numpy as np

UDP.payload_guess = []
TCP.payload_guess = []
ICMP.payload_guess = []

sketch_name = "CMSIS"
V1 = sketch_name + '-M1'
V2 = sketch_name + '-M2'
V3 = sketch_name + '-M3'
CMS = 'Lite'

pcap_file_path = "/home/srani/caida/caida_part1.pcap"
caida_year = 18
parsed_traces_directory = f'/home/srani/python-simulations/parsed_traces/caida_{caida_year}/'

theta = 1000
trace_prefix_ignore_size = 100000 # 100k
trace_max_size = 10000000 # 10M
batch_size=10000

clean_counter = 0
dirty_counter = 0
real_counts = {}
mse = 0

class SketchStatistics:
    def __init__(self) -> None:
        self.fp_num = 0
        self.tp_num = 0
        self.fn_num = 0
        self.tn_num = 0

stats = {
    CMS: SketchStatistics(),
    V1: SketchStatistics(),
    V2: SketchStatistics(),
    V3: SketchStatistics()
}

def make_key(packet):
    key = f'{packet[IP].src},{packet[IP].dst},{packet[IP].proto}'
    if TCP in packet:
        key = f'{key},{packet[TCP].sport},{packet[TCP].dport}'
    elif UDP in packet:
        key = f'{key},{packet[UDP].sport},{packet[UDP].dport}'
    return key

def sniffer():
    global clean_counter
    global mse
    global stats

    packets=sniff(iface='veth1', filter="ether src cc:cc:cc:cc:cc:cc" , count=batch_size, timeout=60) # only get response packets
    print(f'Received {len(packets)} packets')
    for packet in packets:
        try:
            clean_counter += 1
            flow_id = make_key(packet)
            if flow_id not in real_counts:
                real_counts[flow_id] = 1
            else:
                real_counts[flow_id] += 1
            # Calculate statistics only after inserting {trace_prefix_ignore_size} packets
            if clean_counter < trace_prefix_ignore_size:
                continue
            packet_raw  = b''
            if Raw in packet:
                packet_raw = raw(packet[Raw])
            elif Padding in packet:
                packet_raw = raw(packet[Padding])
            else:
                raise Exception(f'Neither Raw nor Padding exist in packet: {packet}')
            # MSE
            freq_est = int.from_bytes(packet_raw[3:7],byteorder='big')
            mse += (freq_est-real_counts[flow_id])**2
            # HH
            match_count = packet_raw[0]
            hh_label = packet_raw[1] == 1
            flow_inserted = packet_raw[2] == 1
            if real_counts[flow_id] >= clean_counter/theta:
                # Ground truth: HH
                # V1
                if (match_count >= 1 or flow_inserted) and hh_label: 
                    # Correctly classified as HH by our sketch
                    stats[V1].tp_num += 1
                else:
                    # Missed by our sketch
                    stats[V1].fn_num += 1
                # V2
                if (match_count >= 2 or flow_inserted) and hh_label: 
                    # Correctly classified as HH by our sketch
                    stats[V2].tp_num += 1
                else:
                    # Missed by our sketch
                    stats[V2].fn_num += 1
                # V3
                if (match_count >= 3 or flow_inserted) and hh_label: 
                    # Correctly classified as HH by our sketch
                    stats[V3].tp_num += 1
                else:
                    # Missed by our sketch
                    stats[V3].fn_num += 1
                # CMS
                if hh_label:
                    stats[CMS].tp_num += 1
                else:
                    stats[CMS].fn_num += 1
            else:
                # Ground truth: non-HH
                # V1
                if (match_count >= 1 or flow_inserted) and hh_label: 
                    # Incorrectly classified as HH by our sketch
                    stats[V1].fp_num += 1
                else:
                    # Correctly not classified as HH
                    stats[V1].tn_num += 1
                # V2
                if (match_count >= 2 or flow_inserted) and hh_label:
                    # Incorrectly classified as HH by our sketch
                    stats[V2].fp_num += 1
                else:
                    # Correctly not classified as HH
                    stats[V2].tn_num += 1
                # V3
                if (match_count >= 3 or flow_inserted) and hh_label:
                    # Incorrectly classified as HH by our sketch
                    stats[V3].fp_num += 1
                else:
                    # Correctly not classified as HH
                    stats[V3].tn_num += 1
                # CMS
                if hh_label:
                    stats[CMS].fp_num += 1
                else:
                    stats[CMS].tn_num += 1
        except Exception as e:
            print(e)
    try:
        print('clean_counter=',clean_counter)
        print_stats()
    except Exception as e:
        pass
    return
            

def iterate_pcap(pcap_path):
    global dirty_counter
    reader = PcapReader(pcap_file_path)
    clean_batch = []
    while True:
        if clean_counter >= trace_max_size:
            return
        packet = next(reader)
        if packet is None:
            return
        dirty_counter += 1
        fields = []
        try:
            clean_packet = Ether(src='00:11:22:33:44:55', dst='cc:cc:cc:cc:cc:cc', type=0x0800)
            if IP not in packet:
                continue
            clean_packet = clean_packet / IP(src=packet['IP'].src, dst=packet['IP'].dst, proto=packet['IP'].proto)
            if UDP in packet:
                clean_packet = clean_packet / UDP(sport=packet['UDP'].sport,dport=packet['UDP'].dport,len=8)
                clean_packet[IP].len = 28
            elif TCP in packet:
                clean_packet = clean_packet / TCP(sport=packet['TCP'].sport,dport=packet['TCP'].dport)
                clean_packet[IP].len = 40
            elif ICMP in packet:
                clean_packet[IP].len = 28
            else:
                continue
            clean_batch.append(clean_packet)
        except Exception as e:
            print(e)
            continue

        if len(clean_batch) % batch_size == 0:
            try:
                t = threading.Thread(target=sniffer)
                t.start()
                time.sleep(0.5) # to make sure that the sniffer has started sniffing
                # send batch to switch
                sendp(clean_batch, iface='veth1')
                t.join()  # wait until sniffer is done
                clean_batch = []
            except Exception as e:
                print('srp failed:', e)
            print('dirty_counter=', dirty_counter)
            
def print_stats():
    global stats
    global mse
    global clean_counter

    print(f'MSE={mse/clean_counter}') 
    for sketch in [V1,V2,V3,CMS]:
        sketch_stats = stats[sketch]
        fpr = sketch_stats.fp_num/(sketch_stats.fp_num+sketch_stats.tp_num)
        fnr = sketch_stats.fn_num/(sketch_stats.fn_num+sketch_stats.tn_num)
        acc = (sketch_stats.tp_num+sketch_stats.tn_num)/(sketch_stats.fp_num+sketch_stats.fn_num+sketch_stats.tp_num+sketch_stats.tn_num)
        precision = sketch_stats.tp_num/(sketch_stats.tp_num+sketch_stats.fp_num)
        recall = sketch_stats.tp_num/(sketch_stats.tp_num+sketch_stats.fn_num)
        print(f'*** {sketch} ***: FPR={fpr:.5f}, FNR={fnr:.5f}, Accuracy={acc:.5f}, Precision={precision:.5f}, Recall={recall:.5f}')


if __name__ == "__main__":
    iterate_pcap(pcap_path=pcap_file_path)
    print('final dirty_counter=',dirty_counter)
    print('final clean_counter=',clean_counter)

    print_stats()
    
    with open('results.txt', 'w') as f:
        for sketch in [V1,V2,V3,CMS]:
            sketch_stats = stats[sketch]
            f.write(f'*** Sketch {sketch} ***')
            fpr = sketch_stats.fp_num/(sketch_stats.fp_num+sketch_stats.tp_num)
            fnr = sketch_stats.fn_num/(sketch_stats.fn_num+sketch_stats.tn_num)
            acc = (sketch_stats.tp_num+sketch_stats.tn_num)/(sketch_stats.fp_num+sketch_stats.fn_num+sketch_stats.tp_num+sketch_stats.tn_num)
            precision = sketch_stats.tp_num/(sketch_stats.tp_num+sketch_stats.fp_num)
            recall = sketch_stats.tp_num/(sketch_stats.tp_num+sketch_stats.fn_num)
            f.write(f'FPR={fpr}, FNR={fnr}, Accuracy={acc}, Precision={precision}, Recall={recall}\n')
        
    # set width of bar
    barWidth = 0.33
    fig = plt.subplots(figsize =(10, 5))
    
    FPR = [stats[sketch].fp_num/(stats[sketch].fp_num+stats[sketch].tp_num) for sketch in stats.keys()]
    FNR = [stats[sketch].fn_num/(stats[sketch].fn_num+stats[sketch].tn_num) for sketch in stats.keys()]
     
    # Set position of bar on X axis
    br1 = np.arange(len(FPR))
    br2 = [x + barWidth for x in br1]
     
    # Make the plot
    plt.bar(br1, FPR, color ='b', width = barWidth,
            edgecolor ='grey', label ='FPR')
    plt.bar(br2, FNR, color ='r', width = barWidth,
            edgecolor ='grey', label ='FNR')
     
    # Adding Xticks
    plt.xticks([r + barWidth for r in range(len(FPR))],
            [sketch for sketch in stats.keys()], fontsize='medium')
    plt.gca().yaxis.set_major_formatter(PercentFormatter(1))
    plt.title(f"Theta={theta}, |Trace|={clean_counter}")
    plt.legend()
    plt.show(block=True)
    
