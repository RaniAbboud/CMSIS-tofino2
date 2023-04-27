from scapy.all import *
import time

UDP.payload_guess = []
TCP.payload_guess = []
ICMP.payload_guess = []

pcap_file_path = "/home/srani/caida/caida_part1.pcap"

theta = 2048
trace_prefix_ignore_size = 1000000
trace_max_size = 3000000
required_matches_for_hh = 2
batch_size=1000

clean_counter = 0
dirty_counter = 0
real_counts = {}
mse = 0

fp_num = 0
tp_num = 0
fn_num = 0
tn_num = 0

fp_num_v2 = 0
tp_num_v2 = 0
fn_num_v2 = 0
tn_num_v2 = 0

fp_num_cms = 0
tp_num_cms = 0
fn_num_cms = 0
tn_num_cms = 0

def make_key(packet):
    key = f'{packet[IP].src},{packet[IP].dst,{packet[IP].proto}}'
    if TCP in packet:
        key = f'{key},{packet[TCP].sport},{packet[TCP].dport}'
    elif UDP in packet:
        key = f'{key},{packet[UDP].sport},{packet[UDP].dport}'
    return key

def sniffer():
    global clean_counter
    global mse
    global fp_num
    global tp_num
    global fn_num
    global tn_num

    global fp_num_v2
    global tp_num_v2
    global fn_num_v2
    global tn_num_v2

    global fp_num_cms
    global tp_num_cms
    global fn_num_cms
    global tn_num_cms

    packets=sniff(iface='veth1', filter="ether src cc:cc:cc:cc:cc:cc" , count=batch_size, timeout=10) # only get response packets
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
            freq_est = int.from_bytes(packet_raw[2:6],byteorder='big')
            mse += (freq_est-real_counts[flow_id])**2
            # HH
            match_count = packet_raw[0]
            hh_label = packet_raw[1] == 1
            if real_counts[flow_id] >= clean_counter/theta:
                # Ground truth: HH
                if match_count >= required_matches_for_hh: 
                    # Correctly classified as HH by our sketch
                    tp_num += 1
                else:
                    # Missed by our sketch
                    fn_num += 1
                # V2
                if match_count >= required_matches_for_hh and hh_label: 
                    # Correctly classified as HH by our sketch
                    tp_num_v2 += 1
                else:
                    # Missed by our sketch
                    fn_num_v2 += 1
                # CMS
                if hh_label:
                    tp_num_cms += 1
                else:
                    fn_num_cms += 1
            else:
                # Ground truth: non-HH
                if match_count >= required_matches_for_hh: 
                    # Incorrectly classified as HH by our sketch
                    fp_num += 1
                else:
                    # Correctly not classified as HH
                    tn_num += 1
                # V2
                if match_count >= required_matches_for_hh and hh_label:
                    # Incorrectly classified as HH by our sketch
                    fp_num_v2 += 1
                else:
                    # Correctly not classified as HH
                    tn_num_v2 += 1            
                # CMS
                if hh_label:
                    fp_num_cms += 1
                else:
                    tn_num_cms += 1
        except Exception as e:
            print(e)
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
                time.sleep(0.2) # to make sure that the sniffer has started sniffing
                # send batch to switch
                sendp(clean_batch, iface='veth1')
                t.join()  # wait until sniffer is done
                clean_batch = []
            except Exception as e:
                print('srp failed:', e)

            print('dirty_counter=', dirty_counter)

if __name__ == "__main__":
    iterate_pcap(pcap_path=pcap_file_path)
    print('final dirty_counter=',dirty_counter)
    print('final clean_counter=',clean_counter)

    print('*** Our Sketch ***')
    print('MSE=',mse/clean_counter)
    print('FPR=',fp_num/(fp_num+tp_num))
    print('FNR=',fn_num/(fn_num+tn_num))

    print('*** Our Sketch V2 ***')
    print('FPR=',fp_num_v2/(fp_num_v2+tp_num_v2))
    print('FNR=',fn_num_v2/(fn_num_v2+tn_num_v2))

    print('*** CMS ***')
    print('FPR=',fp_num_cms/(fp_num_cms+tp_num_cms))
    print('FNR=',fn_num_cms/(fn_num_cms+tn_num_cms))

    

    
