/* -*- P4_16 -*- */
#include <core.p4>
#include <t2na.p4>

/* CONSTANTS */
#define COUNTER_ARRAY_SIZE 16384
#define COUNTER_ARRAY_INDEX_BITS 14
#define ID_ARRAY_SIZE 256
#define ID_ARRAY_INDEX_BITS 8

#define HASH_WIDTH_COUNT_STAGE 16
#define HASH_WIDTH_ID_STAGE 16

#define ID_REG_SIZE_BITS 64

#define THETA 1000

#define INSERTION_PROB_BITS 7

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

header ethernet_h {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16> ether_type;
}

header sketch_t {
    bit<8> flow_id_match_count;
    bit<8> threshold_passed;
    bit<8> inserted;
    bit<32> freq_estimation;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    sketch_t         sketch;
}

// Utility struct used to define registers that hold pairs of values 
struct pair {
    bit<32> high;
    bit<32> low;
}

/*
 * All metadata, globally used in the program, also  needs to be assembled
 * into a single struct. As in the case of the headers, we only need to
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
@flexible 
struct metadata_t {
    bit<INSERTION_PROB_BITS> random_number;
    // indexes
    bit<COUNTER_ARRAY_INDEX_BITS> count_way1_index;
    bit<COUNTER_ARRAY_INDEX_BITS> count_way2_index;
    bit<ID_ARRAY_INDEX_BITS> id_stage1_index;
    // 128-bit flow ID
    bit<ID_REG_SIZE_BITS> flow_id_stage1_part1_old;
    bit<ID_REG_SIZE_BITS> flow_id_stage1_part2_old;
    bit<ID_REG_SIZE_BITS> flow_id_stage2_part1_old;
    bit<ID_REG_SIZE_BITS> flow_id_stage2_part2_old;
  
    bit<ID_REG_SIZE_BITS> flow_id_part1_original; // used as a constant
    bit<ID_REG_SIZE_BITS> flow_id_part2_original; // used as a constant

    bool flow_id_stage1_part1_match;
    bool flow_id_stage1_part2_match;
    bool flow_id_stage2_part1_match;
    bool flow_id_stage2_part2_match;
    bool flow_id_stage3_part1_match;
    bool flow_id_stage3_part2_match;

    // bool should_replace;
    bool stage1_count_ok;
    bool stage2_count_ok;

    int<32> insertion_threshold;

    bit<8> flow_id_match_count;
}

#include "./common/util.p4"

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser IngressParser(packet_in packet,
                out header_t hdr,
                out metadata_t ig_md,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(packet, ig_intr_md);
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        /***********   Initializations   ***********/
        ig_md.flow_id_part1_original = hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr;
        // default values for `flow_id_stage{1/2}_part{1/2}` are later used in hash/index calculations
        ig_md.flow_id_stage1_part1_old = hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr;
        ig_md.flow_id_stage2_part1_old = hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr;

        ig_md.flow_id_part2_original= (bit<ID_REG_SIZE_BITS>)hdr.ipv4.protocol;
        ig_md.flow_id_stage1_part2_old= (bit<ID_REG_SIZE_BITS>)hdr.ipv4.protocol;
        ig_md.flow_id_stage2_part2_old= (bit<ID_REG_SIZE_BITS>)hdr.ipv4.protocol;

        ig_md.flow_id_stage1_part1_match = false;
        ig_md.flow_id_stage1_part2_match = false;
        ig_md.flow_id_stage2_part1_match = false;
        ig_md.flow_id_stage2_part2_match = false;
        ig_md.flow_id_stage3_part1_match = false;
        ig_md.flow_id_stage3_part2_match = false;

        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        ig_md.flow_id_part2_original[63:32]= hdr.tcp.src_port ++ hdr.tcp.dst_port;
        ig_md.flow_id_stage1_part2_old[63:32]= hdr.tcp.src_port ++ hdr.tcp.dst_port;
        ig_md.flow_id_stage2_part2_old[63:32]= hdr.tcp.src_port ++ hdr.tcp.dst_port;
        transition accept;
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
        ig_md.flow_id_part2_original[63:32]= hdr.udp.src_port ++ hdr.udp.dst_port;
        ig_md.flow_id_stage1_part2_old[63:32]= hdr.udp.src_port ++ hdr.udp.dst_port;
        ig_md.flow_id_stage2_part2_old[63:32]= hdr.udp.src_port ++ hdr.udp.dst_port;
        transition accept;
    }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control Ingress(inout header_t hdr,
                  inout metadata_t ig_md,
                  in ingress_intrinsic_metadata_t ig_intr_md,
                  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                  inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    /************************************************************
     ****************  REGISTER DEFINITIONS   *******************
     ************************************************************/
    Random<bit<INSERTION_PROB_BITS>>() random_number_generator;
    Hash<bit<HASH_WIDTH_COUNT_STAGE>>(HashAlgorithm_t.CRC16) hash_count_way1; // crc_16
    Hash<bit<HASH_WIDTH_COUNT_STAGE>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(0x0589, false, false, false, 0x0001, 0x0001)) hash_count_way2; // crc_16_dect
    Hash<bit<HASH_WIDTH_ID_STAGE>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(0x8005, true, false, false, 0x0, 0x0)) hash_id_stage1; 
    Hash<bit<HASH_WIDTH_ID_STAGE>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(0x8BB7, false, false, false, 0x0001, 0x0001)) hash_id_stage2;
    Hash<bit<HASH_WIDTH_ID_STAGE>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(0x3D65, true, false, false, 0xFFFF, 0xFFFF)) hash_id_stage3; // crc_16_dnp

    DirectRegister<pair>({0,0}) packet_counter;
    DirectRegisterAction<pair,bit<32>>(packet_counter) inc_packet_counter_get_threshold = {
        void apply(inout pair value, out bit<32> rv) {
            if(value.low == THETA-1){
                value.high = value.high |+| 1;
                value.low = 0;
            } else {
                value.low = value.low |+| 1;
            }
            rv = value.high;
        }
    };

    Register<int<32>,bit<COUNTER_ARRAY_INDEX_BITS>>(COUNTER_ARRAY_SIZE, 0) reg_counters_stage1;
    RegisterAction2<int<32>,_,int<32>,bool>(reg_counters_stage1) inc_counter_and_read_stage1 = {
        void apply(inout int<32> value, out int<32> count, out bool flag) {
            value = value |+| 1;
            count = value;
            if(value >= ig_md.insertion_threshold){
                flag = true;
            } else {
                flag = false;
            }
        }
    };

    Register<int<32>,bit<COUNTER_ARRAY_INDEX_BITS>>(COUNTER_ARRAY_SIZE, 0) reg_counters_stage2;
    RegisterAction2<int<32>,_,int<32>,bool>(reg_counters_stage2) inc_counter_and_read_stage2 = {
        void apply(inout int<32> value,out int<32> count, out bool flag) {
            value = value |+| 1;
            count = value;
            if(value >= ig_md.insertion_threshold){
                flag = true;
            } else {
                flag = false;
            }
        }
    };

    // ID Stage #1
    Register<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>>(ID_ARRAY_SIZE, 0) reg_flow_id_stage1_part1;
    Register<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>>(ID_ARRAY_SIZE, 0) reg_flow_id_stage1_part2;
    // ID Stage #2
    Register<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>>(ID_ARRAY_SIZE, 0) reg_flow_id_stage2_part1;
    Register<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>>(ID_ARRAY_SIZE, 0) reg_flow_id_stage2_part2;
    // ID Stage #3
    Register<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>>(ID_ARRAY_SIZE, 0) reg_flow_id_stage3_part1;
    Register<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>>(ID_ARRAY_SIZE, 0) reg_flow_id_stage3_part2;

    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>, bit<ID_REG_SIZE_BITS>>(reg_flow_id_stage1_part1) replace_flow_id_stage1_part1 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value, out bit<ID_REG_SIZE_BITS> old_flow_id_part){
            old_flow_id_part = value;
            value = ig_md.flow_id_part1_original;
        }
    };
    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>,bool>(reg_flow_id_stage1_part1) match_flow_id_stage1_part1 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value, out bool match){
            if(value == ig_md.flow_id_part1_original){
                match = true;
            } else {
                match = false;
            }
        }
    };
    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>, bit<ID_REG_SIZE_BITS>>(reg_flow_id_stage1_part2) replace_flow_id_stage1_part2 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value, out bit<ID_REG_SIZE_BITS> old_flow_id_part){ 
            old_flow_id_part = value; 
            value = ig_md.flow_id_part2_original; 
        }
    }; 
    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>,bool>(reg_flow_id_stage1_part2) match_flow_id_stage1_part2 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value, out bool match){
            if(value == ig_md.flow_id_part2_original){
                match = true;
            } else {
                match = false;
            }
        }
    };

    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>,bit<ID_REG_SIZE_BITS>>(reg_flow_id_stage2_part1) replace_flow_id_stage2_part1 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value, out bit<ID_REG_SIZE_BITS> old_flow_id_part){ 
            old_flow_id_part = value; 
            value = ig_md.flow_id_stage1_part1_old; 
        }
    };
    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>,bool>(reg_flow_id_stage2_part1) match_flow_id_stage2_part1 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value, out bool match){
            if(value == ig_md.flow_id_part1_original){
                match = true;
            } else {
                match = false;
            }
        }
    };
    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>,bit<ID_REG_SIZE_BITS>>(reg_flow_id_stage2_part2) replace_flow_id_stage2_part2 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value, out bit<ID_REG_SIZE_BITS> old_flow_id_part){ 
            old_flow_id_part = value; 
            value = ig_md.flow_id_stage1_part2_old; 
        }
    };
    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>,bool>(reg_flow_id_stage2_part2) match_flow_id_stage2_part2 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value, out bool match){
            if(value == ig_md.flow_id_part2_original){
                match = true;
            } else {
                match = false;
            }
        }
    };

    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>,bit<ID_REG_SIZE_BITS>>(reg_flow_id_stage3_part1) replace_flow_id_stage3_part1 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value){ 
            value = ig_md.flow_id_stage2_part1_old; 
        }
    };
    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>,bool>(reg_flow_id_stage3_part1) match_flow_id_stage3_part1 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value, out bool match){
            if(value == ig_md.flow_id_part1_original){
                match = true;
            } else {
                match = false;
            }
        }
    };
    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>,bit<ID_REG_SIZE_BITS>>(reg_flow_id_stage3_part2) replace_flow_id_stage3_part2 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value){ 
            value = ig_md.flow_id_stage2_part2_old; 
        }
    };
    RegisterAction<bit<ID_REG_SIZE_BITS>,bit<ID_ARRAY_INDEX_BITS>,bool>(reg_flow_id_stage3_part2) match_flow_id_stage3_part2 = { 
        void apply(inout bit<ID_REG_SIZE_BITS> value, out bool match){
            if(value == ig_md.flow_id_part2_original){
                match = true;
            } else {
                match = false;
            }
        }
    };

    action generate_random_number() {
        ig_md.random_number = random_number_generator.get();
    }

    /************ Count stages indices calculation ************/
    action get_count_way1_hash(){
        ig_md.count_way1_index = (bit<COUNTER_ARRAY_INDEX_BITS>)hash_count_way1.get({ 
            ig_md.flow_id_part1_original,
            ig_md.flow_id_part2_original
        });
    }
    action get_count_way2_hash(){
        ig_md.count_way2_index = (bit<COUNTER_ARRAY_INDEX_BITS>)hash_count_way2.get({ 
            ig_md.flow_id_part1_original,
            ig_md.flow_id_part2_original
        });
    }
    /************  ID stages indices calculation  ************/
    action get_id_stage1_hash(){
        ig_md.id_stage1_index = (bit<ID_ARRAY_INDEX_BITS>)hash_id_stage1.get({ 
            ig_md.flow_id_part1_original,
            ig_md.flow_id_part2_original
        });
    }

    action stage2_replace_part1(){
        bit<ID_ARRAY_INDEX_BITS> id_stage2_index = (bit<ID_ARRAY_INDEX_BITS>)hash_id_stage2.get({ 
            ig_md.flow_id_stage1_part1_old,
            ig_md.flow_id_stage1_part2_old
        });
        ig_md.flow_id_stage2_part1_old=replace_flow_id_stage2_part1.execute(id_stage2_index);
    }
    action stage2_replace_part2(){
        bit<ID_ARRAY_INDEX_BITS> id_stage2_index = (bit<ID_ARRAY_INDEX_BITS>)hash_id_stage2.get({ 
            ig_md.flow_id_stage1_part1_old,
            ig_md.flow_id_stage1_part2_old
        });
        ig_md.flow_id_stage2_part2_old=replace_flow_id_stage2_part2.execute(id_stage2_index);
    }

    action stage2_match_part1(){
        bit<ID_ARRAY_INDEX_BITS> id_stage2_index = (bit<ID_ARRAY_INDEX_BITS>)hash_id_stage2.get({ 
            ig_md.flow_id_stage1_part1_old,
            ig_md.flow_id_stage1_part2_old
        });
        ig_md.flow_id_stage2_part1_match=match_flow_id_stage2_part1.execute(id_stage2_index);
    }
    action stage2_match_part2(){
        bit<ID_ARRAY_INDEX_BITS> id_stage2_index = (bit<ID_ARRAY_INDEX_BITS>)hash_id_stage2.get({ 
            ig_md.flow_id_stage1_part1_old,
            ig_md.flow_id_stage1_part2_old
        });
        ig_md.flow_id_stage2_part2_match=match_flow_id_stage2_part2.execute(id_stage2_index);
    }

    action stage3_replace_part1(){
        bit<ID_ARRAY_INDEX_BITS> id_stage3_index = (bit<ID_ARRAY_INDEX_BITS>)hash_id_stage3.get({ 
            ig_md.flow_id_stage2_part1_old,
            ig_md.flow_id_stage2_part2_old 
        });
        replace_flow_id_stage3_part1.execute(id_stage3_index);
    }
    action stage3_replace_part2(){
        bit<ID_ARRAY_INDEX_BITS> id_stage3_index = (bit<ID_ARRAY_INDEX_BITS>)hash_id_stage3.get({ 
            ig_md.flow_id_stage2_part1_old,
            ig_md.flow_id_stage2_part2_old 
        });
        replace_flow_id_stage3_part2.execute(id_stage3_index);
    }

    action stage3_match_part1(){
        bit<ID_ARRAY_INDEX_BITS> id_stage3_index = (bit<ID_ARRAY_INDEX_BITS>)hash_id_stage3.get({ 
            ig_md.flow_id_stage2_part1_old,
            ig_md.flow_id_stage2_part2_old 
        });
        ig_md.flow_id_stage3_part1_match=match_flow_id_stage3_part1.execute(id_stage3_index);
    }
    action stage3_match_part2(){
        bit<ID_ARRAY_INDEX_BITS> id_stage3_index = (bit<ID_ARRAY_INDEX_BITS>)hash_id_stage3.get({ 
            ig_md.flow_id_stage2_part1_old,
            ig_md.flow_id_stage2_part2_old 
        });
        ig_md.flow_id_stage3_part2_match=match_flow_id_stage3_part2.execute(id_stage3_index);
    }

    action send_back() {
        bit<48> tmp;

        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;

        /* Send the packet back to the port it came from */
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    apply {
        ig_md.flow_id_match_count = 0;
        get_id_stage1_hash();
        get_count_way1_hash();
        get_count_way2_hash();
        @stage(0){
            ig_md.insertion_threshold = (int<32>)inc_packet_counter_get_threshold.execute();
        }
        int<32> stage1_count;
        int<32> stage2_count;
        @stage(1){
            stage1_count = inc_counter_and_read_stage1.execute(ig_md.count_way1_index, ig_md.stage1_count_ok);
            stage2_count = inc_counter_and_read_stage2.execute(ig_md.count_way2_index, ig_md.stage2_count_ok);
        }
        // choose the minimum count value as the frequency estimation
        hdr.sketch.freq_estimation = (bit<32>)min(stage1_count, stage2_count);
        // set flag stating whether the frequency estimation is larger than the HH threshold
        if(ig_md.stage1_count_ok && ig_md.stage2_count_ok){
            hdr.sketch.threshold_passed = 1;
        } else {
            hdr.sketch.threshold_passed = 0;
        }
        
        generate_random_number();
        if(ig_md.stage1_count_ok && ig_md.stage2_count_ok && ig_md.random_number == 0){
                    hdr.sketch.inserted = 1;
                    @stage(2){
                        ig_md.flow_id_stage1_part1_old=replace_flow_id_stage1_part1.execute(ig_md.id_stage1_index);
                        ig_md.flow_id_stage1_part2_old=replace_flow_id_stage1_part2.execute(ig_md.id_stage1_index);
                    }
                    @stage(3){
                        stage2_replace_part1();
                        stage2_replace_part2();
                    }
                    @stage(4){
                        stage3_replace_part1();
                        stage3_replace_part2();
                    }
        } else {
                    hdr.sketch.inserted = 0;
                    @stage(2){
                        ig_md.flow_id_stage1_part1_match=match_flow_id_stage1_part1.execute(ig_md.id_stage1_index);
                        ig_md.flow_id_stage1_part2_match=match_flow_id_stage1_part2.execute(ig_md.id_stage1_index);
                    }
                    @stage(3){ 
                        // // update match count stage1
                        if (ig_md.flow_id_stage1_part1_match && ig_md.flow_id_stage1_part2_match){
                            ig_md.flow_id_match_count = ig_md.flow_id_match_count + 1;
                        }
                        stage2_match_part1();
                        stage2_match_part2();
                    }
                    @stage(4){
                        stage3_match_part1();
                        stage3_match_part2();
                        // update match count stage2
                        if (ig_md.flow_id_stage2_part1_match && ig_md.flow_id_stage2_part2_match){
                            ig_md.flow_id_match_count = ig_md.flow_id_match_count + 1;
                        }
                    }
                    @stage(5){
                        // update match count stage3
                        if (ig_md.flow_id_stage3_part1_match && ig_md.flow_id_stage3_part2_match){
                            ig_md.flow_id_match_count = ig_md.flow_id_match_count + 1;
                        }
                    }
        }
        send_back();

        hdr.sketch.flow_id_match_count = ig_md.flow_id_match_count;
        hdr.sketch.setValid();

        hdr.ipv4.total_len = hdr.ipv4.total_len + 7; // The size of the custom sketch header is 7 bytes.
        if(hdr.udp.isValid()){
            hdr.udp.hdr_length = hdr.udp.hdr_length + 7;
        }
        
        ig_tm_md.bypass_egress = 1;
    }
}

/*************************************************************************
 *****************  I N G R E S S   D E P A R S E R  *********************
 *************************************************************************/
control IngressDeparser(
        packet_out packet, 
        inout header_t hdr, 
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        packet.emit(hdr);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EmptyEgressParser(),
    EmptyEgress(),
    EmptyEgressDeparser()
) pipe;

Switch(pipe) main;

