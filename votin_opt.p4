/* -*- P4_16 -*- */
#include <core.p4>
#include <t2na.p4>

/* CONSTANTS */
#define COUNTER_ARRAY_SIZE 1024
#define ID_ARRAY_SIZE 128

#define HASH_WIDTH_COUNT_STAGE 11
#define HASH_WIDTH_ID_STAGE 7

#define THETA_SHIFT 12
#define INSERTION_PROB_BITS 8


header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header voting_sketch_t {
    bit<8> flow_id_match_count;
    bit<8> number_of_id_stages;
    bit<32> freq_estimation;
}

/*
 * All headers, used in the program needs to be assembled into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct header_t {
    ethernet_t              ethernet;
    voting_sketch_t         sketch;
}

/*
 * All metadata, globally used in the program, also  needs to be assembled
 * into a single struct. As in the case of the headers, we only need to
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct metadata_t {
    bit<20> packet_count;
    bit<8> random_number;
    // indexes
    bit<16> count_stage1_index;
    bit<16> count_stage2_index;
    bit<16> id_stage1_index;
    bit<16> id_stage2_index;
    bit<16> id_stage3_index;
    // 128-bit flow ID
    bit<64> flow_id_stage1_part1_old;
    bit<64> flow_id_stage1_part2_old;
    bit<64> flow_id_stage2_part1_old;
    bit<64> flow_id_stage2_part2_old;
  
    bit<64> flow_id_part1_original; // used as a constant
    bit<64> flow_id_part2_original; // used as a constant

    bool flow_id_stage1_part1_match;
    bool flow_id_stage1_part2_match;
    bool flow_id_stage2_part1_match;
    bool flow_id_stage2_part2_match;
    bool flow_id_stage3_part1_match;
    bool flow_id_stage3_part2_match;

    bit<1> _padding;
    bool should_replace;

    bit<32> insertion_threshold;

    bit<8> flow_id_match_count;
}

#include "./common/util.p4"

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyIngressParser(packet_in packet,
                out header_t hdr,
                out metadata_t ig_md,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;
    state start {
        tofino_parser.apply(packet, ig_intr_md);
        packet.extract(hdr.ethernet);

        ig_md.flow_id_part1_original = (bit<64>)hdr.ethernet.srcAddr;
        ig_md.flow_id_part2_original = (bit<64>)hdr.ethernet.dstAddr;

        // default values for `flow_id_stage{1/2}_part{1/2}` are later used in hash/index calculations
        ig_md.flow_id_stage1_part1_old = (bit<64>)hdr.ethernet.srcAddr;
        ig_md.flow_id_stage1_part1_old = (bit<64>)hdr.ethernet.dstAddr;
        ig_md.flow_id_stage2_part1_old = (bit<64>)hdr.ethernet.srcAddr;
        ig_md.flow_id_stage2_part1_old = (bit<64>)hdr.ethernet.dstAddr;

        ig_md.should_replace = false;
        transition accept;
    }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout header_t hdr,
                  inout metadata_t ig_md,
                  in ingress_intrinsic_metadata_t ig_intr_md,
                  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                  inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    /************************************************************
     ****************  REGISTER DEFINITIONS   *******************
     ************************************************************/
    Random<bit<INSERTION_PROB_BITS>>() random_number_generator;
    // instantiate a Hash extern named 'hash'
    Hash<bit<HASH_WIDTH_COUNT_STAGE>>(HashAlgorithm_t.CRC16) hash_count_stage1; // crc_16
    Hash<bit<HASH_WIDTH_COUNT_STAGE>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(0x10589, false, false, false, 0x0001, 0x0001)) hash_count_stage2; // crc_16_dect
    Hash<bit<HASH_WIDTH_ID_STAGE>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(0x18005, true, false, false, 0x0, 0x0)) hash_id_stage1;        // crc_16
    Hash<bit<HASH_WIDTH_ID_STAGE>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(0x10589, false, false, false, 0x0001, 0x0001)) hash_id_stage2; // crc_16_dect
    Hash<bit<HASH_WIDTH_ID_STAGE>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(0x13D65, true, false, false, 0xFFFF, 0xFFFF)) hash_id_stage3; // crc_16_dnp

    DirectRegister<int<32>>(0) packet_counter;
    DirectRegisterAction<int<32>,int<32>>(packet_counter) inc_and_get_packet_counter = {
        void apply(inout int<32> value, int<32> rv) {
            value = value |+| 1;
            rv = value;
        }
    };

    Register<int<32>,_>(COUNTER_ARRAY_SIZE, 0) reg_counters_stage1;
    RegisterAction<int<32>,_,int<32>>(reg_counters_stage1) inc_counter_and_read_stage1 = {
        void apply(inout int<32> value, int<32> rv) {
            value = value |+| 1;
            rv = value;
        }
    };

    Register<bit<32>,_>(COUNTER_ARRAY_SIZE, 0) reg_counters_stage2;
    RegisterAction<int<32>,_,int<32>>(reg_counters_stage2) inc_counter_and_read_stage2 = {
        void apply(inout int<32> value, out int<32> rv) {
            value = value |+| 1;
            rv = value;
        }
    };

    // ID Stage #1
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage1_part1;
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage1_part2;
    // ID Stage #2
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage2_part1;
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage2_part2;
    // ID Stage #3
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage3_part1;
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage3_part2;

    RegisterAction2<bit<64>,_, bit<64>, bool>(reg_flow_id_stage1_part1) replace_flow_id_stage1_part1 = { 
        void apply(inout bit<64> value, out bit<64> old_flow_id_part, out bool match){
            if(value == ig_md.flow_id_part1_original){
                match = true;
            } else {
                match = false;
            }
            if(ig_md.should_replace){
                old_flow_id_part = value;
                value = ig_md.flow_id_part1_original;
            }
            else {
                old_flow_id_part = ig_md.flow_id_part1_original;
            }
        }
    };
    RegisterAction2<bit<64>,_,bool, bit<64>>(reg_flow_id_stage1_part2) replace_flow_id_stage1_part2 = { 
        void apply(inout bit<64> value, out bool match, out bit<64> old_flow_id_part){ 
            if(value == ig_md.flow_id_part2_original){
                match = true;
            } else {
                match = false;
            }
            if(ig_md.should_replace){
                old_flow_id_part = value; 
                value = ig_md.flow_id_part2_original; 
            } else {
                old_flow_id_part = ig_md.flow_id_part2_original;
            }
        }
    }; 
    RegisterAction2<bit<64>,_,bool, bit<64>>(reg_flow_id_stage2_part1) replace_flow_id_stage2_part1 = { 
        void apply(inout bit<64> value, out bool match, out bit<64> old_flow_id_part){ 
            if(value == ig_md.flow_id_part1_original){
                match = true;
            } else {
                match = false;
            }
            if(ig_md.should_replace){
                old_flow_id_part = value; 
                value = ig_md.flow_id_stage1_part1_old; 
            } else {
                old_flow_id_part = ig_md.flow_id_part1_original;
            } 
        }
    }; 
    RegisterAction2<bit<64>,_,bool, bit<64>>(reg_flow_id_stage2_part2) replace_flow_id_stage2_part2 = { 
        void apply(inout bit<64> value, out bool match, out bit<64> old_flow_id_part){ 
            if(value == ig_md.flow_id_part2_original){
                match = true;
            } else {
                match = false;
            } 
            if(ig_md.should_replace){
                old_flow_id_part = value; 
                value = ig_md.flow_id_stage1_part2_old; 
            } else {
                old_flow_id_part = ig_md.flow_id_part2_original;
            } 
        }
    };
    RegisterAction<bit<64>,_,bool>(reg_flow_id_stage3_part1) replace_flow_id_stage3_part1 = { 
        void apply(inout bit<64> value, out bool match){ 
            if(value == ig_md.flow_id_part1_original){
                match = true;
            } else {
                match = false;
            }
            if(ig_md.should_replace){
                value = ig_md.flow_id_stage2_part1_old; 
            } 
        }
    };
    RegisterAction<bit<64>,_,bool>(reg_flow_id_stage3_part2) replace_flow_id_stage3_part2 = { 
        void apply(inout bit<64> value, out bool match){ 
            if(value == ig_md.flow_id_part2_original){
                match = true;
            } else {
                match = false;
            }
            if(ig_md.should_replace){
                value = ig_md.flow_id_stage2_part2_old; 
            } 
        }
    };

    action generate_random_number() {
        ig_md.random_number = random_number_generator.get();
    }

    /************ Count stages indices calculation ************/
    action get_count_stage1_hash(){
        ig_md.count_stage1_index = (bit<16>)hash_count_stage1.get({ 
            hdr.ethernet.srcAddr,
            hdr.ethernet.dstAddr 
        });
    }
    action get_count_stage2_hash(){
        ig_md.count_stage2_index = (bit<16>)hash_count_stage2.get({ 
            hdr.ethernet.srcAddr,
            hdr.ethernet.dstAddr 
        });
    }
    /************  ID stages indices calculation  ************/
    action get_id_stage1_hash(){
        ig_md.id_stage1_index = (bit<16>)hash_id_stage1.get({ 
            hdr.ethernet.srcAddr,
            hdr.ethernet.dstAddr 
        });
    }
    action get_id_stage2_hash(){
        ig_md.id_stage2_index = (bit<16>)hash_id_stage2.get({ 
            ig_md.flow_id_stage1_part1_old,
            ig_md.flow_id_stage1_part2_old 
        });
    }
    action get_id_stage3_hash(){
        ig_md.id_stage3_index = (bit<16>)hash_id_stage3.get({ 
            ig_md.flow_id_stage2_part1_old,
            ig_md.flow_id_stage2_part2_old 
        });
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
        // calculate the threshold N//Theta
        int<32> insertion_threshold = inc_and_get_packet_counter.execute(); 
        ig_md.insertion_threshold = insertion_threshold >> THETA_SHIFT;

        generate_random_number();
        get_count_stage1_hash();
        get_count_stage2_hash();
        int<32> stage1_count = inc_counter_and_read_stage1.execute(ig_md.count_stage1_index);
        int<32> stage2_count = inc_counter_and_read_stage2.execute(ig_md.count_stage2_index);
        
        if((stage1_count - ig_md.insertion_threshold >= 0) && (stage2_count - ig_md.insertion_threshold >= 0) && ig_md.random_number == 0){
            ig_md.should_replace = true;
        }
        
        get_id_stage1_hash();
        ig_md.flow_id_stage1_part1_old=replace_flow_id_stage1_part1.execute(ig_md.id_stage1_index, ig_md.flow_id_stage1_part1_match);
        ig_md.flow_id_stage1_part2_match=replace_flow_id_stage1_part2.execute(ig_md.id_stage1_index, ig_md.flow_id_stage1_part2_old);

        get_id_stage2_hash();
        ig_md.flow_id_stage2_part1_match=replace_flow_id_stage2_part1.execute(ig_md.id_stage2_index, ig_md.flow_id_stage2_part1_old);
        ig_md.flow_id_stage2_part2_match=replace_flow_id_stage2_part2.execute(ig_md.id_stage2_index, ig_md.flow_id_stage2_part2_old);

        get_id_stage3_hash();
        ig_md.flow_id_stage3_part1_match=replace_flow_id_stage3_part1.execute(ig_md.id_stage3_index);
        ig_md.flow_id_stage3_part2_match=replace_flow_id_stage3_part2.execute(ig_md.id_stage3_index);
        
        ig_md.flow_id_match_count = 0;
        // update match count stage1
        if (ig_md.flow_id_stage1_part1_match && ig_md.flow_id_stage1_part2_match){
            ig_md.flow_id_match_count = ig_md.flow_id_match_count + 1;
        }
        // update match count stage2
        if (ig_md.flow_id_stage2_part1_match && ig_md.flow_id_stage2_part2_match){
            ig_md.flow_id_match_count = ig_md.flow_id_match_count + 1;
        }
        // update match count stage3
        if (ig_md.flow_id_stage3_part1_match && ig_md.flow_id_stage3_part2_match){
            ig_md.flow_id_match_count = ig_md.flow_id_match_count + 1;
        }

        // choose the minimum count value as the frequency estimation
        hdr.sketch.freq_estimation = min(stage1_count, stage2_count)

        hdr.sketch.flow_id_match_count = ig_md.flow_id_match_count;
        hdr.sketch.number_of_id_stages = 3;
        hdr.sketch.setValid();
    }
}

/*************************************************************************
 *****************  I N G R E S S   D E P A R S E R  *********************
 *************************************************************************/
control MyIngressDeparser(
        packet_out packet, 
        inout header_t hdr, 
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        packet.emit(hdr);
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
// control MyEgress(inout header_t hdr,
//                  inout metadata_t meta,
//                  inout standard_metadata_t standard_metadata) {
//     apply { }
// }

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/
Pipeline(
    MyIngressParser(),
    MyIngress(),
    MyIngressDeparser(),
    EmptyEgressParser(),
    EmptyEgress(),
    EmptyEgressDeparser()
) pipe;

Switch(pipe) main;

