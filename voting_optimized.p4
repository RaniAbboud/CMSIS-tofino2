/* -*- P4_16 -*- */
#include <core.p4>
#include <t2na.p4>

/* CONSTANTS */
#define COUNTER_ARRAY_SIZE 4096
#define ID_ARRAY_SIZE 256

#define HASH_WIDTH_COUNT_STAGE 16
#define HASH_WIDTH_ID_STAGE 16

#define THETA 2048

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

        // ig_md.should_replace = false;
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
    Hash<bit<HASH_WIDTH_COUNT_STAGE>>(HashAlgorithm_t.CRC16) hash_count_stage1; // crc_16
    Hash<bit<HASH_WIDTH_COUNT_STAGE>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(0x0589, false, false, false, 0x0001, 0x0001)) hash_count_stage2; // crc_16_dect
    Hash<bit<HASH_WIDTH_ID_STAGE>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(0x8005, true, false, false, 0x0, 0x0)) hash_id_stage1;        // crc_16
    Hash<bit<HASH_WIDTH_ID_STAGE>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(0x0589, false, false, false, 0x0001, 0x0001)) hash_id_stage2; // crc_16_dect
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

    Register<int<32>,_>(COUNTER_ARRAY_SIZE, 0) reg_counters_stage1;
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

    Register<int<32>,_>(COUNTER_ARRAY_SIZE, 0) reg_counters_stage2;
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
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage1_part1;
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage1_part2;
    // ID Stage #2
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage2_part1;
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage2_part2;
    // ID Stage #3
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage3_part1;
    Register<bit<64>,_>(ID_ARRAY_SIZE, 0) reg_flow_id_stage3_part2;

    RegisterAction<bit<64>,_, bit<64>>(reg_flow_id_stage1_part1) replace_flow_id_stage1_part1 = { 
        void apply(inout bit<64> value, out bit<64> old_flow_id_part){
            old_flow_id_part = value;
            value = ig_md.flow_id_part1_original;
        }
    };
    RegisterAction<bit<64>,_,bool>(reg_flow_id_stage1_part1) match_flow_id_stage1_part1 = { 
        void apply(inout bit<64> value, out bool match){
            if(value == ig_md.flow_id_part1_original){
                match = true;
            } else {
                match = false;
            }
        }
    };
    RegisterAction<bit<64>,_, bit<64>>(reg_flow_id_stage1_part2) replace_flow_id_stage1_part2 = { 
        void apply(inout bit<64> value, out bit<64> old_flow_id_part){ 
            old_flow_id_part = value; 
            value = ig_md.flow_id_part2_original; 
        }
    }; 
    RegisterAction<bit<64>,_,bool>(reg_flow_id_stage1_part2) match_flow_id_stage1_part2 = { 
        void apply(inout bit<64> value, out bool match){
            if(value == ig_md.flow_id_part2_original){
                match = true;
            } else {
                match = false;
            }
        }
    };
    RegisterAction<bit<64>,_,bit<64>>(reg_flow_id_stage2_part1) replace_flow_id_stage2_part1 = { 
        void apply(inout bit<64> value, out bit<64> old_flow_id_part){ 
            old_flow_id_part = value; 
            value = ig_md.flow_id_stage1_part1_old; 
        }
    };
    RegisterAction<bit<64>,_,bool>(reg_flow_id_stage2_part1) match_flow_id_stage2_part1 = { 
        void apply(inout bit<64> value, out bool match){
            if(value == ig_md.flow_id_part1_original){
                match = true;
            } else {
                match = false;
            }
        }
    };
    RegisterAction<bit<64>,_,bit<64>>(reg_flow_id_stage2_part2) replace_flow_id_stage2_part2 = { 
        void apply(inout bit<64> value, out bit<64> old_flow_id_part){ 
            old_flow_id_part = value; 
            value = ig_md.flow_id_stage1_part2_old; 
        }
    };
    RegisterAction<bit<64>,_,bool>(reg_flow_id_stage2_part1) match_flow_id_stage2_part2 = { 
        void apply(inout bit<64> value, out bool match){
            if(value == ig_md.flow_id_part1_original){
                match = true;
            } else {
                match = false;
            }
        }
    };
    RegisterAction<bit<64>,_,bit<64>>(reg_flow_id_stage3_part1) replace_flow_id_stage3_part1 = { 
        void apply(inout bit<64> value){ 
            value = ig_md.flow_id_stage2_part1_old; 
        }
    };
    RegisterAction<bit<64>,_,bool>(reg_flow_id_stage3_part1) match_flow_id_stage3_part1 = { 
        void apply(inout bit<64> value, out bool match){
            if(value == ig_md.flow_id_part1_original){
                match = true;
            } else {
                match = false;
            }
        }
    };
    RegisterAction<bit<64>,_,bit<64>>(reg_flow_id_stage3_part2) replace_flow_id_stage3_part2 = { 
        void apply(inout bit<64> value){ 
            value = ig_md.flow_id_stage2_part2_old; 
        }
    };
    RegisterAction<bit<64>,_,bool>(reg_flow_id_stage3_part2) match_flow_id_stage3_part2 = { 
        void apply(inout bit<64> value, out bool match){
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

    action stage2_replace_part1(){
        bit<16> id_stage2_index = (bit<16>)hash_id_stage2.get({ 
            ig_md.flow_id_stage1_part1_old,
            ig_md.flow_id_stage1_part2_old 
        });
        ig_md.flow_id_stage2_part1_old=replace_flow_id_stage2_part1.execute(id_stage2_index);
    }
    action stage2_replace_part2(){
        bit<16> id_stage2_index = (bit<16>)hash_id_stage2.get({ 
            ig_md.flow_id_stage1_part1_old,
            ig_md.flow_id_stage1_part2_old 
        });
        ig_md.flow_id_stage2_part2_old=replace_flow_id_stage2_part2.execute(id_stage2_index);
    }

    action stage2_match_part1(){
        bit<16> id_stage2_index = (bit<16>)hash_id_stage2.get({ 
            ig_md.flow_id_stage1_part1_old,
            ig_md.flow_id_stage1_part2_old 
        });
        ig_md.flow_id_stage2_part1_match=match_flow_id_stage2_part1.execute(id_stage2_index);
    }
    action stage2_match_part2(){
        bit<16> id_stage2_index = (bit<16>)hash_id_stage2.get({ 
            ig_md.flow_id_stage1_part1_old,
            ig_md.flow_id_stage1_part2_old 
        });
        ig_md.flow_id_stage2_part2_match=match_flow_id_stage2_part2.execute(id_stage2_index);
    }


    action stage3_replace_part1(){
        bit<16> id_stage3_index = (bit<16>)hash_id_stage3.get({ 
            ig_md.flow_id_stage2_part1_old,
            ig_md.flow_id_stage2_part2_old 
        });
        replace_flow_id_stage3_part1.execute(id_stage3_index);
    }
    action stage3_replace_part2(){
        bit<16> id_stage3_index = (bit<16>)hash_id_stage3.get({ 
            ig_md.flow_id_stage2_part1_old,
            ig_md.flow_id_stage2_part2_old 
        });
        replace_flow_id_stage3_part2.execute(id_stage3_index);
    }

    action stage3_match_part1(){
        bit<16> id_stage3_index = (bit<16>)hash_id_stage3.get({ 
            ig_md.flow_id_stage2_part1_old,
            ig_md.flow_id_stage2_part2_old 
        });
        ig_md.flow_id_stage3_part1_match=match_flow_id_stage3_part1.execute(id_stage3_index);
    }
    action stage3_match_part2(){
        bit<16> id_stage3_index = (bit<16>)hash_id_stage3.get({ 
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
        get_count_stage1_hash();
        get_count_stage2_hash();
        @stage(0){
            ig_md.insertion_threshold = (int<32>)inc_packet_counter_get_threshold.execute();
        }
        int<32> stage1_count;
        int<32> stage2_count;
        @stage(1){
            stage1_count = inc_counter_and_read_stage1.execute(ig_md.count_stage1_index, ig_md.stage1_count_ok);
            stage2_count = inc_counter_and_read_stage2.execute(ig_md.count_stage2_index, ig_md.stage2_count_ok);
        }
        // choose the minimum count value as the frequency estimation
        hdr.sketch.freq_estimation = (bit<32>)min(stage1_count, stage2_count);
        
        generate_random_number();
        if(ig_md.stage1_count_ok && ig_md.stage2_count_ok && ig_md.random_number == 0){
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
                    ig_md.flow_id_stage1_part1_old=ig_md.flow_id_part1_original;
                    ig_md.flow_id_stage1_part2_old=ig_md.flow_id_part2_original;
                    ig_md.flow_id_stage2_part1_old=ig_md.flow_id_part1_original;
                    ig_md.flow_id_stage2_part2_old=ig_md.flow_id_part2_original;

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

