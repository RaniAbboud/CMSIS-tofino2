/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

/* CONSTANTS */
#define REGISTER_ARRAY_SIZE 1024
#define HASH_WIDTH 10

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header voting_sketch_t {
    bit<8> flow_id_match_count;
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
    bit<32> random_number;
    bit<32> index;
    // 128-bit flow ID
    bit<64> flow_id_stage1_part1_old;
    bit<64> flow_id_stage1_part2_old;
    bit<64> flow_id_stage2_part1_old;
    bit<64> flow_id_stage2_part2_old;
    bit<64> flow_id_stage3_part1_old;
    bit<64> flow_id_stage3_part2_old;    
    bit<64> flow_id_part1_original; // used as a constant
    bit<64> flow_id_part2_original; // used as a constant

    bool flow_id_stage1_part1_match;
    bool flow_id_stage1_part2_match;
    bool flow_id_stage2_part1_match;
    bool flow_id_stage2_part2_match;
    bool flow_id_stage3_part1_match;
    bool flow_id_stage3_part2_match;

    bit<2> _padding;

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

        // ig_md.flow_id_part1 = (bit<64>)hdr.ethernet.srcAddr;
        ig_md.flow_id_part1_original = (bit<64>)hdr.ethernet.srcAddr;
        // ig_md.flow_id_part2 = (bit<64>)hdr.ethernet.dstAddr;
        ig_md.flow_id_part2_original = (bit<64>)hdr.ethernet.dstAddr;

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
    Random<bit<32>>() random_number_generator;
    // instantiate a Hash extern named 'hash'
    Hash<bit<HASH_WIDTH>>(HashAlgorithm_t.CRC16) hash;

    Register<bit<32>,_>(REGISTER_ARRAY_SIZE, 0) counters_stage0;
    RegisterAction<bit<32>,_,bit<32>>(counters_stage0) inc_counter_and_read = {
        void apply(inout bit<32> value, out bit<32> rv) {
            value = value |+| 1;
            rv = value;
        }
    };

    // Stage #1
    Register<bit<64>,_>(REGISTER_ARRAY_SIZE, 0) reg_flow_id_stage1_part1;
    Register<bit<64>,_>(REGISTER_ARRAY_SIZE, 0) reg_flow_id_stage1_part2;
    // Stage #2
    Register<bit<64>,_>(REGISTER_ARRAY_SIZE, 0) reg_flow_id_stage2_part1;
    Register<bit<64>,_>(REGISTER_ARRAY_SIZE, 0) reg_flow_id_stage2_part2;
    // Stage #3
    Register<bit<64>,_>(REGISTER_ARRAY_SIZE, 0) reg_flow_id_stage3_part1;
    Register<bit<64>,_>(REGISTER_ARRAY_SIZE, 0) reg_flow_id_stage3_part2;

    #define Reg_Actions_Match_And_Replace_ID(S,P) \
    RegisterAction<bit<64>,_,bool>(reg_flow_id_stage## S ##_part## P ##) match_flow_id_stage## S ##_part## P ## = {       \
        void apply(inout bit<64> value, out bool match){            \
            match = (value == ig_md.flow_id_part## P ##_original);                                  \
        }                                                                                           \
    };                                                                                              \
    action exec_match_flow_id_stage## S ##_part## P ##(){ ig_md.flow_id_stage## S ##_part## P ##_match=match_flow_id_stage## S ##_part## P ##.execute(ig_md.index);}  
//    action exec_replace_flow_id_stage## S ##_part## P ##(){ ig_md.flow_id_stage## S ##_part## P ##_match=(bool)replace_flow_id_stage## S ##_part## P ##.execute(ig_md.index, ig_md.flow_id_part## P ##);}  \
    // RegisterAction2<bit<64>,_,bit<1>, bit<64>>(reg_flow_id_stage## S ##_part## P ##) replace_flow_id_stage## S ##_part## P ## = {       \
    //     void apply(inout bit<64> value, out bit<1> match, out bit<64> new_flow_id_part){            \
    //         match = 0;                                                                              \
    //         new_flow_id_part = 0;                                                                   \
    //         if (value == ig_md.flow_id_part## P ##_original){                                       \
    //             match = 1;                                                                          \
    //         }                                                                                       \
    //         if (ig_md.random_number == 0) {                                                         \
    //             bit<64> tmp = ig_md.flow_id_part## P ##;                                            \
    //             new_flow_id_part = value;                                                           \
    //             value = tmp;                                                                        \
    //         }                                                                                       \
    //     }                                                                                           \
    // };                

    Reg_Actions_Match_And_Replace_ID(1,1)
    Reg_Actions_Match_And_Replace_ID(1,2)
    Reg_Actions_Match_And_Replace_ID(2,1)
    Reg_Actions_Match_And_Replace_ID(2,2)
    Reg_Actions_Match_And_Replace_ID(3,1)
    Reg_Actions_Match_And_Replace_ID(3,2)

    RegisterAction2<bit<64>,_,bool, bit<64>>(reg_flow_id_stage1_part1) replace_flow_id_stage1_part1 = { void apply(inout bit<64> value, out bool match, out bit<64> new_flow_id_part){ match = (value == ig_md.flow_id_part1_original); new_flow_id_part = value; value = ig_md.flow_id_part1_original; } }; action exec_replace_flow_id_stage1_part1(){ ig_md.flow_id_stage1_part1_match=replace_flow_id_stage1_part1.execute(ig_md.index, ig_md.flow_id_stage1_part1_old);}
    RegisterAction2<bit<64>,_,bool, bit<64>>(reg_flow_id_stage1_part2) replace_flow_id_stage1_part2 = { void apply(inout bit<64> value, out bool match, out bit<64> new_flow_id_part){ match = (value == ig_md.flow_id_part2_original); new_flow_id_part = value; value = ig_md.flow_id_part2_original; } }; action exec_replace_flow_id_stage1_part2(){ ig_md.flow_id_stage1_part2_match=replace_flow_id_stage1_part2.execute(ig_md.index, ig_md.flow_id_stage1_part2_old);}
    RegisterAction2<bit<64>,_,bool, bit<64>>(reg_flow_id_stage2_part1) replace_flow_id_stage2_part1 = { void apply(inout bit<64> value, out bool match, out bit<64> new_flow_id_part){ match = (value == ig_md.flow_id_part1_original); new_flow_id_part = value; value = ig_md.flow_id_stage1_part1_old; } }; action exec_replace_flow_id_stage2_part1(){ ig_md.flow_id_stage2_part1_match=replace_flow_id_stage2_part1.execute(ig_md.index, ig_md.flow_id_stage2_part1_old);}
    RegisterAction2<bit<64>,_,bool, bit<64>>(reg_flow_id_stage2_part2) replace_flow_id_stage2_part2 = { void apply(inout bit<64> value, out bool match, out bit<64> new_flow_id_part){ match = (value == ig_md.flow_id_part2_original); new_flow_id_part = value; value = ig_md.flow_id_stage1_part2_old; } }; action exec_replace_flow_id_stage2_part2(){ ig_md.flow_id_stage2_part2_match=replace_flow_id_stage2_part2.execute(ig_md.index, ig_md.flow_id_stage2_part2_old);}
    RegisterAction2<bit<64>,_,bool, bit<64>>(reg_flow_id_stage3_part1) replace_flow_id_stage3_part1 = { void apply(inout bit<64> value, out bool match, out bit<64> new_flow_id_part){ match = (value == ig_md.flow_id_part1_original); new_flow_id_part = value; value = ig_md.flow_id_stage2_part1_old; } }; action exec_replace_flow_id_stage3_part1(){ ig_md.flow_id_stage3_part1_match=replace_flow_id_stage3_part1.execute(ig_md.index, ig_md.flow_id_stage3_part1_old);}
    RegisterAction2<bit<64>,_,bool, bit<64>>(reg_flow_id_stage3_part2) replace_flow_id_stage3_part2 = { void apply(inout bit<64> value, out bool match, out bit<64> new_flow_id_part){ match = (value == ig_md.flow_id_part2_original); new_flow_id_part = value; value = ig_md.flow_id_stage2_part2_old; } }; action exec_replace_flow_id_stage3_part2(){ ig_md.flow_id_stage3_part2_match=replace_flow_id_stage3_part2.execute(ig_md.index, ig_md.flow_id_stage3_part2_old);}

    action generate_random_number() {
        ig_md.random_number = random_number_generator.get();
    }

    action generate_packet_hash() {
        // calculate the hash of the concatenation of a few fields
        ig_md.index = (bit<32>)hash.get({ 
            hdr.ethernet.srcAddr,
            hdr.ethernet.dstAddr 
        });
    }

    action get_inc_packet_count() {
        // increment the entry's counter and get its updated value
        ig_md.packet_count = (bit<20>)inc_counter_and_read.execute(ig_md.index);
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

    action operation_drop() {
        mark_to_drop(ig_dprsr_md);
    }

    action apply_mask_on_coin(bit<32> coin_mask) {
        ig_md.random_number = ig_md.random_number & coin_mask;
    }

    table approximate_coin_flip {
        key = {
            ig_md.packet_count : range;
        }
        actions = {
            apply_mask_on_coin;
        }
        size = 32;
        const entries = {
            0 ..  3 : apply_mask_on_coin(32w0b_0001);
            3 ..  5 : apply_mask_on_coin(32w0b_0011);
            5 ..  9 : apply_mask_on_coin(32w0b_0111);
            9 ..  17 : apply_mask_on_coin(32w0b_1111);
            17 ..  33 : apply_mask_on_coin(32w0b_1_1111);
            33 ..  65 : apply_mask_on_coin(32w0b_11_1111);
            65 ..  129 : apply_mask_on_coin(32w0b_111_1111);
            129 ..  257 : apply_mask_on_coin(32w0b_1111_1111);
            257 ..  513 : apply_mask_on_coin(32w0b_1_1111_1111);
            513 ..  1025 : apply_mask_on_coin(32w0b_11_1111_1111);
            1025 ..  2049 : apply_mask_on_coin(32w0b_111_1111_1111);
            2049 ..  4097 : apply_mask_on_coin(32w0b_1111_1111_1111);
            4097 ..  8193 : apply_mask_on_coin(32w0b_1_1111_1111_1111);
            8193 ..  16385 : apply_mask_on_coin(32w0b_11_1111_1111_1111);
            16385 ..  32769 : apply_mask_on_coin(32w0b_111_1111_1111_1111);
            32769 ..  65537 : apply_mask_on_coin(32w0b_1111_1111_1111_1111);
            65537 ..  131073 : apply_mask_on_coin(32w0b_1_1111_1111_1111_1111);
            131073 ..  262145 : apply_mask_on_coin(32w0b_11_1111_1111_1111_1111);
            262145 ..  524289 : apply_mask_on_coin(32w0b_111_1111_1111_1111_1111);
            //524289 ..  1048577 : apply_mask_on_coin(32w0b_1111_1111_1111_1111_1111);
            524289 ..  999999 : apply_mask_on_coin(32w0b_1111_1111_1111_1111_1111);
            // 1048577 ..  2097153 : apply_mask_on_coin(32w0b_1_1111_1111_1111_1111_1111);
            // 2097153 ..  4194305 : apply_mask_on_coin(32w0b_11_1111_1111_1111_1111_1111);
            // 4194305 ..  8388609 : apply_mask_on_coin(32w0b_111_1111_1111_1111_1111_1111);
            // 8388609 ..  16777217 : apply_mask_on_coin(32w0b_1111_1111_1111_1111_1111_1111);
            // 16777217 ..  33554433 : apply_mask_on_coin(32w0b_1_1111_1111_1111_1111_1111_1111);
            // 33554433 ..  67108865 : apply_mask_on_coin(32w0b_11_1111_1111_1111_1111_1111_1111);
            // 67108865 ..  134217729 : apply_mask_on_coin(32w0b_111_1111_1111_1111_1111_1111_1111);
            // 134217729 ..  268435457 : apply_mask_on_coin(32w0b_1111_1111_1111_1111_1111_1111_1111);
            // 268435457 ..  536870913 : apply_mask_on_coin(32w0b_1_1111_1111_1111_1111_1111_1111_1111);
            // 536870913 ..  1073741825 : apply_mask_on_coin(32w0b_11_1111_1111_1111_1111_1111_1111_1111);
            // 1073741825 ..  2147483649 : apply_mask_on_coin(32w0b_111_1111_1111_1111_1111_1111_1111_1111);
            // 2147483649 ..  4294967295 : apply_mask_on_coin(32w0b_1111_1111_1111_1111_1111_1111_1111_1111);
        }
    }

    apply {
        generate_random_number();
        generate_packet_hash();
        get_inc_packet_count();
        approximate_coin_flip.apply(); // masks the ig_md.random_number, depending on the counter's value
        if( ig_md.random_number == 0 ){
            // insert flow ID while shifting (only if random_number=0, otherwise only match and count)
            exec_replace_flow_id_stage1_part1();
            exec_replace_flow_id_stage1_part2();
            exec_replace_flow_id_stage2_part1();
            exec_replace_flow_id_stage2_part2();
            exec_replace_flow_id_stage3_part1();
            exec_replace_flow_id_stage3_part2();
        } else {
            exec_match_flow_id_stage1_part1();
            exec_match_flow_id_stage1_part2();
            exec_match_flow_id_stage2_part1();
            exec_match_flow_id_stage2_part2();
            exec_match_flow_id_stage3_part1();
            exec_match_flow_id_stage3_part2();
        }
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
    
        hdr.sketch.freq_estimation = (bit<32>)ig_md.packet_count;
        hdr.sketch.flow_id_match_count = ig_md.flow_id_match_count;
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

