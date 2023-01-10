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
#define COUNTERS_ARRAY_SIZE 2048
#define FLOW_ID_ARRAY_SIZE 512

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/*
 * All headers, used in the program needs to be assembled into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct header_t {
    ethernet_t              ethernet;
}

/*
 * All metadata, globally used in the program, also  needs to be assembled
 * into a single struct. As in the case of the headers, we only need to
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct metadata_t {
    bit<32> packet_count;
    bit<32> random_value;
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
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash;

    Register<bit<32>,_>(COUNTERS_ARRAY_SIZE, 0) counters_stage0;
    RegisterAction<bit<32>,_,bit<32>>(counters_stage0) inc_counter_and_read = {
        void apply(inout bit<32> value, out bit<32> rv) {
            value = value |+| 1;
            rv = value;
        }
    };

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

    action insert_wp(bit<32> mask) {
        if(mask & ig_md.random_value == 0){
            // TODO: insert flow
        }
    }

    table approximate_coin_flip {
        key = {
            ig_md.packet_count : range;
        }
        actions = {
            insert_wp;
        }
        counters = packet_size_stats;
        size = 32;
        const entries = {
            0 ..  3 : insert_wp(32w0b_0001);
            3 ..  5 : insert_wp(32w0b_0011);
            5 ..  9 : insert_wp(32w0b_0111);
            9 ..  17 : insert_wp(32w0b_1111);
            17 ..  33 : insert_wp(32w0b_1_1111);
            33 ..  65 : insert_wp(32w0b_11_1111);
            65 ..  129 : insert_wp(32w0b_111_1111);
            129 ..  257 : insert_wp(32w0b_1111_1111);
            257 ..  513 : insert_wp(32w0b_1_1111_1111);
            513 ..  1025 : insert_wp(32w0b_11_1111_1111);
            1025 ..  2049 : insert_wp(32w0b_111_1111_1111);
            2049 ..  4097 : insert_wp(32w0b_1111_1111_1111);
            4097 ..  8193 : insert_wp(32w0b_1_1111_1111_1111);
            8193 ..  16385 : insert_wp(32w0b_11_1111_1111_1111);
            16385 ..  32769 : insert_wp(32w0b_111_1111_1111_1111);
            32769 ..  65537 : insert_wp(32w0b_1111_1111_1111_1111);
            65537 ..  131073 : insert_wp(32w0b_1_1111_1111_1111_1111);
            131073 ..  262145 : insert_wp(32w0b_11_1111_1111_1111_1111);
            262145 ..  524289 : insert_wp(32w0b_111_1111_1111_1111_1111);
            524289 ..  1048577 : insert_wp(32w0b_1111_1111_1111_1111_1111);
            1048577 ..  2097153 : insert_wp(32w0b_1_1111_1111_1111_1111_1111);
            2097153 ..  4194305 : insert_wp(32w0b_11_1111_1111_1111_1111_1111);
            4194305 ..  8388609 : insert_wp(32w0b_111_1111_1111_1111_1111_1111);
            8388609 ..  16777217 : insert_wp(32w0b_1111_1111_1111_1111_1111_1111);
            16777217 ..  33554433 : insert_wp(32w0b_1_1111_1111_1111_1111_1111_1111);
            33554433 ..  67108865 : insert_wp(32w0b_11_1111_1111_1111_1111_1111_1111);
            67108865 ..  134217729 : insert_wp(32w0b_111_1111_1111_1111_1111_1111_1111);
            134217729 ..  268435457 : insert_wp(32w0b_1111_1111_1111_1111_1111_1111_1111);
            268435457 ..  536870913 : insert_wp(32w0b_1_1111_1111_1111_1111_1111_1111_1111);
            536870913 ..  1073741825 : insert_wp(32w0b_11_1111_1111_1111_1111_1111_1111_1111);
            1073741825 ..  2147483649 : insert_wp(32w0b_111_1111_1111_1111_1111_1111_1111_1111);
            2147483649 ..  4294967295 : insert_wp(32w0b_1111_1111_1111_1111_1111_1111_1111_1111);
        }
    }

    apply {
        // calculate the hash of the concatenation of a few fields
        bit<16> reg_index = hash.get({ 
            hdr.ethernet.srcAddr,
            hdr.ethernet.dstAddr 
        });
        // increment the entry's counter and get its updated value
        ig_md.packet_count = inc_counter_and_read.execute(reg_index);
        // estimate insertion probability and flip a coin.
        ig_md.random_value = random_number_generator.get();

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
        packet.emit(hdr.ethernet);
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

