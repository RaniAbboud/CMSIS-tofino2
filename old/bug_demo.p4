/* -*- P4_16 -*- */
#include <core.p4>
#include <t2na.p4>

/* CONSTANTS */
#define ARRAY_SIZE 256
#define ARRAY_INDEX_BITS 8

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header sketch_t {
    bit<64> prev;
}

struct header_t {
    ethernet_t              ethernet;
    sketch_t                sketch;
}

struct metadata_t {}

parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

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
    Register<bit<64>,bit<ARRAY_INDEX_BITS>>(ARRAY_SIZE, 0) reg;

    RegisterAction<bit<64>,bit<ARRAY_INDEX_BITS>, bit<64>>(reg) replace_reg_value = { 
        // Write the packet's srcAddr into the register, and read the old value.
        void apply(inout bit<64> value, out bit<64> prev_val){
            prev_val= value;
            value = (bit<64>)hdr.ethernet.srcAddr;
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

    apply {
        hdr.sketch.prev=replace_reg_value.execute(0);
        
        send_back();
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
parser EmptyEgressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control EmptyEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {
        pkt.emit(hdr);
    }
}

control EmptyEgress(
        inout header_t hdr,
        inout metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}

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

