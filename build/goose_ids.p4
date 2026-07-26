/* Gerado automaticamente por rules2p4. Não editar manualmente. */
#include <core.p4>
#include <tna.p4>

const bit<16> ETHERTYPE_VLAN  = 0x8100;
const bit<16> ETHERTYPE_GOOSE = 0x88B8;


header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header vlan_h {
    bit<3>  pcp;
    bit<1>  dei;
    bit<12> vid;
    bit<16> ether_type;
}

/* Campos GOOSE já extraídos por estágio anterior do pipeline.
   Larguras limitadas a 16 bits: o range match do Tofino não aceita
   chaves acima de 4 nibbles. */
header goose_feat_h {
    bit<16> SqNum;
    bit<16> StNum;
    bit<16> sqDiff;
    bit<16> stDiff;
    bit<16> tDiff;
    bit<16> timeFromLastChange;
    bit<16> timestampDiff;
    bit<16> delay;
    bit<8> cbStatus;
}

struct headers_t {
    ethernet_h   ethernet;
    vlan_h       vlan;
    goose_feat_h goose;
}

struct metadata_t {
    bit<3> band_SqNum;
    bit<3> band_StNum;
    bit<2> band_cbStatus;
    bit<1> band_delay;
    bit<2> band_sqDiff;
    bit<3> band_stDiff;
    bit<3> band_tDiff;
    bit<2> band_timeFromLastChange;
    bit<3> band_timestampDiff;
    bit<16> attack_id;
    bit<1>  is_attack;
}

parser IngressParser(packet_in pkt,
                     out headers_t hdr,
                     out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        md = (metadata_t){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_VLAN:  parse_vlan;
            ETHERTYPE_GOOSE: parse_goose;
            default: accept;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition select(hdr.vlan.ether_type) {
            ETHERTYPE_GOOSE: parse_goose;
            default: accept;
        }
    }

    state parse_goose {
        pkt.extract(hdr.goose);
        transition accept;
    }
}


control Ingress(inout headers_t hdr,
                inout metadata_t md,
                in    ingress_intrinsic_metadata_t ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action set_band_SqNum(bit<3> idx) {
        md.band_SqNum = idx;
    }

    action band_SqNum_default() {
        md.band_SqNum = 0;
    }

    table tbl_band_SqNum {
        key = { hdr.goose.SqNum : range; }
        actions = { set_band_SqNum; band_SqNum_default; }
        default_action = band_SqNum_default();
        size = 16;
    }

    action set_band_StNum(bit<3> idx) {
        md.band_StNum = idx;
    }

    action band_StNum_default() {
        md.band_StNum = 0;
    }

    table tbl_band_StNum {
        key = { hdr.goose.StNum : range; }
        actions = { set_band_StNum; band_StNum_default; }
        default_action = band_StNum_default();
        size = 14;
    }

    action set_band_cbStatus(bit<2> idx) {
        md.band_cbStatus = idx;
    }

    action band_cbStatus_default() {
        md.band_cbStatus = 0;
    }

    table tbl_band_cbStatus {
        key = { hdr.goose.cbStatus : range; }
        actions = { set_band_cbStatus; band_cbStatus_default; }
        default_action = band_cbStatus_default();
        size = 8;
    }

    action set_band_delay(bit<1> idx) {
        md.band_delay = idx;
    }

    action band_delay_default() {
        md.band_delay = 0;
    }

    table tbl_band_delay {
        key = { hdr.goose.delay : range; }
        actions = { set_band_delay; band_delay_default; }
        default_action = band_delay_default();
        size = 8;
    }

    action set_band_sqDiff(bit<2> idx) {
        md.band_sqDiff = idx;
    }

    action band_sqDiff_default() {
        md.band_sqDiff = 0;
    }

    table tbl_band_sqDiff {
        key = { hdr.goose.sqDiff : range; }
        actions = { set_band_sqDiff; band_sqDiff_default; }
        default_action = band_sqDiff_default();
        size = 8;
    }

    action set_band_stDiff(bit<3> idx) {
        md.band_stDiff = idx;
    }

    action band_stDiff_default() {
        md.band_stDiff = 0;
    }

    table tbl_band_stDiff {
        key = { hdr.goose.stDiff : range; }
        actions = { set_band_stDiff; band_stDiff_default; }
        default_action = band_stDiff_default();
        size = 10;
    }

    action set_band_tDiff(bit<3> idx) {
        md.band_tDiff = idx;
    }

    action band_tDiff_default() {
        md.band_tDiff = 0;
    }

    table tbl_band_tDiff {
        key = { hdr.goose.tDiff : range; }
        actions = { set_band_tDiff; band_tDiff_default; }
        default_action = band_tDiff_default();
        size = 12;
    }

    action set_band_timeFromLastChange(bit<2> idx) {
        md.band_timeFromLastChange = idx;
    }

    action band_timeFromLastChange_default() {
        md.band_timeFromLastChange = 0;
    }

    table tbl_band_timeFromLastChange {
        key = { hdr.goose.timeFromLastChange : range; }
        actions = { set_band_timeFromLastChange; band_timeFromLastChange_default; }
        default_action = band_timeFromLastChange_default();
        size = 8;
    }

    action set_band_timestampDiff(bit<3> idx) {
        md.band_timestampDiff = idx;
    }

    action band_timestampDiff_default() {
        md.band_timestampDiff = 0;
    }

    table tbl_band_timestampDiff {
        key = { hdr.goose.timestampDiff : range; }
        actions = { set_band_timestampDiff; band_timestampDiff_default; }
        default_action = band_timestampDiff_default();
        size = 12;
    }

    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) detect_ctr;

    action flag_grayhole() {
        md.attack_id = 1;
        md.is_attack = 1;
        detect_ctr.count();
    }
    action flag_high_StNum() {
        md.attack_id = 2;
        md.is_attack = 1;
        detect_ctr.count();
    }
    action flag_injection() {
        md.attack_id = 3;
        md.is_attack = 1;
        detect_ctr.count();
    }
    action flag_inverse_replay() {
        md.attack_id = 4;
        md.is_attack = 1;
        detect_ctr.count();
    }
    action flag_masquerade_fake_fault() {
        md.attack_id = 5;
        md.is_attack = 1;
        detect_ctr.count();
    }
    action flag_masquerade_fake_normal() {
        md.attack_id = 6;
        md.is_attack = 1;
        detect_ctr.count();
    }
    action flag_poisoned_high_rate() {
        md.attack_id = 7;
        md.is_attack = 1;
        detect_ctr.count();
    }
    action flag_random_replay() {
        md.attack_id = 8;
        md.is_attack = 1;
        detect_ctr.count();
    }

    action no_attack() {
        md.is_attack = 0;
        detect_ctr.count();
    }

    table detect {
        key = {
            md.band_SqNum : ternary;
            md.band_StNum : ternary;
            md.band_cbStatus : ternary;
            md.band_delay : ternary;
            md.band_sqDiff : ternary;
            md.band_stDiff : ternary;
            md.band_tDiff : ternary;
            md.band_timeFromLastChange : ternary;
            md.band_timestampDiff : ternary;
        }
        actions = { flag_grayhole; flag_high_StNum; flag_injection; flag_inverse_replay; flag_masquerade_fake_fault; flag_masquerade_fake_normal; flag_poisoned_high_rate; flag_random_replay; no_attack; }
        default_action = no_attack();
        counters = detect_ctr;
        size = 2048;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table fwd {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { forward; drop; }
        default_action = drop();
        size = 512;
    }

    apply {
        if (hdr.goose.isValid()) {
            tbl_band_SqNum.apply();
            tbl_band_StNum.apply();
            tbl_band_cbStatus.apply();
            tbl_band_delay.apply();
            tbl_band_sqDiff.apply();
            tbl_band_stDiff.apply();
            tbl_band_tDiff.apply();
            tbl_band_timeFromLastChange.apply();
            tbl_band_timestampDiff.apply();
            detect.apply();
        }
        fwd.apply();
    }
}


control IngressDeparser(packet_out pkt,
                        inout headers_t hdr,
                        in    metadata_t md,
                        in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}

parser EgressParser(packet_in pkt,
                    out headers_t hdr,
                    out metadata_t md,
                    out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control Egress(inout headers_t hdr,
               inout metadata_t md,
               in    egress_intrinsic_metadata_t eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}

control EgressDeparser(packet_out pkt,
                       inout headers_t hdr,
                       in    metadata_t md,
                       in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}


Pipeline(IngressParser(), Ingress(), IngressDeparser(),
         EgressParser(),  Egress(),  EgressDeparser()) pipe;

Switch(pipe) main;
