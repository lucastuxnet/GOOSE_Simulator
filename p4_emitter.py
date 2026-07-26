"""Emissão do programa P4_16/TNA a partir das regras."""

from typing import List
from rule_parser import Rule
from field_model import FIELDS, RangeEncoder

HEADER = """/* Gerado automaticamente por rules2p4. Não editar manualmente. */
#include <core.p4>
#include <tna.p4>

const bit<16> ETHERTYPE_VLAN  = 0x8100;
const bit<16> ETHERTYPE_GOOSE = 0x88B8;
"""


def emit(rules: List[Rule], enc: RangeEncoder, prog: str = "goose_ids") -> str:
    fields = enc.active_fields()
    out = [HEADER]
    out.append(_headers(fields))
    out.append(_metadata(fields, enc))
    out.append(_parser(fields))
    out.append(_ingress(rules, fields, enc))
    out.append(_deparser_and_egress())
    out.append(_pipeline())
    return "\n".join(out)


def _headers(fields) -> str:
    """Header derivado de FIELDS para acompanhar as larguras reais."""
    from field_model import FIELDS as FM
    order = ["SqNum", "StNum", "sqDiff", "stDiff", "tDiff",
             "timeFromLastChange", "timestampDiff", "delay", "cbStatus"]
    lines, bits = [], 0
    for name in order:
        w = FM[name].width
        lines.append(f"    bit<{w}> {name};")
        bits += w
    pad = (-bits) % 8
    if pad:
        lines.append(f"    bit<{pad}> pad;")

    body = "\n".join(lines)
    return f"""
header ethernet_h {{
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}}

header vlan_h {{
    bit<3>  pcp;
    bit<1>  dei;
    bit<12> vid;
    bit<16> ether_type;
}}

/* Campos GOOSE já extraídos por estágio anterior do pipeline.
   Larguras limitadas a 16 bits: o range match do Tofino não aceita
   chaves acima de 4 nibbles. */
header goose_feat_h {{
{body}
}}

struct headers_t {{
    ethernet_h   ethernet;
    vlan_h       vlan;
    goose_feat_h goose;
}}
"""


def _metadata(fields, enc: RangeEncoder) -> str:
    lines = ["struct metadata_t {"]
    for f in fields:
        lines.append(f"    bit<{enc.band_width(f)}> band_{f};")
    lines.append("    bit<16> attack_id;")
    lines.append("    bit<1>  is_attack;")
    lines.append("}")
    return "\n".join(lines)


def _parser(fields) -> str:
    init = ", ".join(["0"] * len(fields) + ["0", "0"])
    return f"""
parser IngressParser(packet_in pkt,
                     out headers_t hdr,
                     out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {{
    state start {{
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        md = (metadata_t){{{init}}};
        transition parse_ethernet;
    }}

    state parse_ethernet {{
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {{
            ETHERTYPE_VLAN:  parse_vlan;
            ETHERTYPE_GOOSE: parse_goose;
            default: accept;
        }}
    }}

    state parse_vlan {{
        pkt.extract(hdr.vlan);
        transition select(hdr.vlan.ether_type) {{
            ETHERTYPE_GOOSE: parse_goose;
            default: accept;
        }}
    }}

    state parse_goose {{
        pkt.extract(hdr.goose);
        transition accept;
    }}
}}
"""


def _band_table(field: str, enc: RangeEncoder) -> str:
    w = enc.band_width(field)
    n = len(enc.bands(field))
    return f"""
    action set_band_{field}(bit<{w}> idx) {{
        md.band_{field} = idx;
    }}

    action band_{field}_default() {{
        md.band_{field} = 0;
    }}

    table tbl_band_{field} {{
        key = {{ hdr.goose.{field} : range; }}
        actions = {{ set_band_{field}; band_{field}_default; }}
        default_action = band_{field}_default();
        size = {max(8, n * 2)};
    }}
"""


def _ingress(rules, fields, enc: RangeEncoder) -> str:
    band_tables = "".join(_band_table(f, enc) for f in fields)
    keys = "\n".join(f"            md.band_{f} : ternary;" for f in fields)
    applies = "\n".join(f"            tbl_band_{f}.apply();" for f in fields)

    # Uma ação por classe de ataque (Opção A): a classe é identificada pela
    # ação executada, não por um parâmetro BYTE_STREAM. Isso evita o campo de
    # dado de ação, que o tofino-model não serializa na leitura de volta, e
    # deixa a classe legível direto no dump (Ingress.flag_<classe>).
    # attack_id ainda é gravado na metadata para uso posterior no pipeline.
    classes = sorted({r.attack for r in rules})
    class_id = {c: i + 1 for i, c in enumerate(classes)}

    class_actions = "\n".join(f"""    action flag_{c}() {{
        md.attack_id = {class_id[c]};
        md.is_attack = 1;
        detect_ctr.count();
    }}""" for c in classes)

    action_list = "; ".join(f"flag_{c}" for c in classes)

    return f"""
control Ingress(inout headers_t hdr,
                inout metadata_t md,
                in    ingress_intrinsic_metadata_t ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {{
{band_tables}
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) detect_ctr;

{class_actions}

    action no_attack() {{
        md.is_attack = 0;
        detect_ctr.count();
    }}

    table detect {{
        key = {{
{keys}
        }}
        actions = {{ {action_list}; no_attack; }}
        default_action = no_attack();
        counters = detect_ctr;
        size = 2048;
    }}

    action drop() {{
        ig_dprsr_md.drop_ctl = 1;
    }}

    action forward(PortId_t port) {{
        ig_tm_md.ucast_egress_port = port;
    }}

    table fwd {{
        key = {{ ig_intr_md.ingress_port : exact; }}
        actions = {{ forward; drop; }}
        default_action = drop();
        size = 512;
    }}

    apply {{
        if (hdr.goose.isValid()) {{
{applies}
            detect.apply();
        }}
        fwd.apply();
    }}
}}
"""


def _deparser_and_egress() -> str:
    return """
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
"""


def _pipeline() -> str:
    return """
Pipeline(IngressParser(), Ingress(), IngressDeparser(),
         EgressParser(),  Egress(),  EgressDeparser()) pipe;

Switch(pipe) main;
"""
