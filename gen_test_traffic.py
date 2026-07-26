#!/usr/bin/env python3
"""Gera pacotes de teste com header goose_feat_h para validar o pipeline no modelo.

Produz um PCAP e imprime o veredito esperado de cada pacote, permitindo
comparar com os contadores da tabela detect após a injeção.

Uso:
    python3 gen_test_traffic.py rules_v1.py -o test.pcap
    sudo tcpreplay -i veth0 test.pcap
"""

import argparse
import importlib.util
import struct
import sys

from rule_parser import parse_rules_file
from field_model import FIELDS

# Ordem e larguras derivadas de FIELDS, espelhando goose_feat_h no P4.
_ORDER = ["SqNum", "StNum", "sqDiff", "stDiff", "tDiff",
          "timeFromLastChange", "timestampDiff", "delay", "cbStatus"]
GOOSE_FIELDS = [(n, FIELDS[n].width // 8) for n in _ORDER]
_PAD_BITS = (-sum(FIELDS[n].width for n in _ORDER)) % 8

DST_MAC = bytes.fromhex("010ccd010000")   # multicast GOOSE
SRC_MAC = bytes.fromhex("001122334455")
ETH_VLAN = 0x8100
ETH_GOOSE = 0x88B8
VLAN_TCI = (4 << 13) | 0                  # PCP=4, VID=0 (padrão IEC 61850)


def encode_packet(values, tagged=True):
    """Monta o quadro Ethernet [+VLAN] + goose_feat_h."""
    pkt = DST_MAC + SRC_MAC
    if tagged:
        pkt += struct.pack("!HH", ETH_VLAN, VLAN_TCI)
    pkt += struct.pack("!H", ETH_GOOSE)

    for name, nbytes in GOOSE_FIELDS:
        spec = FIELDS[name]
        raw = spec.encode(values.get(name, 0))
        pkt += raw.to_bytes(nbytes, "big")

    if _PAD_BITS:
        pkt += b"\x00" * (_PAD_BITS // 8 or 1)

    if len(pkt) < 60:
        pkt += b"\x00" * (60 - len(pkt))
    return pkt


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(packets):
            f.write(struct.pack("<IIII", i, 0, len(p), len(p)))
            f.write(p)


def load_rules_module(path):
    spec = importlib.util.spec_from_file_location("rules_mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_cases():
    """Um caso por classe de ataque, mais tráfego normal.

    IMPORTANTE: os campos não especificados recebem valores NEUTROS, não zero.
    Zero satisfaz predicados como `SqNum < 5` ou `StNum < 30`, o que faria
    todo pacote acionar regras não pretendidas e tornaria o teste inútil
    para isolar qual regra casou.
    """
    base = {
        "SqNum": 30,                # fora de <5, <10, <1, >37, >55, >80
        "StNum": 300,               # fora de <20, <30, <100, >680, >700, >1000
        "cbStatus": 0,              # fora de ==1 e >1
        "sqDiff": 0,                # fora de <-63 e >30
        "stDiff": 0,                # fora de >300..>500 e <-40000
        "tDiff": 500,               # fora de >1000..>2000 e <-120, <-1500
        "timeFromLastChange": 20,   # fora de >45, >100, >120
        "timestampDiff": 0.0,       # fora de >0.1721, >0.2, >0.3, >0.35, >0.4
        "delay": 0.0,               # fora de >0.001
    }
    cases = []

    def case(label, **kw):
        v = dict(base)
        v.update(kw)
        cases.append((label, v))

    case("normal_1", SqNum=20, StNum=200, tDiff=100, cbStatus=0)
    case("normal_2", SqNum=45, StNum=350, tDiff=250, timeFromLastChange=10)
    case("grayhole_sq_tdiff", SqNum=2, tDiff=2000)
    case("grayhole_sq_stdiff", SqNum=3, stDiff=800)
    case("grayhole_sq_timechange", SqNum=1, timeFromLastChange=150)
    case("high_StNum_stnum", StNum=1200, stDiff=700)
    case("high_StNum_timing", tDiff=2500, timestampDiff=0.5)
    case("injection_seq_state", SqNum=90, StNum=10)
    case("injection_timing_status", tDiff=-2000, cbStatus=2)
    case("inverse_replay_seq_state", SqNum=0, StNum=15)
    case("inverse_replay_stdiff_time", stDiff=700, timeFromLastChange=150)
    case("masq_fault_tdiff_ts", tDiff=1500, timestampDiff=0.3)
    case("masq_fault_stnum_cb", StNum=50, cbStatus=1)
    case("masq_normal_seq_state", SqNum=0, StNum=700)
    case("masq_normal_jump_delay", stDiff=500, delay=0.002)
    case("poisoned_seq_state", StNum=800, sqDiff=-70)
    case("poisoned_timing", tDiff=-200, timeFromLastChange=150, delay=0.002)
    case("random_replay_sq_st", SqNum=60, StNum=50)
    case("random_replay_ts_idle", timestampDiff=0.4, timeFromLastChange=50)
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rules")
    ap.add_argument("-o", "--out", default="test_goose.pcap")
    ap.add_argument("--untagged", action="store_true",
                    help="gera quadros sem VLAN (testa o outro caminho do parser)")
    args = ap.parse_args()

    rules = parse_rules_file(args.rules)
    mod = load_rules_module(args.rules)
    fns = [(r.name, r.attack, getattr(mod, r.name)) for r in rules]

    cases = build_cases()
    packets = []

    print(f"{'#':>3}  {'caso':28s} {'esperado':22s} regras acionadas")
    print("-" * 100)
    n_attack = 0
    for i, (label, values) in enumerate(cases, start=1):
        fired = [(n, a) for n, a, fn in fns if fn(values)]
        expected = fired[0][1] if fired else "NORMAL"
        if fired:
            n_attack += 1
        names = ", ".join(n for n, _ in fired) or "-"
        print(f"{i:3d}  {label:28s} {expected:22s} {names}")
        packets.append(encode_packet(values, tagged=not args.untagged))

    write_pcap(args.out, packets)
    print("-" * 100)
    print(f"{len(packets)} pacotes -> {args.out}  "
          f"({n_attack} devem casar em detect, {len(packets)-n_attack} normais)")
    print(f"VLAN: {'nao' if args.untagged else 'sim (PCP=4, VID=0)'}")


if __name__ == "__main__":
    main()
