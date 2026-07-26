#!/usr/bin/env python3
"""Valida equivalência entre as regras Python e as entradas ternárias geradas.

Simula o pipeline (discretização + match ternário) sobre pacotes aleatórios
e compara com a avaliação direta das funções originais.
"""

import argparse
import importlib.util
import random
import sys

from rule_parser import parse_rules_file
from field_model import FIELDS, RangeEncoder
from bfrt_emitter import build_entries


def load_module(path):
    spec = importlib.util.spec_from_file_location("rules_mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def band_of(enc, field, raw_value):
    """Reproduz a tabela tbl_band_<field> do dataplane."""
    spec = FIELDS[field]
    v = spec.encode(raw_value)
    for i, (lo, hi) in enumerate(enc.bands(field)):
        if lo <= v <= hi:
            return i
    return 0


def simulate(enc, entries, packet):
    """Reproduz o match ternário: menor prioridade vence."""
    bands = {f: band_of(enc, f, packet.get(f, 0)) for f in enc.active_fields()}
    best = None
    for e in entries:
        ok = True
        for f, k in e["key"].items():
            if k["mask"] and bands[f] != k["value"]:
                ok = False
                break
        if ok and (best is None or e["priority"] < best["priority"]):
            best = e
    return best


def random_packet(rng):
    return {
        "SqNum": rng.randint(0, 200),
        "StNum": rng.randint(0, 1500),
        "cbStatus": rng.randint(0, 3),
        "sqDiff": rng.randint(-200, 200),
        "stDiff": rng.randint(-60000, 2000),
        "tDiff": rng.randint(-3000, 4000),
        "timeFromLastChange": rng.randint(0, 300),
        "timestampDiff": round(rng.uniform(-1.0, 1.0), 4),
        "delay": round(rng.uniform(0, 0.005), 6),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rules")
    ap.add_argument("-n", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rules = parse_rules_file(args.rules)
    enc = RangeEncoder(rules)
    entries, attack_id = build_entries(rules, enc)
    mod = load_module(args.rules)

    fns = {r.name: (getattr(mod, r.name), r) for r in rules}
    rng = random.Random(args.seed)

    total = mism_detect = mism_class = hits = 0
    per_rule_mismatch = {}

    for _ in range(args.n):
        pkt = random_packet(rng)
        total += 1

        fired = [r.name for name, (fn, r) in fns.items() if fn(pkt)]
        py_detect = len(fired) > 0

        m = simulate(enc, entries, pkt)
        p4_detect = m is not None

        if py_detect != p4_detect:
            mism_detect += 1
            for name in fired:
                per_rule_mismatch[name] = per_rule_mismatch.get(name, 0) + 1
            if not fired and m:
                per_rule_mismatch["FALSO_POSITIVO_" + m["rule"]] = \
                    per_rule_mismatch.get("FALSO_POSITIVO_" + m["rule"], 0) + 1
        elif py_detect:
            hits += 1
            expected = {fns[n][1].attack for n in fired}
            if m["attack"] not in expected:
                mism_class += 1

    print(f"pacotes testados ......... {total}")
    print(f"detecções coincidentes ... {hits}")
    print(f"divergência detecção ..... {mism_detect}")
    print(f"divergência classe ....... {mism_class}")

    if per_rule_mismatch:
        print("\nregras com divergência:")
        for k, v in sorted(per_rule_mismatch.items(), key=lambda x: -x[1]):
            print(f"  {v:5d}  {k}")

    return 1 if (mism_detect or mism_class) else 0


if __name__ == "__main__":
    sys.exit(main())
