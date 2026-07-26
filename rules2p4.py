#!/usr/bin/env python3
"""Conversor de regras Python -> P4 (TNA/Tofino) + script BF-Runtime.

Uso:
    python3 rules2p4.py rules_v1.py -o build/ --prog goose_ids
"""

import argparse
import os
import sys

from rule_parser import parse_rules_file
from field_model import FIELDS, RangeEncoder
import p4_emitter
import bfrt_emitter


def main():
    ap = argparse.ArgumentParser(description="Regras Python -> P4 TNA")
    ap.add_argument("rules", help="arquivo .py com funções rule_*")
    ap.add_argument("-o", "--outdir", default="build")
    ap.add_argument("--prog", default="goose_ids")
    ap.add_argument("--report", action="store_true", help="imprime resumo das faixas")
    args = ap.parse_args()

    rules = parse_rules_file(args.rules)
    if not rules:
        sys.exit("nenhuma regra encontrada")

    unknown = {p.field for r in rules for p in r.predicates} - set(FIELDS)
    if unknown:
        sys.exit(f"campos não mapeados em FIELDS: {sorted(unknown)}")

    # O range match do Tofino exige chave de no máximo 4 nibbles (16 bits).
    # Acima disso o p4c falha com "does not fit in under 5 PHV nibbles".
    wide = {f for r in rules for p in r.predicates
            if (f := p.field) and FIELDS[f].width > 16}
    if wide:
        sys.exit(
            f"campos acima de 16 bits usados em range match: {sorted(wide)}\n"
            "O Tofino rejeita chaves de range com mais de 4 nibbles.\n"
            "Reduza a largura em field_model.py, ajustando 'scale' para que\n"
            "os limiares das regras caibam no novo domínio."
        )

    # Limiares fora do domínio representável saturam e alteram a semântica.
    # Um limiar exatamente no extremo também é problema: `x < lim` nunca
    # dispara se não houver espaço codificável abaixo dele.
    for r in rules:
        for p in r.predicates:
            spec = FIELDS[p.field]
            raw = int(round(p.value * spec.scale)) + spec.offset
            hi = (1 << spec.width) - 1
            if raw < 0 or raw > hi:
                sys.exit(
                    f"limiar {p.value} do campo {p.field} (regra {r.name}) "
                    f"estoura {spec.width} bits.\n"
                    "Ajuste 'scale' ou 'bias' em field_model.py."
                )
            # Só campos deslocados (com offset) têm risco de saturação
            # semanticamente relevante: em campos naturalmente não-negativos,
            # zero é o piso real e `x < 5` funciona como esperado.
            if spec.offset:
                margem = 0.02 * hi
                if p.op in ("<", "<=") and raw < margem:
                    sys.exit(
                        f"limiar {p.value} do campo {p.field} (regra {r.name}) "
                        f"fica no extremo inferior do domínio (codificado {raw}).\n"
                        f"Valores abaixo dele saturam e deixam de satisfazer "
                        f"'{p.op}'.\nAumente 'bias' em field_model.py."
                    )
                if p.op in (">", ">=") and raw > hi - margem:
                    sys.exit(
                        f"limiar {p.value} do campo {p.field} (regra {r.name}) "
                        f"fica no extremo superior do domínio (codificado {raw}).\n"
                        "Reduza 'bias' ou 'scale' em field_model.py."
                    )

    enc = RangeEncoder(rules)
    os.makedirs(args.outdir, exist_ok=True)

    p4_src = p4_emitter.emit(rules, enc, args.prog)
    p4_path = os.path.join(args.outdir, f"{args.prog}.p4")
    with open(p4_path, "w", encoding="utf-8") as f:
        f.write(p4_src)

    bfrt_src, entries, attack_id = bfrt_emitter.emit(rules, enc, args.prog)
    bfrt_path = os.path.join(args.outdir, "setup_rules.py")
    with open(bfrt_path, "w", encoding="utf-8") as f:
        f.write(bfrt_src)

    print(f"regras lidas ......... {len(rules)}")
    print(f"campos ativos ........ {len(enc.active_fields())}")
    print(f"entradas ternárias ... {len(entries)}")
    print(f"classes de ataque .... {len(attack_id)}")
    print(f"\n{p4_path}\n{bfrt_path}")

    if args.report:
        print("\n--- faixas por campo ---")
        for f in enc.active_fields():
            b = enc.bands(f)
            print(f"{f:22s} {len(b):3d} faixas, {enc.band_width(f)} bits")
        print("\n--- ataques ---")
        for a, i in attack_id.items():
            print(f"  {i:2d}  {a}")


if __name__ == "__main__":
    main()
