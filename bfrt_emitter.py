"""Emissão do script BF-Runtime que popula as tabelas geradas."""

import json
from typing import List
from rule_parser import Rule
from field_model import RangeEncoder


def build_entries(rules: List[Rule], enc: RangeEncoder):
    """Produz entradas ternárias. Regras com N campos livres viram
    produto cartesiano das faixas que satisfazem cada predicado; campos
    não citados ficam don't-care (mask 0)."""
    fields = enc.active_fields()
    attacks = sorted({r.attack for r in rules})
    attack_id = {a: i + 1 for i, a in enumerate(attacks)}

    entries = []
    prio = 0
    for rule_idx, rule in enumerate(rules, start=1):
        per_field = {}
        for p in rule.predicates:
            bands = set(enc.matching_bands(p.field, p.op, p.value))
            if p.field in per_field:
                per_field[p.field] &= bands
            else:
                per_field[p.field] = bands
        if any(not v for v in per_field.values()):
            continue

        combos = [{}]
        for f, bands in per_field.items():
            combos = [dict(c, **{f: b}) for c in combos for b in sorted(bands)]

        for combo in combos:
            prio += 1  # prioridade única: TCAM rejeita entradas com prioridade repetida
            key = {}
            for f in fields:
                w = enc.band_width(f)
                if f in combo:
                    key[f] = {"value": combo[f], "mask": (1 << w) - 1}
                else:
                    key[f] = {"value": 0, "mask": 0}
            entries.append({
                "rule": rule.name,
                "attack": rule.attack,
                "attack_id": attack_id[rule.attack],
                "rule_order": rule_idx,
                "priority": prio,
                "key": key,
            })
    return entries, attack_id


TEMPLATE = '''#!/usr/bin/env python3
"""Populado por rules2p4. Executar via: run_bfshell.sh -b setup_rules.py

Nomes de parâmetro conforme a API bfrt_python:
  - ação da tabela de faixa tem sufixo do campo: add_with_set_band_<campo>
  - chave RANGE usa apenas o último componente: <campo>_start / <campo>_end
  - prioridade é MATCH_PRIORITY (sem cifrão, sem underscore inicial)
  - chave TERNARY da detect usa band_<campo> / band_<campo>_mask
"""

import json

P4_NAME = "{prog}"
BANDS = json.loads(r"""{bands_json}""")
ENTRIES = json.loads(r"""{entries_json}""")

p4 = bfrt.{prog}.pipe


def populate_bands():
    total = 0
    for field, ranges in BANDS.items():
        tbl = getattr(p4.Ingress, "tbl_band_" + field)
        tbl.clear()
        add = getattr(tbl, "add_with_set_band_" + field)
        for idx, (lo, hi) in enumerate(ranges):
            add(**{{
                field + "_start": lo,
                field + "_end": hi,
                "MATCH_PRIORITY": idx,
                "idx": idx,
            }})
        total += len(ranges)
        print("  tbl_band_%-20s %d faixas" % (field, len(ranges)))
    print("faixas inseridas: %d" % total)


def populate_detect():
    tbl = p4.Ingress.detect
    tbl.clear()
    for e in ENTRIES:
        kwargs = {{"MATCH_PRIORITY": e["priority"]}}
        for field, k in e["key"].items():
            kwargs["band_" + field] = k["value"]
            kwargs["band_" + field + "_mask"] = k["mask"]
        # Ação nomeada por classe (Opção A): sem parâmetro attack_id.
        add = getattr(tbl, "add_with_flag_" + e["attack"])
        add(**kwargs)
    print("detect: %d entradas" % len(ENTRIES))


def show_counters():
    """Contadores por entrada. Chame após injetar tráfego."""
    tbl = p4.Ingress.detect
    tbl.operation_counter_sync()
    tbl.dump(from_hw=True)


def hits():
    """Só as entradas que contaram pacotes, agrupadas por classe.

    Lê pela ação da entrada (flag_<classe>), sem parsear texto do dump —
    a classe vem do nome da ação, não de um campo de dado.
    Nesta versão do SDE, ent.data já é um dict com chaves em bytes.
    """
    tbl = p4.Ingress.detect
    tbl.operation_counter_sync()
    por_classe = {{}}
    total = 0
    for ent in tbl.get(regex=True, print_ents=False):
        d = ent.data
        if hasattr(d, "to_dict"):
            d = d.to_dict()
        pkts = d.get(b"$COUNTER_SPEC_PKTS", d.get("$COUNTER_SPEC_PKTS", 0)) or 0
        if not pkts:
            continue
        acao = getattr(ent, "action", None) or "?"
        classe = acao.split("flag_", 1)[-1] if "flag_" in acao else acao
        por_classe[classe] = por_classe.get(classe, 0) + pkts
        total += pkts
    for classe in sorted(por_classe):
        print("%4d pkts  %s" % (por_classe[classe], classe))
    print("---")
    print("%d classes com trafego, %d pacotes no total" % (len(por_classe), total))


populate_bands()
populate_detect()
print("OK - regras carregadas")
'''


def emit(rules: List[Rule], enc: RangeEncoder, prog: str = "goose_ids") -> str:
    entries, attack_id = build_entries(rules, enc)
    bands = {f: enc.bands(f) for f in enc.active_fields()}
    return TEMPLATE.format(
        prog=prog,
        bands_json=json.dumps(bands),
        entries_json=json.dumps(entries),
    ), entries, attack_id
