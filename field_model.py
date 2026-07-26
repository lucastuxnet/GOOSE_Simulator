"""Modelo de campos GOOSE: largura, escala e discretização em faixas."""

from dataclasses import dataclass
from typing import Dict, List, Tuple
from rule_parser import Rule


@dataclass
class FieldSpec:
    """scale converte float do plano de controle para inteiro do dataplane.
    signed indica campos que assumem valores negativos (offset binário).

    LARGURA MÁXIMA 16 BITS: o range match do Tofino exige que a chave caiba
    em 4 nibbles. Chaves de 32 bits são rejeitadas pelo p4c com
    "does not fit in under 5 PHV nibbles"."""
    name: str
    width: int
    scale: float = 1
    signed: bool = False
    bias: int = None   # offset explícito; se None, usa 2^(w-1) quando signed

    @property
    def p4_type(self) -> str:
        return f"bit<{self.width}>"

    @property
    def offset(self) -> int:
        if self.bias is not None:
            return self.bias
        return (1 << (self.width - 1)) if self.signed else 0

    def encode(self, value: float) -> int:
        v = int(round(value * self.scale)) + self.offset
        return max(0, min(v, (1 << self.width) - 1))


# Larguras limitadas a 16 bits (restrição do range match no Tofino).
# Escalas escolhidas para que os limiares das regras caibam no domínio:
#   stDiff        usa bias explícito de 62000 em vez do offset binário padrão:
#                 o limiar -40000 exigiria domínio de 40001 valores negativos,
#                 acima dos 32768 do offset simétrico. Escala fracionária não
#                 serve aqui — colapsaria -40001 e -39999 no mesmo inteiro,
#                 destruindo a fronteira do predicado.
#   timestampDiff usa 10^4 para preservar 4 casas decimais (limiar 0.1721).
#   delay         usa 10^6 para preservar o limiar 0.001 (=> 1000).
FIELDS: Dict[str, FieldSpec] = {
    "SqNum":              FieldSpec("SqNum", 16),
    "StNum":              FieldSpec("StNum", 16),
    "cbStatus":           FieldSpec("cbStatus", 8),
    "sqDiff":             FieldSpec("sqDiff", 16, signed=True),
    "stDiff":             FieldSpec("stDiff", 16, bias=62000),
    "tDiff":              FieldSpec("tDiff", 16, signed=True),
    "timeFromLastChange": FieldSpec("timeFromLastChange", 16),
    "timestampDiff":      FieldSpec("timestampDiff", 16, scale=10_000, signed=True),
    "delay":              FieldSpec("delay", 16, scale=1_000_000),
}


class RangeEncoder:
    """Converte predicados numéricos em bitmaps de faixa.

    Cada campo recebe pontos de corte derivados das constantes das regras.
    Uma tabela exact mapeia valor -> índice de faixa; o índice vira chave
    ternária na tabela de detecção, permitindo don't-care por regra.
    """

    def __init__(self, rules: List[Rule]):
        self.cuts: Dict[str, List[int]] = {}
        self._build_cuts(rules)

    def _build_cuts(self, rules: List[Rule]):
        """Pontos de corte no domínio codificado.

        Com escala fracionária (< 1), valores reais distintos colapsam no
        mesmo inteiro. Para que a fronteira do predicado caia ENTRE dois
        inteiros — e não sobre um valor ambíguo — o corte é calculado a
        partir do menor incremento representável, garantindo que
        `x > v` e `x <= v` fiquem em faixas distintas.
        """
        raw: Dict[str, set] = {}
        for rule in rules:
            for p in rule.predicates:
                spec = FIELDS[p.field]
                enc = spec.encode(p.value)
                # Menor passo real que altera o valor codificado.
                step = 1.0 / spec.scale if spec.scale else 1.0
                enc_next = spec.encode(p.value + step)
                if p.op == ">":
                    # primeira faixa acima do limiar
                    raw.setdefault(p.field, set()).add(max(enc + 1, enc_next))
                elif p.op == ">=":
                    raw.setdefault(p.field, set()).add(enc)
                elif p.op == "<":
                    raw.setdefault(p.field, set()).add(enc)
                elif p.op == "<=":
                    raw.setdefault(p.field, set()).add(max(enc + 1, enc_next))
                elif p.op in ("==", "!="):
                    raw.setdefault(p.field, set()).update(
                        {enc, max(enc + 1, enc_next)})
        for f, s in raw.items():
            self.cuts[f] = sorted(s)

    def bands(self, field: str) -> List[Tuple[int, int]]:
        """Faixas [lo, hi] cobrindo todo o domínio do campo."""
        spec = FIELDS[field]
        cuts = self.cuts.get(field, [])
        edges = [0] + cuts + [(1 << spec.width)]
        out = []
        for i in range(len(edges) - 1):
            lo, hi = edges[i], edges[i + 1] - 1
            if lo <= hi:
                out.append((lo, hi))
        return out

    def band_width(self, field: str) -> int:
        n = len(self.bands(field))
        w = max(1, (n - 1).bit_length())
        return min(w, 16)

    def matching_bands(self, field: str, op: str, value: float) -> List[int]:
        """Índices de faixa que satisfazem o predicado."""
        spec = FIELDS[field]
        enc = spec.encode(value)
        out = []
        for i, (lo, hi) in enumerate(self.bands(field)):
            ok = {
                ">":  lo > enc,
                ">=": lo >= enc,
                "<":  hi < enc,
                "<=": hi <= enc,
                "==": lo <= enc <= hi,
                "!=": not (lo <= enc <= hi),
            }[op]
            if ok:
                out.append(i)
        return out

    def active_fields(self) -> List[str]:
        return sorted(self.cuts.keys())
