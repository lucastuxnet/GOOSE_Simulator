"""Extração de predicados de regras Python via AST."""

import ast
from dataclasses import dataclass, field
from typing import List, Optional


OPS = {
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.Eq: "==",
    ast.NotEq: "!=",
}


@dataclass
class Predicate:
    field: str
    op: str
    value: float

    def __repr__(self):
        return f"{self.field} {self.op} {self.value}"


@dataclass
class Rule:
    name: str
    attack: str
    predicates: List[Predicate] = field(default_factory=list)

    @property
    def fields(self):
        return sorted({p.field for p in self.predicates})


class RuleExtractor(ast.NodeVisitor):
    """Percorre o AST e coleta regras no formato rule_<attack>_<variant>."""

    def __init__(self):
        self.rules: List[Rule] = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if not node.name.startswith("rule_"):
            return
        aliases = self._collect_aliases(node)
        ret = self._find_return(node)
        if ret is None:
            return
        preds = self._parse_condition(ret, aliases)
        if preds:
            self.rules.append(
                Rule(name=node.name, attack=self._attack_name(node.name), predicates=preds)
            )

    # Classes conhecidas do dataset GOOSE; o sufixo após a classe é a variante.
    ATTACK_CLASSES = [
        "masquerade_fake_fault",
        "masquerade_fake_normal",
        "poisoned_high_rate",
        "inverse_replay",
        "random_replay",
        "high_StNum",
        "injection",
        "grayhole",
    ]

    def _attack_name(self, fn_name: str) -> str:
        rest = fn_name[len("rule_"):]
        for cls in self.ATTACK_CLASSES:
            if rest.startswith(cls):
                return cls
        return rest.rsplit("_", 1)[0] if "_" in rest else rest

    def _collect_aliases(self, node) -> dict:
        """Mapeia variáveis locais -> chave real do dict (packet.get("X", 0))."""
        aliases = {}
        for stmt in node.body:
            if not isinstance(stmt, ast.Assign):
                continue
            if not isinstance(stmt.value, ast.Call):
                continue
            call = stmt.value
            if not (isinstance(call.func, ast.Attribute) and call.func.attr == "get"):
                continue
            if not call.args or not isinstance(call.args[0], ast.Constant):
                continue
            target = stmt.targets[0]
            if isinstance(target, ast.Name):
                aliases[target.id] = call.args[0].value
        return aliases

    def _find_return(self, node) -> Optional[ast.AST]:
        for stmt in reversed(node.body):
            if isinstance(stmt, ast.Return) and stmt.value is not None:
                return stmt.value
        return None

    def _parse_condition(self, node, aliases) -> List[Predicate]:
        """Aceita conjunções de comparações binárias. Rejeita OR e formas complexas."""
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.Or):
                raise ValueError("disjunção não suportada; separe em regras distintas")
            out = []
            for v in node.values:
                out.extend(self._parse_condition(v, aliases))
            return out

        if isinstance(node, ast.Compare):
            return [self._parse_compare(node, aliases)]

        raise ValueError(f"expressão não suportada: {ast.dump(node)[:80]}")

    def _parse_compare(self, node: ast.Compare, aliases) -> Predicate:
        if len(node.ops) != 1:
            raise ValueError("comparação encadeada não suportada")
        op_type = type(node.ops[0])
        if op_type not in OPS:
            raise ValueError(f"operador não suportado: {op_type.__name__}")

        left, right = node.left, node.comparators[0]
        op = OPS[op_type]

        l_name = self._operand_name(left, aliases)
        r_name = self._operand_name(right, aliases)
        l_const = self._const_value(left)
        r_const = self._const_value(right)

        if l_name is not None and r_const is not None:
            name, value = l_name, r_const
        elif r_name is not None and l_const is not None:
            name, value = r_name, l_const
            op = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}.get(op, op)
        else:
            raise ValueError("comparação precisa ser variável/get vs constante")

        return Predicate(field=name, op=op, value=float(value))

    def _const_value(self, node):
        """Constante numérica, incluindo negativas (UnaryOp USub)."""
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if (isinstance(node, ast.UnaryOp)
                and isinstance(node.op, ast.USub)
                and isinstance(node.operand, ast.Constant)):
            return -node.operand.value
        return None

    def _operand_name(self, node, aliases):
        """Resolve variável local ou packet.get("X", 0) inline."""
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and isinstance(node.args[0], ast.Constant)):
            return node.args[0].value
        return None


def parse_rules_file(path: str) -> List[Rule]:
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    extractor = RuleExtractor()
    extractor.visit(tree)
    return extractor.rules
