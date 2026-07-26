#!/usr/bin/env bash
#
# Automatiza: conversão -> validação -> compilação P4.
# Não sobe o modelo nem popula tabelas: essas etapas exigem terminais
# separados e são feitas manualmente (ver GUIA_rules2p4_tofino.md).
#
# Uso:
#   ./deploy.sh ~/rules_v1.py
#   ./deploy.sh ~/rules_v1.py --skip-build     # só gera e valida
#   ./deploy.sh ~/rules_v1.py --packets 200000

set -euo pipefail

RULES="${1:-}"
PROG="goose_ids"
OUTDIR="build"
PACKETS=100000
SKIP_BUILD=0

shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=1; shift ;;
        --packets)    PACKETS="$2"; shift 2 ;;
        --prog)       PROG="$2"; shift 2 ;;
        *) echo "opção desconhecida: $1" >&2; exit 2 ;;
    esac
done

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[1;33m'; NC=$'\033[0m'
ok()   { echo "${GRN}✓${NC} $*"; }
warn() { echo "${YEL}!${NC} $*"; }
die()  { echo "${RED}✗${NC} $*" >&2; exit 1; }
step() { echo; echo "${YEL}==>${NC} $*"; }

[[ -n "$RULES" ]] || die "uso: $0 <arquivo_regras.py> [--skip-build] [--packets N]"
[[ -f "$RULES" ]] || die "arquivo não encontrado: $RULES"

# ---------------------------------------------------------------- ambiente
step "Verificando ambiente"

if [[ $SKIP_BUILD -eq 0 ]]; then
    [[ -n "${SDE:-}" ]] || die "\$SDE vazio. Rode: source ~/setup-open-p4studio.bash"
    [[ -n "${SDE_INSTALL:-}" ]] || die "\$SDE_INSTALL vazio."
    [[ -d "$SDE" ]] || die "\$SDE aponta para diretório inexistente: $SDE"
    ok "SDE: $SDE"
else
    warn "--skip-build: pulando verificação do SDE"
fi

command -v python3 >/dev/null || die "python3 não encontrado"
ok "python3: $(python3 --version 2>&1)"

# ---------------------------------------------------------------- conversão
step "Convertendo regras -> P4"

python3 rules2p4.py "$RULES" --outdir "$OUTDIR" --prog "$PROG" --report \
    || die "conversão falhou"

P4_FILE="$OUTDIR/$PROG.p4"
RULES_FILE="$OUTDIR/setup_rules.py"
[[ -f "$P4_FILE" ]]    || die "não gerado: $P4_FILE"
[[ -f "$RULES_FILE" ]] || die "não gerado: $RULES_FILE"
ok "$P4_FILE"
ok "$RULES_FILE"

# Alerta de expansão: >2048 estoura o size da tabela detect.
N_ENTRIES=$(python3 - "$RULES" <<'PY'
import sys
sys.path.insert(0, '.')
from rule_parser import parse_rules_file
from field_model import RangeEncoder
from bfrt_emitter import build_entries
rules = parse_rules_file(sys.argv[1])
enc = RangeEncoder(rules)
entries, _ = build_entries(rules, enc)
print(len(entries))
PY
)

if [[ "$N_ENTRIES" -gt 2048 ]]; then
    die "$N_ENTRIES entradas excedem size=2048 da tabela detect"
elif [[ "$N_ENTRIES" -gt 1024 ]]; then
    warn "$N_ENTRIES entradas — acima de 50% da capacidade (2048)"
else
    ok "$N_ENTRIES entradas ternárias (limite 2048)"
fi

# ---------------------------------------------------------------- validação
step "Validando equivalência semântica ($PACKETS pacotes)"

if python3 validate.py "$RULES" -n "$PACKETS"; then
    ok "equivalência confirmada"
else
    die "DIVERGÊNCIA SEMÂNTICA — o pipeline classificaria diferente do Python.
    Causa provável: escala insuficiente em campo de ponto flutuante.
    Verifique 'scale' em field_model.py para os campos das regras divergentes."
fi

# ---------------------------------------------------------------- compilação
if [[ $SKIP_BUILD -eq 1 ]]; then
    step "Compilação pulada (--skip-build)"
    echo
    echo "Para compilar:"
    echo "  cp $P4_FILE \$SDE/pkgsrc/p4-examples/p4_16_programs/$PROG/"
    echo "  cd \$SDE && ./p4_build.sh pkgsrc/p4-examples/p4_16_programs/$PROG/$PROG.p4"
    exit 0
fi

step "Compilando P4"

TARGET_DIR="$SDE/pkgsrc/p4-examples/p4_16_programs/$PROG"
mkdir -p "$TARGET_DIR"
cp "$P4_FILE" "$TARGET_DIR/"
ok "copiado para $TARGET_DIR"

pushd "$SDE" >/dev/null
./p4_build.sh "pkgsrc/p4-examples/p4_16_programs/$PROG/$PROG.p4" \
    || { popd >/dev/null; die "compilação P4 falhou"; }
popd >/dev/null

# p4_build.sh pode retornar 0 sem produzir artefatos — confira explicitamente.
ARTIFACTS="$SDE_INSTALL/share/tofinopd/$PROG"
[[ -f "$ARTIFACTS/context.json" ]] \
    || die "context.json ausente em $ARTIFACTS — compilação não produziu artefatos"
ok "artefatos em $ARTIFACTS"

# ---------------------------------------------------------------- resumo
cat <<EOF

${GRN}Pronto.${NC} Próximos passos, em terminais separados:

  ${YEL}Terminal 1${NC}  cd \$SDE && ./run_tofino_model.sh -p $PROG --arch tofino
  ${YEL}Terminal 2${NC}  cd \$SDE && ./run_switchd.sh -p $PROG --arch tofino
              (aguarde o prompt 'bfshell>' e a linha do gRPC)
  ${YEL}Terminal 3${NC}  cd \$SDE && ./run_bfshell.sh -b $(pwd)/$RULES_FILE
  ${YEL}Terminal 4${NC}  python3 gen_test_traffic.py $RULES -o test_goose.pcap
              sudo tcpreplay -i veth0 test_goose.pcap

Interfaces veth (uma vez por boot):
  sudo \${SDE_INSTALL}/bin/veth_setup.sh 128
EOF
