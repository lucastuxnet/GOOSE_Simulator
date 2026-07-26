# From Red Flags to Detection Rules, Revisited
## Benchmarking LLM-Generated Rules for Real-Time GOOSE Intrusion Detection on the P4Studio Simulator for Intel Tofino

**Authors:** Lucas A. Martins¹, Camilla B. Quincozes¹², Silvio E. Quincozes¹², Giovanni Siervo¹, Marcelo Caggiani Luizelli²
¹ Universidade Federal de Uberlândia (UFU) – Uberlândia, Brazil
² Universidade Federal do Pampa (UNIPAMPA) – Alegrete, Brazil

`{lucas.martins, camillaquincozes, sequincozes, gsiervo}@ufu.br`

`{marceloluizelli}@unipampa.edu.br`

---

## Overview

This project converts Python-defined detection rules into a P4_16/TNA program for the Intel Tofino ASIC (run here on the `tofino-model` simulator) and validates that the generated data plane classifies GOOSE (IEC 61850) traffic exactly as the reference Python oracle does.

| Stage | What happens | Where it runs |
|---|---|---|
| 1 | Install dependencies and SDE | host |
| 2 | Environment and virtual interfaces | host |
| 3 | Conversion: `rules_v1.py` → `goose_ids.p4` + `setup_rules.py` | host |
| 4 | Semantic validation (Python oracle) | host |
| 5 | Compile P4 | host |
| 6 | Populate tables via BF-Runtime | terminal 2 |
| 7 | Bring up `tofino-model` + `bf_switchd` | terminals 3 and 4 |
| 8 | Inject traffic and read counters | terminals 5 and 6 |

Stages 1–5 run without the switch. If something fails there, there is no point in bringing up the model.

---

## 1. Installing the SDE on Ubuntu 22.04

### Installing the dependencies

```bash
sudo apt update && sudo apt install -y \
  git \
  python3 \
  python3-pip \
  python3-venv \
  build-essential \
  cmake \
  libssl-dev \
  libbz2-dev \
  zlib1g-dev \
  libffi-dev \
  curl \
  ca-certificates \
  sudo \
  bison \
  flex \
  libboost-all-dev \
  libedit-dev \
  tcpreplay
```

### Installing P4Studio

```bash
cd ~
git clone https://github.com/p4lang/open-p4studio.git
cd open-p4studio
git submodule update --init --recursive

./p4studio/p4studio profile apply ./p4studio/profiles/testing.yaml
```

### Generating and loading the environment script

```bash
cd ~/open-p4studio
./create-setup-script.sh > ~/setup-open-p4studio.bash
echo 'source ~/setup-open-p4studio.bash' >> ~/.bashrc
source ~/setup-open-p4studio.bash
```

Confirm that the environment loaded:

```bash
echo "SDE.........: $SDE"
echo "SDE_INSTALL.: $SDE_INSTALL"
python3 --version
```

If `$SDE` is empty, the environment script was not sourced — review the installation before continuing.

---

## 2. Environment and virtual interfaces

Use **six separate terminal sessions** for a cleaner workflow. Every terminal must source the environment first (`source ~/setup-open-p4studio.bash`).

The virtual interfaces are created once per machine boot. In **terminal 1**:

```bash
{
  source ~/setup-open-p4studio.bash
  sudo ~/open-p4studio/install/bin/veth_setup.sh 128
  ip link show veth0 >/dev/null 2>&1 && echo "veths OK"
} 2>&1 | tee setup_veths.log
```

---

## 3. Convert and validate the rules

Clone the Python-to-P4 rule converter:

```bash
cd ~
git clone https://github.com/lucastuxnet/GOOSE_Simulator.git
cd GOOSE_Simulator/
```

Convert the rules and inspect the expansion:

```bash
python3 rules2p4.py rules_v1.py -o build --prog goose_ids --report | tee saida.txt
```

Expected output:

```
regras lidas ......... 21
campos ativos ........ 9
entradas ternárias ... 95
classes de ataque .... 8
```

Two files are produced in `build/`:

- `goose_ids.p4` — TNA program
- `setup_rules.py` — BF-Runtime script

### Interpreting `--report`

The report lists ranges and bits per field. **It is worth checking before compiling**, especially after regenerating the rules with the LLM:

- **Ternary entries much higher than ~4× the number of rules** → a new rule expanded too much. The `detect` table has `size = 2048`; beyond that, the compiler rejects it.
- **A field with too many ranges** → too many thresholds on the same field, growing the cartesian product.

### Common errors in this stage

| Message | Cause | Fix |
|---|---|---|
| `campos não mapeados em FIELDS` | Rule uses a new field | Add it to `FIELDS` in `field_model.py` with width, scale, and sign |
| `disjunção não suportada` | Rule uses `or` | Split it into two `rule_*` functions — the ternary match performs the union |
| `comparação precisa ser variável/get vs constante` | Arithmetic or comparison between two fields | Rewrite the rule or pre-compute the value |

### Validate before compiling

```bash
python3 validate.py rules_v1.py -n 100000 | tee validacao.txt
```

Acceptance criterion — **both divergence lines at zero**:

```
divergência detecção ..... 0
divergência classe ....... 0
```

A non-zero divergence means the translation does not preserve the semantics of the rules. Do not proceed: the pipeline will classify differently from Python.

The most likely cause is floating-point precision loss — if a new rule introduces a threshold with more decimal places than the field's scale supports, distinct values collapse into the same range. Increase the field's `scale` in `field_model.py` and revalidate.

---

## 4. Copy the converted P4 into P4Studio

```bash
mkdir -p ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids
cp build/goose_ids.p4 ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids/
```

---

## 5. Compile the P4

```bash
cd ~/open-p4studio/

p4c --target tofino --arch tna \
    --program-name goose_ids \
    --bf-rt-schema /open-p4studio/install/share/tofinopd/goose_ids/bf-rt.json \
    -o /open-p4studio/install/share/tofinopd/goose_ids \
    ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids/goose_ids.p4 \
    2>&1 | tee "p4c_build_$(date +%Y%m%d_%H%M%S).log"
```

List the produced artifacts:

```bash
ls -la /open-p4studio/install/share/tofinopd/goose_ids/ | tee listagem_goose_ids.txt
```

Verify that the essential artifacts exist:

```bash
{
  python3 -m json.tool /open-p4studio/install/share/p4/targets/tofino/goose_ids.conf >/dev/null && echo "JSON ok"

  for f in bf-rt.json pipe/context.json pipe/tofino.bin; do
    [ -f "/open-p4studio/install/share/tofinopd/goose_ids/$f" ] && echo "ok    $f" || echo "MISSING $f"
  done
} 2>&1 | tee verificacao.log
```

`context.json` and `pipe/tofino.bin` must be present. Without them the compilation failed, even if the script returned zero.

**If it fails on resources** (`table placement failed`, `not enough stages`): reduce the number of rules or consolidate nearby thresholds in the Python file. The report from stage 3 already flagged the risk.

---

## 6. Populate the tables

In **terminal 2**:

```bash
cd ~/open-p4studio/
./run_bfshell.sh -b ~/GOOSE_Simulator/build/setup_rules.py 2>&1 | tee "bfshell_setup_$(date +%Y%m%d_%H%M%S).log"
```

Expected output:

```
tbl_band_SqNum: 8 ranges
tbl_band_StNum: 7 ranges
...
detect: 95 entries
OK - rules loaded
```

### If you get an API syntax error

The `range match` parameter names vary between SDE versions. If you see `unexpected keyword argument`, inspect the real signature in the interactive `bfshell`:

```bash
./run_bfshell.sh
```

```
bfrt_python
bfrt.goose_ids.pipe.Ingress.tbl_band_SqNum.info(return_info=False)
bfrt.goose_ids.pipe.Ingress.detect.info(return_info=False)
```

This prints the exact key-field and action names. Adjust `bfrt_emitter.py` to match what appears and regenerate. The suffixes the script currently assumes are `_start`/`_end` for `range` and `_mask` for `ternary`.

---

## 7. Bring up the model and switchd

**Terminal 3** — model:

```bash
cd ~/open-p4studio/
./run_tofino_model.sh -p goose_ids --arch tofino 2>&1 | tee "tofino_model_$(date +%Y%m%d_%H%M%S).log"
```

**Terminal 4** — driver:

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio
./run_switchd.sh -p goose_ids --arch tofino 2>&1 | tee "switchd_$(date +%Y%m%d_%H%M%S).log"
```

Wait for the `bfshell>` prompt and the gRPC line:

```
bfshell> bfruntime gRPC server started on 0.0.0.0:50052
```

This takes one to two minutes. Before that, injection fails with connection refused.

---

## 8. Inject traffic and check

**Terminal 5** — generate the test PCAP and replay it:

```bash
cd ~/GOOSE_Simulator/
{
  echo "=== Generating test traffic - $(date) ==="
  python3 gen_test_traffic.py rules_v1.py -o test_goose.pcap
  echo ""

  echo "=== Checking veth interfaces ==="
  ip -br link show | grep veth | head
  echo ""

  echo "=== Replaying traffic ==="
  sudo tcpreplay -i veth0 test_goose.pcap
  echo ""
  echo "=== End - $(date) ==="
} 2>&1 | tee test_traffic.log
```

The generator prints the expected verdict table per packet:

```
  #  case                    expected         rules triggered
  1  normal_1                NORMAL           -
  2  normal_2                NORMAL           -
  3  grayhole_sq_tdiff       grayhole         rule_grayhole_sq_tdiff
  ...
19 packets -> test_goose.pcap  (17 should match in detect, 2 normal)
```

**Terminal 6** — read the counters:

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio
script -c "./run_bfshell.sh" bfshell_session.log
```

```
bfrt_python
d = bfrt.goose_ids.pipe.Ingress.detect
exec(open('~/GOOSE_Simulator/build/setup_rules.py').read())
hits()
```

**Expected result:** the sum of the `flag_attack` entry counters must match the number of attack packets from the generator (17), and the 2 normal packets fall into `no_attack`.

---

## Diagnostics

### Counters zeroed after injection

In order of likelihood:

1. **The packet never reached the GOOSE parser.** In terminal 3, the model log shows the valid headers per packet. If only `ethernet` appears (no `goose`), the EtherType did not match — check `0x88B8` in the PCAP:
   ```bash
   tcpdump -r test_goose.pcap -xx -c 1 | head -5
   ```
2. **Range tables not populated.** With no entries, every field falls into the `default_action` and goes to range 0, which rarely matches in `detect`:
   ```
   bfrt.goose_ids.pipe.Ingress.tbl_band_SqNum.dump()
   ```
3. **Wrong interface.** `veth_setup.sh` creates pairs; the model listens on a specific side. Try `veth1` if `veth0` does not work.

### Counters increment but on the wrong entry

Compare the returned `attack_id` with the table printed by the generator. A divergence here, with `validate.py` passing, points to a difference between the traffic generator's encoding and the control plane's — verify that `GOOSE_FIELDS` in `gen_test_traffic.py` is in the same order as `goose_feat_h` in `goose_ids.p4`.

### Error inserting entries with a repeated priority

This should not happen: each entry gets a unique priority (1 to 95), assigned in rule order. If it appears, `bfrt_emitter.py` was modified — uniqueness is mandatory in the TCAM.

---

## Iteration cycle

When regenerating the rules with the LLM, the short path:

```bash
cd ~/GOOSE_Simulator

# 1. convert and check the expansion
python3 rules2p4.py rules_v2.py -o build --prog goose_ids --report

# 2. validate — do not skip this step
python3 validate.py rules_v2.py -n 100000

# 3. recompile
cp build/goose_ids.p4 ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids/
cd ~/open-p4studio
p4c --target tofino --arch tna \
    --program-name goose_ids \
    --bf-rt-schema /open-p4studio/install/share/tofinopd/goose_ids/bf-rt.json \
    -o /open-p4studio/install/share/tofinopd/goose_ids \
    ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids/goose_ids.p4
```

If only the **thresholds** changed and the fields are the same, the P4 changes too — the ranges are derived from the constants. You cannot reload just the rules without recompiling.

---

## Important limitation

`goose_ids.p4` assumes the fields arrive ready in the `goose_feat_h` header. Four of them are derived and require per-publisher state (`gocbRef`):

| Field | How it is obtained |
|---|---|
| `tDiff` | difference between consecutive arrival timestamps |
| `stDiff` | variation of `StNum` |
| `sqDiff` | variation of `SqNum` |
| `timeFromLastChange` | time since the last `StNum` change |

On Tofino this requires `Register` + `RegisterAction` indexed by a hash of `gocbRef`. **This stage is not generated by the converter.** The traffic generator fills these values directly, which lets you validate the classification logic but does not replace the real extraction.

In production, this module must exist upstream. It is the hardest part of the complete implementation — each `RegisterAction` allows a single read-modify-write operation per stage.
