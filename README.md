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

It is the **hardware/data-plane extension** of the rule-generation tool published in the Tools Track of **SBRC 2026** (see [Relationship to the SBRC 2026 tool](#relationship-to-the-sbrc-2026-tool)). While the SBRC tool produces detection rules from labeled GOOSE traffic with an LLM-driven pipeline, this repository takes those Python rules and compiles them into a real Tofino data plane, closing the loop from *red-flag extraction* to *line-rate detection*.

| Stage | What happens | Where it runs |
|-------|--------------|---------------|
| 1 | Install dependencies and SDE | host |
| 2 | Environment and virtual interfaces | host |
| 3 | Conversion: `rules_vN.py` → `goose_ids.p4` + `setup_rules.py` | host |
| 4 | Semantic validation (Python oracle) | host |
| 5 | Compile P4 | host |
| 6 | Populate tables via BF-Runtime | terminal 2 |
| 7 | Bring up `tofino-model` + `bf_switchd` | terminals 3 and 4 |
| 8 | Inject traffic and read counters | terminals 5 and 6 |

Stages 1–5 run without the switch. If something fails there, there is no point in bringing up the model.

---

## Relationship to the SBRC 2026 tool

The rule sets consumed by this simulator (`rules_v1.py`, `rules_v2.py`, `rules_v3.py`) originate from the **LLM-driven rule-generation pipeline** presented at SBRC 2026:

> MARTINS, Lucas A.; QUINCOZES, Camilla B.; SIERVO, Giovanni; QUINCOZES, Silvio E.; LUIZELLI, Marcelo Caggiani. **From Red Flags to Detection Rules: An LLM-driven Pipeline for Real-Time GOOSE Intrusion Detection and Prevention**. *In*: Salão de Ferramentas — Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC), 44., 2026, Praia do Forte/BA. Anais [...]. Porto Alegre: SBC, 2026. p. 57–65. DOI: [10.5753/sbrc_estendido.2026.23263](https://doi.org/10.5753/sbrc_estendido.2026.23263).

That tool identifies behavioral *red flags* in the ERENO dataset and emits executable Python detection functions. **This repository is the deployment stage**: `rules2p4.py` translates those functions into a P4_16/TNA program plus a BF-Runtime population script, and validates that the compiled data plane reproduces the Python oracle's verdicts bit-for-bit.

---

## Tool Versioning

This section tracks the evolution of the simulator itself and of the converter and rule sets it consumes.

### Simulator releases

| Version | Date | Summary |
|---|---|---|
| **v1** | June 14, 2026 | First working end-to-end pipeline: convert (`rules2p4.py`) → validate → compile → populate → inject → read counters on `tofino-model`. |
| **v2** | July 16, 2026 | Correctness pass fixing issues that were affecting the final results (see [Changes in v2](#changes-in-v2)). This is the version that reproduces the reported metrics. |

> Use **v2 or later**. The v1 pipeline ran end to end but produced detection results skewed by the issues corrected in v2.

### Changes in v2 (July 16, 2026)

The v2 revision corrected defects that were silently distorting the final detection output in v1:

- **Rule-to-class attribution** — per-class named actions (`flag_grayhole`, `flag_injection`, …) were consolidated so that a hit is credited to the correct attack class instead of a generic `flag_attack`, fixing counters that incremented on the wrong entry.
- **Parser branch parity** — the VLAN-tagged and untagged GOOSE paths now yield identical counters; previously only one branch matched.
- **Range-boundary precision** — thresholds with more decimal places than the field scale collapsed into the same band; field scales in `field_model.py` were adjusted so `validate.py` reports zero divergence.
- **Priority uniqueness** — every TCAM entry receives a unique priority (1..N) in rule order, preventing insertion errors on repeated priorities.
- **Operational ordering** — documented the mandatory *populate → inject → read* order; re-running populate after injection was resetting counters.

### `rules2p4.py` converter history

The converter has gone through **three iterations**:

| Converter rev. | Consumed by | Key change |
|---|---|---|
| rev. 1 | `rules_v1.py` | Initial Python AST → P4_16/TNA translation with ternary `detect` table and per-field range (band) tables. |
| rev. 2 | `rules_v2.py` | Named per-class actions, VLAN/untagged parser parity, corrected priority assignment, scale fixes surfaced by `validate.py`. |
| rev. 3 | `rules_v3.py` | Threshold/rule-set refinements from a regenerated LLM run; same field model, re-derived ranges (requires recompilation). |

## LLMs and Generated Rule Sets

This document describes the three large language models (LLMs) used to generate the rule sets for the specification-based intrusion detection system (IDS) for **GOOSE / IEC 61850** traffic. Each model produced one version of the rules file (`rules_v1/2/3.py`), enabling a comparative analysis of coverage and detection quality.

All figures below were extracted directly from the notebook runs (`SBRC_2026_LLM_IDS_GOOSE_v{1,2,3}.ipynb`) over the **ERENO 2.0** dataset (200,052 samples: 39,999 normal + 8 attack classes with ~20,000 samples each).

> **Note on the figures.** The files `matriz_regras_ataques_plot_v2.png` and `matriz_regras_ataques_plot_v3.png` were saved with **swapped suffixes**: the figure with 3 bars corresponds to **v3 (Qwen, 3 rules)** and the figure with ~22 bars corresponds to **v2 (Llama, 22 rules)**. This README uses the correct mapping (verified against the notebooks), not the filename order. It's worth renaming the PNGs before reusing them.

---

## How to read the `rules × classes` matrix

Each `matriz_regras_ataques_plot_v*.png` figure is built by `build_rule_class_matrix`:

- **Each row = one IDS rule** (`rule_*`).
- **The color of each segment = the true class** of the samples that triggered that rule.
- **The numbers inside the bars = absolute count** of triggers per class.

Therefore, a **single-color** rule is **specific** (fires for only one true class); a **multi-color** rule is **unspecific** (fires across several true classes, contributing to cross-class false positives). Broad coverage with unspecific rules is not necessarily better than lean coverage with specific rules — what matters is the balance between recall and the false-positive rate (FPR).

---

## Rule sets overview

| File | Generator model | Rules loaded | Classes covered | Global FPR |
|:---|:---|:---:|:---:|:---:|
| `rules_v1.py` | `openai/gpt-oss-120b` | 21 | 8 / 8 | 11.6% |
| `rules_v2.py` | `llama-3.3-70b-versatile` | 22 | 8 / 8 | 35.3% |
| `rules_v3.py` | `qwen/qwen3-32b` | 3 | 2 / 8 | 4.2% |

> **Recommendation:** for publication, use **`rules_v1.py` (GPT-OSS-120B)** as the main configuration. It offers the best **balance between recall and FPR**: it covers all 8 classes with an 11.6% FPR, whereas v2 only reaches higher recall at the cost of a 35.3% FPR (unacceptable for an IDS), and v3, despite the lowest FPR, fails to cover 6 of the 8 classes.

---

## Model details

### 1. `openai/gpt-oss-120b` → `rules_v1.py` (recommended baseline)

| Feature | Detail |
|:---|:---|
| Architecture | Mixture of Experts (MoE) — 117B total parameters, ~5.1B active per token |
| Key differentiator | Deep reasoning with adjustable Chain-of-Thought (CoT) across three levels |
| Role in generation | Exploratory generator — produced the most balanced set |
| Rules | **21 rules** covering all **8 attack classes** |
| Global FPR | **11.6%** (4,625 normal samples flagged as attack) |

**Why it is recommended**

- **Full coverage** of the 8 classes: `grayhole`, `high_StNum`, `injection`, `inverse_replay`, `masquerade_fake_fault`, `masquerade_fake_normal`, `poisoned_high_rate`, `random_replay`.
- **Only one to reach 100% recall** on `poisoned_high_rate`, plus strong recall on `high_StNum` (93.8%) and `injection` (68.2%).
- **Built-in FPR filter** during generation: rules above 5% mean FPR were rejected (e.g., `rule_grayhole_sq_stnum`, FPR 7.2% — rejected).
- **Balance**: global FPR of 11.6%, roughly 3× lower than v2, while keeping full coverage.

**Limitation:** low recall on hard classes — `grayhole` (5.7%) and `random_replay` (12.9%).

---

### 2. `llama-3.3-70b-versatile` → `rules_v2.py`

| Feature | Detail |
|:---|:---|
| Architecture | Dense Transformer — 70B parameters with Grouped-Query Attention (GQA) |
| Key differentiator | Good balance of accuracy, cost, and scalability |
| Role in generation | Highest raw recall — more aggressive rules |
| Rules | **22 rules** covering all **8 classes** |
| Global FPR | **35.3%** (14,121 normal samples flagged as attack) |
| Cost | Best cost-benefit ($0.59 / 1M input, $0.79 / 1M output) |

**Observations**

- **Highest recall on most classes** — beats v1 on `injection` (87.7%), `masquerade_fake_normal` (82.6%), `masquerade_fake_fault` (58.6%), and `random_replay` (32.2%).
- **Critical issue:** FPR of **35.3%**. More than a third of normal traffic is classified as attack, which makes it operationally unusable despite the high recall.
- **Unfavorable trade-off:** the broader rules simultaneously raised both detection and false positives.

---

### 3. `qwen/qwen3-32b` → `rules_v3.py`

| Feature | Detail |
|:---|:---|
| Architecture | Dense — 32.8B parameters |
| Key differentiator | Toggleable "thinking" mode (deep reasoning or fast responses) |
| Role in generation | Aggressive refiner — drastically reduced the set |
| Rules | **3 rules** (`rule_injection_sq_st`, `rule_poisoned_high_rate_1`, `rule_poisoned_high_rate_2`) |
| Classes covered | only **2 / 8** (`injection`, `poisoned_high_rate`) |
| Global FPR | **4.2%** (the lowest of the three) |

**Observations**

- **Lowest FPR (4.2%)** and good precision on the two classes it covers — `poisoned_high_rate` (93.8%) and `injection` (64.1%).
- **Critically insufficient coverage:** zeroes out three whole classes — `inverse_replay` (0%), `masquerade_fake_normal` (0%) — and detects very little on `high_StNum` (25.5%), `grayhole` (3.9%), and `random_replay` (4.3%).
- **Over-refinement:** the process reduced the set to just 3 rules, sacrificing almost all coverage in exchange for a low FPR.

---

## Comparative analysis — recall per class

Recall (TPR) per attack class; **FPR** is the global false-positive rate (measured over normal traffic).

| Class (support) | v1 — GPT-OSS | v2 — Llama | v3 — Qwen |
|:---|:---:|:---:|:---:|
| grayhole (19,999) | 5.7% | 31.5% | 3.9% |
| high_StNum (20,000) | **93.8%** | 93.4% | 25.5% |
| injection (20,000) | 68.2% | **87.7%** | 64.1% |
| inverse_replay (20,000) | 51.6% | **56.3%** | 0% |
| masquerade_fake_fault (20,000) | 33.0% | **58.6%** | 6.1% |
| masquerade_fake_normal (20,000) | 26.2% | **82.6%** | 0% |
| poisoned_high_rate (20,000) | **100%** | 98.2% | 93.8% |
| random_replay (20,000) | 12.9% | **32.2%** | 4.3% |
| **Classes covered** | **8 / 8** | **8 / 8** | **2 / 8** |
| **Number of rules** | **21** | **22** | **3** |
| **Global FPR** | **11.6%** | 35.3% | **4.2%** |

---

## Decision matrix

| If your goal is… | Recommended model | Rule set |
|:---|:---|:---|
| **Best recall × FPR balance** | **GPT-OSS-120B** | `rules_v1.py` ⭐ |
| **Full coverage of all 8 classes with controlled FPR** | **GPT-OSS-120B** | `rules_v1.py` ⭐ |
| **Publish balanced, defensible results** | **GPT-OSS-120B** | `rules_v1.py` ⭐ |
| Maximize recall (accepting a 35% FPR) | Llama-3.3-70B | `rules_v2.py` |
| Minimize FPR / iterate fast (accepting 2/8 coverage) | Qwen3-32B | `rules_v3.py` |

---

## Executive summary

- **GPT-OSS-120B** (`rules_v1.py`) — ⭐ **Recommended.** 21 rules, 8/8 classes, 11.6% FPR. Best recall × FPR balance and the only one to reach 100% on `poisoned_high_rate`.
- **Llama-3.3-70B** (`rules_v2.py`) — Highest raw recall (beats v1 on 5 of the 8 classes), but a **35.3% FPR** makes it operationally unusable.
- **Qwen3-32B** (`rules_v3.py`) — Lowest FPR (4.2%), but only **3 rules** covering **2/8 classes**; over-aggressive refinement.

Any of the three can be passed to `rules2p4.py`; the commands below use `rules_v1.py` as the running example — substitute `rules_v3.py` to reproduce the latest results.
---

## Repository layout

```
.
├── rules2p4.py          # Converter entry point: rules_vN.py -> goose_ids.p4 + setup_rules.py
├── rule_parser.py       # Parses the Python rule functions into an internal representation
├── field_model.py       # FIELDS: width, scale, and sign per GOOSE feature
├── p4_emitter.py        # Emits the P4_16/TNA program
├── bfrt_emitter.py      # Emits the BF-Runtime population script
├── validate.py          # Semantic oracle: compares P4 logic vs. Python over random inputs
├── gen_test_traffic.py  # Builds the labeled test PCAP and the expected-verdict table
├── deploy.sh            # Convenience deployment helper
├── rules_v1.py          # Rule set — baseline
├── rules_v2.py          # Rule set — corrected
├── rules_v3.py          # Rule set — latest/refined
├── build/               # Generated artifacts (goose_ids.p4, setup_rules.py, ...)
├── LICENSE              # MIT License
└── README.md            # This file
```

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

Convert the rules and inspect the expansion (swap `rules_v1.py` for `rules_v3.py` for the latest set):

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

> The messages below are the literal strings printed by `rules2p4.py` (in Portuguese); an English gloss is given in parentheses so the table still matches your terminal output.

| Message | Cause | Fix |
|---|---|---|
| `campos não mapeados em FIELDS` *(fields not mapped in FIELDS)* | Rule uses a new field | Add it to `FIELDS` in `field_model.py` with width, scale, and sign |
| `disjunção não suportada` *(disjunction not supported)* | Rule uses `or` | Split it into two `rule_*` functions — the ternary match performs the union |
| `comparação precisa ser variável/get vs constante` *(comparison must be variable/get vs constant)* | Arithmetic or comparison between two fields | Rewrite the rule or pre-compute the value |

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

The most likely cause is floating-point precision loss — if a new rule introduces a threshold with more decimal places than the field's scale supports, distinct values collapse into the same range. Increase the field's `scale` in `field_model.py` and revalidate. (This class of defect is exactly what the v2 revision corrected.)

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

Compare the returned `attack_id` with the table printed by the generator. A divergence here, with `validate.py` passing, points to a difference between the traffic generator's encoding and the control plane's — verify that `GOOSE_FIELDS` in `gen_test_traffic.py` is in the same order as `goose_feat_h` in `goose_ids.p4`. (This was one of the v1 defects corrected in v2.)

### Error inserting entries with a repeated priority

This should not happen: each entry gets a unique priority (1 to 95), assigned in rule order. If it appears, `bfrt_emitter.py` was modified — uniqueness is mandatory in the TCAM.

---

## Iteration cycle

When regenerating the rules with the LLM, the short path (example uses `rules_v3.py`):

```bash
cd ~/GOOSE_Simulator

# 1. convert and check the expansion
python3 rules2p4.py rules_v3.py -o build --prog goose_ids --report

# 2. validate — do not skip this step
python3 validate.py rules_v3.py -n 100000

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

---

## Citation

If you use this simulator or the rules it consumes, please cite the SBRC 2026 tool paper:

> MARTINS, Lucas A.; QUINCOZES, Camilla B.; SIERVO, Giovanni; QUINCOZES, Silvio E.; LUIZELLI, Marcelo Caggiani. **From Red Flags to Detection Rules: An LLM-driven Pipeline for Real-Time GOOSE Intrusion Detection and Prevention**. *In*: Salão de Ferramentas — Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC), 44., 2026, Praia do Forte/BA. Anais [...]. Porto Alegre: Sociedade Brasileira de Computação, 2026. p. 57–65. ISSN 2177-9384. DOI: 10.5753/sbrc_estendido.2026.23263.

```bibtex
@inproceedings{martins2026redflags,
  author    = {Martins, Lucas A. and Quincozes, Camilla B. and Siervo, Giovanni and Quincozes, Silvio E. and Luizelli, Marcelo Caggiani},
  title     = {From Red Flags to Detection Rules: An LLM-driven Pipeline for Real-Time GOOSE Intrusion Detection and Prevention},
  booktitle = {Anais Estendidos do XLIV Simp{\'o}sio Brasileiro de Redes de Computadores e Sistemas Distribu{\'i}dos (SBRC) --- Sal{\~a}o de Ferramentas},
  year      = {2026},
  pages     = {57--65},
  publisher = {Sociedade Brasileira de Computa{\c c}{\~a}o (SBC)},
  address   = {Porto Alegre, RS, Brasil},
  issn      = {2177-9384},
  doi       = {10.5753/sbrc_estendido.2026.23263},
  url       = {https://doi.org/10.5753/sbrc_estendido.2026.23263}
}
```

---

## References

### Standards

- International Electrotechnical Commission (2003). *Communication networks and systems in substations — Part 8-1: Specific communication service mapping (SCSM) — Mappings to MMS (ISO 9506-1 and ISO 9506-2) and to ISO/IEC 8802-3.* IET.

### Base Tool (this work)

- Martins, L. A., Quincozes, C. B., Siervo, G., Quincozes, S. E., & Luizelli, M. C. (2026). From Red Flags to Detection Rules: An LLM-driven Pipeline for Real-Time GOOSE Intrusion Detection and Prevention. In *Anais Estendidos do XLIV Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC) — Salão de Ferramentas*, pp. 57–65. Porto Alegre: SBC. DOI: 10.5753/sbrc_estendido.2026.23263.

### Journal Articles

- Boeding, M., Hempel, M., Sharif, H., Lopez Jr., J., & Perumalla, K. (2023). A flexible OT testbed for evaluating on-device implementations of IEC-61850 GOOSE. *International Journal of Critical Infrastructure Protection*, 43, 100618.
- Hong, J. & Liu, C. (2019). Intelligent electronic devices with collaborative intrusion detection systems. *IEEE Transactions on Smart Grid*, 10(1), 271–281.
- Jay, D. (2023). Deception technology based intrusion protection and detection mechanism for digital substations: A game theoretical approach. *IEEE Transactions on Smart Grid*, 3279504.

### Conference Papers

- Bhattacharya, S., Saqib, N., & Govindarasu, M. (2023). ML-based anomaly detection system for IEC 61850 communication in substations. In *IEEE Power & Energy Society Innovative Smart Grid Technologies Conference (ISGT)*.
- Delhomme, A., Nweke, L. O., & Yildirim Yayilgan, S. (2024). Detecting denial of service attacks in smart grids using machine learning: A study of IEC 61850 protocols. In *SECURWARE 2024*.
- Girdhar, M., Hong, J., Su, W., Herath, A., & Liu, C.-C. (2023). SDN-based dynamic cybersecurity framework of IEC-61850 communications in smart grid. In *IEEE Conference*.
- Hong, J., Liu, C., & Govindarasu, M. (2014). Detection of cyber intrusions using network-based multicast messages for substation automation. In *Innovative Smart Grid Technologies (ISGT)*, pp. 1–5. IEEE.
- Pärssinen, J., Raussi, P., Noponen, S., Opas, M., & Salonen, J. (2023). The digital forensics of cyber-attacks at electrical power grid substation. In *IEEE Conference*.
- Saqib, N., Bhattacharya, S., Hyder, B., & Govindarasu, M. (2023). Cyber attack impact characterization for IEC 61850-based substations. In *IEEE Power & Energy Society General Meeting (PESGM)*.
- Yang, C.-W., Galkin, N., Drozdov, D., & Vyatkin, V. (2023). On evaluating R-GOOSE messaging latency over 5G: A Swedish case study. In *IEEE Conference*.

### Datasets

- Quincozes, S. E., Albuquerque, C., Passos, D., & Mossé, D. (2023). ERENO: A framework for generating realistic IEC-61850 intrusion detection datasets for smart grids. *IEEE Transactions on Dependable and Secure Computing*, 21(4), 3851–3865.

---

## License

Distributed under the terms of the MIT License. See `LICENSE`.
