# From Red Flags to Detection Rules, Revisited
## Benchmarking LLM-Generated Rules for Real-Time GOOSE Intrusion Detection on P4Studio Simulator for Intel Tofino

**Authors:** Lucas A. Martins¹, Camilla B. Quincozes¹², Silvio E. Quincozes¹², Giovanni Siervo¹, Marcelo Caggiani Luizelli²   
¹ Universidade Federal de Uberlândia (UFU) – Uberlândia, Brazil  
² Universidade Federal do Pampa (UNIPAMPA) – Alegrete, Brazil  

`{lucas.martins, camillaquincozes, sequincozes, gsiervo}@ufu.br`

`{marceloluizelli}@unipampa.edu.br`

---

## Visão geral

| Etapa | O que acontece | Onde roda |
|---|---|---|
| 1 | Ambiente e variáveis | host |
| 2 | Conversão: `rules_v1.py` → `goose_ids.p4` + `setup_rules.py` | host |
| 3 | Validação semântica (oráculo Python) | host |
| 4 | Compilação P4 | host |
| 5 | Subir `tofino-model` + `bf_switchd` | 2 terminais |
| 6 | Popular tabelas via BF-Runtime | 3º terminal |
| 7 | Injetar tráfego e ler contadores | 4º terminal |

Etapas 1–4 rodam sem o switch. Se algo falhar ali, não adianta subir o modelo.

---

## 1. Ambiente

```bash
source ~/setup-open-p4studio.bash

echo "SDE.........: $SDE"
echo "SDE_INSTALL.: $SDE_INSTALL"
python3 --version
```

Se `$SDE` vier vazio, o script de ambiente não foi carregado — reveja a instalação antes de continuar.

Interfaces virtuais (uma vez por boot da máquina):

```bash
sudo ${SDE_INSTALL}/bin/veth_setup.sh 128
ip link show veth0 >/dev/null 2>&1 && echo "veths OK"
```

---

## 2. Gerar o P4 e o script de regras

```bash
cd ~/rules2p4

python3 rules2p4.py ~/rules_v1.py \
    --outdir build \
    --prog goose_ids \
    --report
```

Saída esperada:

```
regras lidas ......... 21
campos ativos ........ 9
entradas ternárias ... 95
classes de ataque .... 8
```

Dois arquivos em `build/`:

- `goose_ids.p4` — programa TNA
- `setup_rules.py` — script BF-Runtime

### Interpretando o `--report`

O relatório lista faixas e bits por campo. **Vale conferir antes de compilar**, especialmente após regenerar as regras com o LLM:

- **Entradas ternárias muito acima de ~4× o número de regras** → alguma regra nova expandiu demais. A tabela `detect` tem `size = 2048`; passando disso, o compilador rejeita.
- **Campo com muitas faixas** → limiares demais sobre o mesmo campo, aumentando o produto cartesiano.

### Erros comuns nesta etapa

| Mensagem | Causa | Correção |
|---|---|---|
| `campos não mapeados em FIELDS` | Regra usa campo novo | Adicione a `FIELDS` em `field_model.py` com largura, escala e sinal |
| `disjunção não suportada` | Regra usa `or` | Separe em duas funções `rule_*` — o match ternário faz a união |
| `comparação precisa ser variável/get vs constante` | Aritmética ou comparação entre dois campos | Reescreva a regra ou pré-compute o valor |

---

## 3. Validar antes de compilar

```bash
python3 validate.py ~/rules_v1.py -n 100000
```

Critério de aceitação — **as duas linhas de divergência em zero**:

```
divergência detecção ..... 0
divergência classe ....... 0
```

Divergência diferente de zero significa que a tradução não preserva a semântica das regras. Não prossiga: o pipeline vai classificar diferente do Python.

A causa mais provável é perda de precisão em ponto flutuante — se uma regra nova trouxer um limiar com mais casas decimais do que a escala do campo comporta, valores distintos colapsam na mesma faixa. Aumente `scale` do campo em `field_model.py` e revalide.

---

## 4. Compilar o P4

```bash
mkdir -p ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids
cp build/goose_ids.p4 \
   ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids/

cd ~/open-p4studio
./p4_build.sh pkgsrc/p4-examples/p4_16_programs/goose_ids/goose_ids.p4
```

Confirme que os artefatos existem:

```bash
ls -la $SDE_INSTALL/share/tofinopd/goose_ids/
```

Devem aparecer `context.json` e `pipe/tofino.bin`. Sem eles, a compilação falhou mesmo que o script tenha retornado zero.

**Se falhar por recursos** (`table placement failed`, `not enough stages`): reduza o número de regras ou consolide limiares próximos no arquivo Python. O relatório da etapa 2 já indicava o risco.

---

## 5. Subir modelo e switchd

**Terminal 1** — modelo:

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio
./run_tofino_model.sh -p goose_ids --arch tofino
```

**Terminal 2** — driver:

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio
./run_switchd.sh -p goose_ids --arch tofino
```

Aguarde o prompt `bfshell>` e a linha do gRPC:

```
bfshell> bfruntime gRPC server started on 0.0.0.0:50052
```

Leva um a dois minutos. Antes disso, a etapa 6 falha por conexão recusada.

---

## 6. Popular as tabelas

**Terminal 3:**

```bash
source ~/setup-open-p4studio.bash
cd ~/open-p4studio

ls -la ~/rules2p4/build/setup_rules.py   # confirme que existe

./run_bfshell.sh -b ~/rules2p4/build/setup_rules.py
```

Saída esperada:

```
tbl_band_SqNum: 8 faixas
tbl_band_StNum: 7 faixas
...
detect: 95 entradas
OK - regras carregadas
```

### Se der erro de sintaxe da API

Os nomes de parâmetros do `range match` variam entre versões do SDE. Se aparecer `unexpected keyword argument`, inspecione a assinatura real no `bfshell` interativo:

```bash
./run_bfshell.sh
```

```
bfrt_python
bfrt.goose_ids.pipe.Ingress.tbl_band_SqNum.info(return_info=False)
bfrt.goose_ids.pipe.Ingress.detect.info(return_info=False)
```

Isso imprime os nomes exatos dos campos de chave e ações. Ajuste `bfrt_emitter.py` conforme o que aparecer e regenere. Os sufixos que o script assume hoje são `_start`/`_end` para `range` e `_mask` para `ternary`.

### Verificar o que foi inserido

Ainda no `bfshell>`:

```
bfrt
goose_ids
pipe
Ingress
detect
dump
```

---

## 7. Injetar tráfego e conferir

**Terminal 4** — gerar o PCAP de teste:

```bash
cd ~/rules2p4
python3 gen_test_traffic.py ~/rules_v1.py -o test_goose.pcap
```

Imprime a tabela de veredito esperado por pacote:

```
  #  caso                    esperado         regras acionadas
  1  normal_1                NORMAL           -
  2  normal_2                NORMAL           -
  3  grayhole_sq_tdiff       grayhole         rule_grayhole_sq_tdiff
  ...
19 pacotes -> test_goose.pcap  (17 devem casar em detect, 2 normais)
```

Injetar:

```bash
sudo tcpreplay -i veth0 test_goose.pcap
```

Sem `tcpreplay` instalado:

```bash
sudo apt install -y tcpreplay
```

Ler os contadores — no **terminal 3**:

```bash
./run_bfshell.sh
```

```
bfrt_python
tbl = bfrt.goose_ids.pipe.Ingress.detect
tbl.operations_execute("SyncCounters")
tbl.dump(from_hw=True)
```

**Resultado esperado:** a soma dos contadores das entradas `flag_attack` deve bater com o número de pacotes de ataque do gerador (17), e os 2 normais caem no `no_attack`.

### Testar o caminho sem VLAN

O parser trata os dois casos. Para exercitar o ramo sem marcação:

```bash
python3 gen_test_traffic.py ~/rules_v1.py -o test_untagged.pcap --untagged
sudo tcpreplay -i veth0 test_untagged.pcap
```

Os contadores devem incrementar igual. Se só a versão com VLAN funcionar (ou vice-versa), o problema está na transição do parser.

---

## Diagnóstico

### Contadores zerados após injeção

Em ordem de probabilidade:

1. **Pacote não chegou ao parser GOOSE.** No terminal 1, o log do modelo mostra os headers válidos por pacote. Se aparecer só `ethernet` (sem `goose`), o EtherType não casou — confira o `0x88B8` no PCAP:
   ```bash
   tcpdump -r test_goose.pcap -xx -c 1 | head -5
   ```
2. **Tabelas de faixa não populadas.** Sem entradas, todo campo cai no `default_action` e vai para a faixa 0, que raramente casa em `detect`:
   ```
   bfrt.goose_ids.pipe.Ingress.tbl_band_SqNum.dump()
   ```
3. **Interface errada.** O `veth_setup.sh` cria pares; o modelo escuta em um lado específico. Teste `veth1` se `veth0` não funcionar.

### Contadores incrementam mas na entrada errada

Compare o `attack_id` retornado com a tabela impressa pelo gerador. Divergência aqui, com o `validate.py` passando, aponta para diferença entre a codificação do gerador de tráfego e a do plano de controle — verifique se `GOOSE_FIELDS` em `gen_test_traffic.py` está na mesma ordem que `goose_feat_h` no `goose_ids.p4`.

### Erro ao inserir entradas com prioridade repetida

Não deve ocorrer: cada entrada recebe prioridade única (1 a 95), atribuída na ordem das regras. Se aparecer, o `bfrt_emitter.py` foi modificado — a unicidade é obrigatória no TCAM.

---

## Ciclo de iteração

Ao regenerar as regras com o LLM, o caminho curto:

```bash
cd ~/rules2p4

# 1. converter e conferir a expansão
python3 rules2p4.py ~/rules_v2.py -o build --prog goose_ids --report

# 2. validar — não pule esta etapa
python3 validate.py ~/rules_v2.py -n 100000

# 3. recompilar
cp build/goose_ids.p4 ~/open-p4studio/pkgsrc/p4-examples/p4_16_programs/goose_ids/
cd ~/open-p4studio && ./p4_build.sh pkgsrc/p4-examples/p4_16_programs/goose_ids/goose_ids.p4
```

Se apenas os **limiares** mudaram e os campos são os mesmos, o P4 muda também — as faixas são derivadas das constantes. Não dá para recarregar só as regras sem recompilar.

---

## Limitação importante

O `goose_ids.p4` assume que os campos chegam prontos no header `goose_feat_h`. Quatro deles são derivados e exigem estado por publicador (`gocbRef`):

| Campo | Como se obtém |
|---|---|
| `tDiff` | diferença entre timestamps de chegada consecutivos |
| `stDiff` | variação de `StNum` |
| `sqDiff` | variação de `SqNum` |
| `timeFromLastChange` | tempo desde a última mudança de `StNum` |

No Tofino isso exige `Register` + `RegisterAction` indexados por hash do `gocbRef`. **Esse estágio não é gerado pelo conversor.** O gerador de tráfego preenche os valores diretamente, o que permite validar a lógica de classificação, mas não substitui a extração real.

Em produção, esse módulo precisa existir a montante. É a parte de maior dificuldade da implementação completa — cada `RegisterAction` admite uma única operação de leitura-modificação-escrita por estágio.
