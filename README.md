# GRN 反探测离线实验

从已有 MAWI 和 GRN PCAP 开始，依次完成数据准备、Suricata 通用规则、监督分类和自编码器实验。全部离线运行，无需网络回放。

以下命令在项目根目录执行。示例使用系统 Suricata、仓库提供的 Zeek Docker 脚本、0.1% 误报预算。数据路径、采集组和阳性样本需按实际填写；输出目录不可重复使用。

## 1. 启用 Python 环境

当前项目已创建 `venv`；首次在其他位置部署时先执行 `python3 -m venv venv`。

```bash
cd /anti-detection
source venv/bin/activate
python -c 'import sys; print(sys.executable)'
```

确认解释器位于本项目 `venv/bin/python`。每次打开新终端都需重新激活。

## 2. 安装依赖并准备检测工具

Python 依赖首次安装一次，后续可跳过：

```bash
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
python -m pip install -e '.[ml,ae]'
python -m pip check
```

安装系统 Suricata 和规则管理工具（需要 sudo 权限）：

```bash
sudo apt update
sudo apt install suricata suricata-update
suricata --build-info
suricata-update --version
```

确认已安装 Docker 且当前用户可使用，再准备固定版本的官方 Zeek 镜像：

```bash
docker info
docker pull zeek/zeek@sha256:03edc722834dc810a7766b1cbece6a1ee345726ec9726f3e69671600a1673c5a
scripts/zeek-docker.sh --version
```

此脚本固定已验证的 Zeek 7.0.0。若使用系统 Zeek，后续两条提取命令均将 `--zeek "$PWD/scripts/zeek-docker.sh"` 替换为相同的系统 Zeek 路径。

## 3. 放置原始 PCAP

```bash
mkdir -p data/raw/mawi data/raw/grn data/controls outputs
```

将自己的文件复制到相应目录。清单模板对应以下文件名，可修改清单适配实际名称：

```text
data/raw/
  mawi/
    train.pcap          # 训练背景
    tuning.pcap         # 调参背景
    validation.pcap     # 独立阈值校准背景
    test.pcap           # 测试背景
  grn/
    train.pcap          # 监督训练 GRN
    tuning.pcap         # 监督调参 GRN
    validation.pcap     # 可选校准组 GRN，AE 不使用
    test.pcap           # 共同留出测试 GRN
```

每类可包含多个日期／独立批次文件，无需合成成上述四份。保留原始文件；GRN 输入须已排除 SSH、系统更新等非目标业务。不要复制同一 PCAP 来充当不同分区。

## 4. 检查原始数据

```bash
prepare-data inspect \
  data/raw/mawi/*.pcap data/raw/grn/*.pcap \
  --timeout 120 --output outputs/raw-inventory01.json
python -m json.tool outputs/raw-inventory01.json
```

检查 `eligible_flows`、`eligible_ip_bytes`、`captured_truncated_packets`、`excluded_packets` 和链路类型。损坏文件、时间戳倒退先处理；当前工具输入为经典 PCAP，不支持直接读取 PCAPNG。

## 5. 填写数据划分清单

首次创建自己的清单：

```bash
cp configs/captures.example.json configs/captures.json
nano configs/captures.json
```

逐项修改 `path`、`group`、`split` 和 `role`。路径相对 `configs/`，例如 `../data/raw/mawi/train.pcap`。

| 用途 | split | role |
|---|---|---|
| 训练 | train | 无需填写，提取时自动设 train |
| 模型调参／AE 早停 | validation | tuning |
| 最终阈值校准 | validation | calibration |
| 共同测试集 | test | 无需填写，提取时自动设 test |

同一日期／相关会话组不得跨用途。确认目标业务后才为 GRN 条目填写 `target_only: true`。多个文件逐个添加条目；不使用 GRN 校准文件时删除对应条目，不必为了模板凑文件。

## 6. 校验数据划分

```bash
prepare-data validate configs/captures.json
```

必须校验通过。工具检查分组跨分区及完全重复文件；仍需人工确认不同文件没有包含同一业务会话或派生副本。

## 7. 固定背景并估算 GRN 需求

从步骤 4 的报告统计本轮全部测试 MAWI 的可用 IP 字节量，固定该背景，按以下公式估算各条件所需目标：

```text
所需 GRN IP 字节量 = 固定 MAWI IP 字节量 × r / (1-r)
```

`r=0.0001` 对应 0.01%。例如固定 10 GB 背景时，0.01% 约需 1.0001 MB GRN，5% 约需 526.316 MB GRN；不能按 PCAP 文件大小换算，还需检查最低占比的独立目标连接数。当前工具使用内存处理，大规模正式数据应先规划分批或扩展外存处理。

先构造纯背景、5% 和纯 GRN，验证数据准备流程：

```bash
prepare-data mix configs/captures.json \
  --split test --ratios 0,0.05,1 \
  --seed 2026 --timeout 120 --tolerance 0.05 \
  --output outputs/pilot01
```

GRN 不足或完整连接导致比例误差超限时先补充数据／调整预实验规模，不删包凑比例。

## 8. 构造正式混合测试集

```bash
prepare-data mix configs/captures.json \
  --split test --ratios 0,0.0001,0.001,0.01,0.05,1 \
  --seed 2026 --timeout 120 --tolerance 0.05 \
  --output outputs/round01
```

0% 及所有混合条件使用同一份完整可用背景，改变完整 GRN 连接数量；100% 是不含背景的独立校验组。比例按 IP 字节计算，`--tolerance 0.05` 为相对比例误差最多 5%。所有输入的链路类型必须一致；跨源五元组冲突时先处理并保留映射记录。

## 9. 复核混合产物

```bash
python -m json.tool outputs/round01/ratio_0.01/manifest.json
head -n 5 outputs/round01/ratio_0.01/labels.csv
prepare-data inspect outputs/round01/ratio_0.01/mixed.pcap \
  --timeout 120 --output outputs/round01-check.json
```

逐条件检查目标／背景包数、IP 字节数和连接数，记录实际比例；抽查 `labels.csv` 的标签、五元组、时间范围及来源。后续三类检测器共用这些测试输入。

## 10. 获取通用规则并准备 Suricata 配置

```bash
mkdir -p outputs/rule-provenance
suricata-update list-enabled-sources > outputs/rule-provenance/enabled-sources.txt
sudo suricata-update
suricata --build-info > outputs/rule-provenance/build-info.txt
suricata-update --version > outputs/rule-provenance/update-version.txt
date -u +%F > outputs/rule-provenance/download-date.txt
cp /etc/suricata/suricata.yaml configs/suricata-experiment.yaml
nano configs/suricata-experiment.yaml
```

确认实际来源为 ET Open，记录更新日志及启用／禁用规则配置。若还有其他来源，实验名称如实注明。

在已有 YAML 中修改对应字段，不要重复添加配置段：

```yaml
# vars.address-groups 下：适用于任意方向的通用离线观测场景
HOME_NET: "any"
EXTERNAL_NET: "any"

# 根级配置：改为本机实际文件路径
classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
```

检查 TCP 重组、协议解析、资源限制及白名单／抑制策略；存在 `threshold-file` 时核对其绝对路径。不要保留 `HOME_NET=any` 和 `EXTERNAL_NET=!$HOME_NET` 的组合。冻结工具会配置 EVE 的 alert、flow、stats 输出。

## 11. 校验流程、冻结规则并验证阳性样本

先执行合成流程校验：

```bash
suricata-experiment selftest \
  --config configs/suricata-experiment.yaml \
  --output outputs/suricata-pipeline-check01
cat outputs/suricata-pipeline-check01/selftest.json
```

确认 `status=passed`，再冻结规则。将来源和日期替换为本轮实际记录：

```bash
suricata-experiment freeze \
  --config configs/suricata-experiment.yaml \
  --rules /var/lib/suricata/rules/suricata.rules \
  --source 'ET Open; downloaded YYYY-MM-DD; provenance in outputs/rule-provenance' \
  --output outputs/suricata-snapshot01
cat outputs/suricata-snapshot01/config-check.log
cat outputs/suricata-snapshot01/check/suricata.log
```

核对实际规则加载数、失败数和警告。准备一个已知命中当前规则的独立阳性 PCAP，验证预期 SID：

```bash
suricata-experiment check-positive \
  --snapshot outputs/suricata-snapshot01 \
  --pcap data/controls/known-positive.pcap \
  --sid 1234567 --checksums all \
  --output outputs/et-open-positive01
cat outputs/et-open-positive01/positive-check.json
```

`known-positive.pcap` 和 `1234567` 均需替换，仓库未提供现成 ET Open 阳性流量。确认 `passed` 后再开始正式实验；合成 selftest 不能代替规则能力校验。冻结后不移动或修改快照。

## 12. 批量运行 Suricata

```bash
suricata-experiment run \
  --snapshot outputs/suricata-snapshot01 \
  --input outputs/round01 --checksums all \
  --output outputs/suricata-round01
cat outputs/suricata-round01/summary.csv
```

检查各条件 `analysis/metrics.json`、`rules.csv`、`unresolved-alerts.csv` 和 `stats.json`。未归因告警、解析失败及包数异常先复核；通用告警率不等于 GRN 身份识别率。

## 13. 提取开发集和测试集的共用 Zeek 特征

```bash
supervised-experiment extract \
  --manifest configs/captures.json \
  --zeek "$PWD/scripts/zeek-docker.sh" \
  --checksums all --timeout 120 \
  --output outputs/ml-development01

supervised-experiment extract \
  --input outputs/round01 \
  --zeek "$PWD/scripts/zeek-docker.sh" \
  --checksums all \
  --output outputs/ml-test-features01
```

监督分类和 AE 复用这些表。Docker 脚本只挂载项目目录，因此数据放在本项目下。若预先决定忽略卸载造成的校验和问题，所有提取和检测阶段一致改用 `none` 并记录原因。

## 14. 检查特征质量

```bash
python -m json.tool outputs/ml-development01/dataset.json
python -m json.tool outputs/ml-test-features01/ratio_0.01/dataset.json
head -n 5 outputs/ml-development01/dataset.csv
```

逐文件查看 `extraction.json`、`conn.log` 和 `console.log`，核查 `status=ok` 的比例。歧义、包数／字节数不符的连接不会强行评分；覆盖率不足时先修复数据处理问题。

## 15. 训练 RF、XGBoost、MLP

```bash
supervised-experiment train \
  --data outputs/ml-development01 \
  --models rf,xgb,mlp --grid configs/supervised.example.json \
  --fpr 0.001 --seed 2026 --jobs 1 \
  --output outputs/ml-models01
python -m json.tool outputs/ml-models01/training.json
```

检查候选选择、覆盖率和未收敛警告。只用训练组拟合，在调参组选择模型；不根据测试集调整配置。

## 16. 校准并冻结监督模型阈值

```bash
supervised-experiment calibrate \
  --models outputs/ml-models01 --data outputs/ml-development01 \
  --output outputs/ml-calibration01
python -m json.tool outputs/ml-calibration01/thresholds.json
```

核查每模型的背景样本量、经验 FPR 和 `low_tail_sample_support`。最终阈值只由独立背景校准组确定。

## 17. 测试监督模型并绘图

```bash
supervised-experiment evaluate \
  --models outputs/ml-models01 \
  --thresholds outputs/ml-calibration01/thresholds.json \
  --input outputs/ml-test-features01 \
  --bootstrap 1000 --seed 2026 \
  --output outputs/ml-results01

supervised-experiment plot \
  --input outputs/ml-results01 --output outputs/ml-plots01
cat outputs/ml-results01/summary.csv
```

查看 TP/FP/FN/TN、TPR、FPR、Precision、覆盖率和 PR 图。测试误报超预算时如实记录，不重新选阈值。

## 18. 仅用背景训练自编码器

```bash
ae-experiment train \
  --data outputs/ml-development01 \
  --config configs/autoencoder.example.json \
  --fpr 0.001 --seed 2026 --threads 1 \
  --output outputs/ae-model01
python -m json.tool outputs/ae-model01/training.json
head -n 10 outputs/ae-model01/history.csv
```

检查训练／调参损失和最佳轮次。AE 自动排除 GRN 开发样本，仅使用背景拟合预处理、训练和早停选型。

## 19. 校准并冻结 AE 阈值

```bash
ae-experiment calibrate \
  --model outputs/ae-model01 --data outputs/ml-development01 \
  --output outputs/ae-calibration01
python -m json.tool outputs/ae-calibration01/threshold.json
```

确认背景样本量、经验异常率及阈值分辨率；校准不使用 GRN，不更新 AE 权重。

## 20. 测试 AE 并绘图

```bash
ae-experiment evaluate \
  --model outputs/ae-model01 \
  --threshold outputs/ae-calibration01/threshold.json \
  --input outputs/ml-test-features01 \
  --bootstrap 1000 --seed 2026 \
  --output outputs/ae-results01

ae-experiment plot \
  --input outputs/ae-results01 --model outputs/ae-model01 \
  --output outputs/ae-plots01
cat outputs/ae-results01/summary.csv
```

查看 GRN 异常检出率、背景异常率、覆盖率、误差分布和训练损失。异常标签不等于 GRN 身份识别。

## 21. 独立重复、汇总并归档

修改测试清单中的背景日期和 GRN 独立批次，使用新目录（如 round02）重复步骤 8—9、12—14、17、20，模型、阈值和 Suricata 快照保持不变。新测试组仍不得与任何开发组重叠。

```bash
mkdir -p outputs/environment01
python -m pip freeze > outputs/environment01/python-requirements.txt
uname -a > outputs/environment01/system.txt
```

保留数据清单、输入／输出哈希、模型、规则快照、日志、预测及图表。分别汇总三类结果，不把跨比例复用样本当成新增独立样本。组数不足或零检出时，不把空置信区间解释为零不确定性。

## 可选：先运行代码与合成流程检查

已安装全部依赖后运行单元测试：

```bash
python -m unittest discover -s tests -v
```

按顺序运行合成流程验证（输出目录需未存在）：

```bash
python scripts/check_suricata_pipeline.py \
  --config configs/suricata-experiment.yaml \
  --output outputs/suricata-integration-check01

python scripts/check_supervised_pipeline.py \
  --zeek "$PWD/scripts/zeek-docker.sh" \
  --output outputs/ml-pipeline-check01

python scripts/check_autoencoder_pipeline.py \
  --development outputs/ml-pipeline-check01/development \
  --test-features outputs/ml-pipeline-check01/test-features \
  --output outputs/ae-pipeline-check01
```

合成样本仅验证流程，不能代替正式 MAWI／GRN 实验或 ET Open 阳性校验。

详细说明：[共用数据准备](docs/data-preparation.md) · [Suricata 通用规则](docs/suricata-generic.md) · [监督分类](docs/supervised-classification.md) · [自编码器](docs/autoencoder.md)

混合策略已更新为固定背景。旧版混合文件不会自动改变，请使用新目录重新生成并重跑测试特征提取和检测。不同占比目标子集不同，需同时报告目标连接数及业务覆盖。
