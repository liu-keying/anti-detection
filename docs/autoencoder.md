# Zeek＋自编码器异常检测实验手册

本实验使用只学习背景连接的自编码器（Autoencoder，AE），验证 GRN 的统计特征是否容易偏离背景。输出为重构误差和异常标签，**异常不等于已识别出 GRN 身份**。本阶段离线读取特征表，不进行网络回放。

## 1. 与已有流程的衔接

共用 [数据准备手册](data-preparation.md) 和 [监督分类手册](supervised-classification.md) 的 Zeek 特征提取。若已有开发表和各比例测试表，直接复用，不能为 AE 单独改变采集处理或连接口径。

```text
背景训练组 → 拟合预处理、训练 AE
背景调参组 → 早停、选择最佳轮次和候选结构
独立背景校准组 → 固定误报预算下的重构误差阈值
共用混合测试组 → 固定预处理＋AE＋阈值 → 异常判定和指标
```

这里“背景”指 MAWI 负类来源，不保证每条连接都为正常业务。GRN 不参与预处理拟合、网络训练、早停、结构选择和阈值校准；最终测试才比较其重构误差和异常率。

## 2. 环境安装

在项目根目录启用 venv。先安装官方 CPU 版 PyTorch，避免默认下载 GPU 依赖：

```bash
source venv/bin/activate
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
python -m pip install -e '.[ml,ae]'
python -c 'import torch; print(torch.__version__)'
ae-experiment --help
```

AE 复用 ML 依赖和质量统计辅助函数，因此安装 `ml,ae` 两组可选依赖。无需 torchvision、torchaudio、CUDA 或 GPU。程序固定在 CPU 上训练和推理，默认 1 个计算线程。

正式重现时按 training.json、Python 版本和依赖快照恢复环境，不在训练与测试之间升级。保存依赖：

```bash
mkdir -p outputs/ae-environment01
python -m pip freeze > outputs/ae-environment01/python-requirements.txt
```

PyTorch CPU 安装方式及 state_dict 保存方式见文末官方参考。

## 3. 准备训练、调参、校准及测试分组

复用 captures.json 的日期／会话分组：

| 用途 | split | role | AE 实际使用的数据 |
|---|---|---|---|
| 训练 | train | train | 仅 label=0 的背景 |
| 早停／选型 | validation | tuning | 仅 label=0 的背景 |
| 最终阈值 | validation | calibration | 仅 label=0 的背景 |
| 正式测试 | test | test | 所有背景和 GRN |

原始清单的 train 条目无需写 role，提取时自动设 train；validation 需明确 tuning 或 calibration，未写时默认为 calibration。参照 `configs/captures.example.json`。三类背景分组彼此独立，不能按同一会话的连接随机拆分。

允许复用包含 GRN 开发记录的监督分类特征表：AE 仅依据标签筛选背景，其余 GRN 开发记录不会进入训练／评分选型。为与其他检测器保持共同留出测试集，所有开发记录的样本 ID、来源文件哈希和组信息仍保留用于测试泄漏检查；因此不能把监督训练用过的 GRN 再当成 AE 的共同正式测试集。

## 4. 提取或复用特征表

如果已完成监督分类特征提取，直接跳到训练。否则执行：

```bash
supervised-experiment extract \
  --manifest configs/captures.json \
  --checksums all --timeout 120 \
  --output outputs/ml-development01

supervised-experiment extract \
  --input outputs/round01 --checksums all \
  --output outputs/ml-test-features01
```

如果使用仓库固定官方 Zeek 容器，两条命令均增加 `--zeek "$PWD/scripts/zeek-docker.sh"`。不要覆盖已有目录。

使用相同十个连接统计特征：duration、双向包数、双向 IP 字节数、总包数／字节数、双向平均 IP 包长和发起字节比例。地址、端口、协议、时间、来源和标签只用于匹配与评估，不作为网络输入。

审核 dataset.json 的状态统计、各 capture 的 extraction.json、conn.log 及 Zeek 错误。无法唯一匹配、计数不符等记录仍保留，但不用于拟合或校准。单向流、载荷截断和采集差异需要在实验报告说明；详细匹配规则见监督分类手册。

## 5. 确定 AE 配置

默认配置见 `configs/autoencoder.example.json`：

```json
{
  "candidates": [
    {
      "hidden_dims": [16, 8, 4, 8, 16],
      "learning_rate": 0.001,
      "weight_decay": 0.00001,
      "max_epochs": 200,
      "batch_size": 256,
      "patience": 15,
      "min_delta": 0.000001
    }
  ]
}
```

对应网络为 `10 → 16 → 8 → 4 → 8 → 16 → 10`。隐藏层 ReLU，末层线性输出；标准化数据可能为负，不使用 sigmoid 限制输出。损失为十维重构均方误差，优化器 Adam。

候选必须包含小于输入维数的瓶颈。可以在 candidates 中预先列出有限结构／训练参数，只用背景调参 MSE 比较；并列时选择靠前候选。不能通过查看 GRN 或测试误差挑选结构，也不应根据测试结果调整特征。

所有数值先 log1p；缺失 duration 用背景训练集统计量填补，再由背景训练集拟合 StandardScaler。若训练 duration 全缺失则填 0。预处理以 pipeline 单独保存，测试和校准只 transform。

低背景重构误差只说明模型学会重构该背景，不保证它一定能有效检测未见异常；不能仅凭此认定检测器充分有效。

## 6. 仅用背景训练和早停

```bash
ae-experiment train \
  --data outputs/ml-development01 \
  --config configs/autoencoder.example.json \
  --fpr 0.001 --seed 2026 --threads 1 \
  --output outputs/ae-model01
```

`--fpr 0.001` 表示 0.1% 的背景异常预算，保存供后续校准；训练阶段不会用该预算或 GRN 检出率选择网络。

每轮记录背景训练 MSE 和背景调参 MSE。背景调参损失下降不足 min_delta 连续达到 patience 轮时早停；即使很小的损失改善未重置 patience，也会保存实际最低调参损失的权重。训练结束恢复该权重，候选结构也按最低背景调参 MSE 选择。

训练与调参数据不合并重训。若没有可评分的背景训练、调参或独立校准数据，程序拒绝执行，不自动拆分同一会话。

查看 training.json 中 trials 和 history.csv：

- best_epoch、best_tuning_mse：实际恢复的最佳轮次和背景调参损失；
- epochs_run、stopped_early、reached_epoch_limit：实际训练情况；达到轮次上限不代表已经收敛；
- coverage：各背景分区总数与可评分数量；
- ignored_grn_rows：开发表中被忽略的 GRN 行数；
- background_identities：实际背景分区身份；development_identities 用于共同测试集防泄漏。

固定随机种子和确定性 CPU 算法。多个候选使用 seed＋候选编号，记录实际种子；不同环境之间仍应以保存的权重和依赖版本为准。

产物 weights.pt 仅保存 PyTorch state_dict，以 weights_only=True 加载；preprocessing.joblib 保存预处理。joblib 仅加载自己生成、来源可信的文件。文件哈希用于检查变更，不提供来源真实性保证。

## 7. 用独立背景校准误差阈值

```bash
ae-experiment calibrate \
  --model outputs/ae-model01 \
  --data outputs/ml-development01 \
  --output outputs/ae-calibration01
```

只能使用训练时声明的同一份开发表，数据哈希和提取配置必须一致；实际评分仅选 role=calibration、label=0、status=ok 的背景。

对预处理后的输入 x 计算：

`e(x) = mean((x - AE(x))²)`

以 **e(x) > threshold** 判为异常。阈值采用与监督分类相同的严格大于经验统计量规则，校准背景中最多允许 `floor(预算 × 可评分背景数)` 个超阈值样本。同分样本不随机拆分，经验背景异常率可能比预算更低。

输出 threshold.json 和 background-errors.csv，记录训练指纹、阈值、预算、背景总数、可评分数量、经验异常率、分辨率及 low_tail_sample_support。预算×校准样本数低于 20 时尾部证据有限；即使全部未超阈值，也不能证明总体背景误报率为零。

## 8. 冻结后测试全部混合比例

```bash
ae-experiment evaluate \
  --model outputs/ae-model01 \
  --threshold outputs/ae-calibration01/threshold.json \
  --input outputs/ml-test-features01 \
  --bootstrap 1000 --seed 2026 \
  --output outputs/ae-results01
```

可把 input 指向单个 ratio 特征目录。测试前校验模型／预处理／训练配置的哈希、Python 和库版本、Zeek 特征配置及测试身份。开发与测试共享文件哈希、样本 ID 或同类别 group 时拒绝执行。

固定 AE、预处理和阈值，只做前向推理。测试阶段不更新均值、标准差、权重或阈值。

| 主指标 | 计算方式与含义 |
|---|---|
| grn_anomaly_detection_rate | GRN 被标异常连接数／全部 GRN 标签连接数 |
| background_anomaly_rate | 背景被标异常连接数／全部背景标签连接数 |
| anomaly_grn_fraction | 所有异常判定中实际 GRN 的比例，不能解释为身份识别精确率 |
| scoreable_grn_anomaly_rate | 只在可评分 GRN 子集上的异常率 |
| scoreable_background_anomaly_rate | 只在可评分背景子集上的异常率 |
| grn_coverage、background_coverage | 各类标签连接的可评分比例 |
| grn_flagged／unflagged、background_flagged／unflagged | 保留原始计数，便于复核 |

无法评分的标签连接不产生异常判定，但仍计入总分母；预测行的 reconstruction_error 为空，decision 为 unscorable。review_required 为 true 时必须先核查覆盖情况。特别是背景大量无法评分时，低总体背景异常率可能具有误导性，应同时报告可评分子集指标。

纯背景条件的 GRN 异常率为空，纯 GRN 条件的背景异常率为空；没有异常判定时 anomaly_grn_fraction 为空。身份识别率始终为“不评价”（JSON null）。标签分母仍只包含准备阶段可纳入的连接，早期排除的分片／其他协议需另报覆盖范围。

测试背景异常率超过预算时照实标记，不重新校准来掩盖。不能把未知异常全都标成 GRN。

## 9. 输出结果和图表

```text
outputs/ae-model01/
  training.json
  weights.pt
  preprocessing.joblib
  config.json
  history.csv
outputs/ae-calibration01/
  threshold.json
  background-errors.csv
outputs/ae-results01/
  summary.csv, summary.json
  ratio_0.01/
    metrics.json
    predictions.csv
    groups.csv
```

predictions.csv 包含每个标签连接的 reconstruction_error、anomalous、提取状态、标签和来源组。groups.csv 按来源类别和独立采集组统计，保留全部连接。

生成异常率曲线、两类重构误差分布和背景训练损失图：

```bash
ae-experiment plot \
  --input outputs/ae-results01 \
  --model outputs/ae-model01 \
  --output outputs/ae-plots01
```

输出 PNG 和 SVG。误差分布只画可评分连接，横轴为 log10(1＋标准化重构 MSE)，虚线为同样变换后的固定阈值；两类直方图使用共同区间并各自归一化，不把低占比造成的柱数差异解释为分布相似。异常率图为点估计，不自动绘制置信带。

可选 model 用于读取训练历史绘制损失，不会重新训练。

## 10. 多轮统计与结果解释

默认按各类来源 group 对异常连接率做 percentile cluster bootstrap。少于两个独立组、bootstrap=0、全部检出或全部未检出时不输出区间。非参数 bootstrap 无法为零检出提供未见事件上界，不能报告 [0,0] 作为低异常率证据。

各混合比例固定全部可用背景，使用目标池的嵌套完整连接子集。应报告每条件 GRN 数量和业务覆盖，对共有目标作配对分析，不能把复用样本累计为独立样本或将子集组成变化当成纯占比效应。多轮、跨日期与部署结果分别保留；组数过少时需要补充数据，单侧验收上界和多重比较需另行预先设计。

监督分类说明“见过 GRN 后能否识别身份”，AE 说明“未用 GRN 学习时能否从背景偏离中发现目标”，结论分开报告。MAWI 包含真实少见业务和异常，背景异常标签不等于安全事件误报的真值。

建议结论：

> 在指定 Zeek 观测特征、背景训练自编码器、固定阈值和实验条件下，GRN 异常检出率为……，背景异常率为……，两类覆盖率为……。主要误差分布与跨批次稳定性为……。该结果评价统计异常可检测性，不代表模型识别出 GRN 身份。

低异常率不能单独证明 GRN 不可识别，应结合充分训练的监督模型和 Suricata 实验。固定逐连接模型对相同目标特征的误差通常不随周围背景数量改变，不预设低占比必然导致异常检出率下降。

## 11. 合成验证和正式验收

先运行已有真实 Zeek 合成流程，得到共用特征表（若已经生成则直接复用）：

```bash
python scripts/check_supervised_pipeline.py \
  --zeek "$PWD/scripts/zeek-docker.sh" \
  --output outputs/ml-pipeline-check01
```

再验证 AE：

```bash
python scripts/check_autoencoder_pipeline.py \
  --development outputs/ml-pipeline-check01/development \
  --test-features outputs/ml-pipeline-check01/test-features \
  --output outputs/ae-pipeline-check01
```

该脚本实际训练 PyTorch AE、独立背景校准、测试三个合成条件并生成图表，检查结果数量、覆盖率、分母与非身份识别标记。配置中的 10% 预算和 50% 混合比例仅用于小样本接口检查，不是正式实验参数，也不验证真实 GRN 检出能力。

当前环境已用 CPU PyTorch 2.14.1+cpu，通过真实 Zeek 生成的三个合成条件的 AE 训练、校准、测试和绘图检查；18 项全套自动化测试通过。验证产物位于 `outputs/autoencoder-integration/`。这不包含真实 MAWI／GRN 实测。

自动化测试：

```bash
python -m unittest discover -s tests -v
```

AE 测试专门检查改变开发集 GRN 数值不会改变预处理、训练历史和模型权重；只用背景校准；恢复最佳背景调参权重；不可评分分母；无目标指标；缺失独立背景数据拒绝；数据泄漏和模型篡改拒绝。

正式验收还需审核背景样本量与多样性、质量和覆盖率、训练／调参损失、尾部阈值支持和测试实际背景异常率。程序使用内存特征表和 CPU mini-batch 训练／推理，不是 TB 级外存处理实现。没有真实输入时只能确认代码流程，不能形成反探测实验结论。

## 官方参考

- [PyTorch CPU 安装命令](https://pytorch.org/get-started/previous-versions/)
- [PyTorch state_dict 保存及 weights_only 加载](https://docs.pytorch.org/tutorials/beginner/saving_loading_models.html)
- [Zeek 连接字段](https://docs.zeek.org/en/current/reference/logs/conn.html)
