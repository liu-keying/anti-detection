# 基于 Zeek 连接统计特征的监督分类实验

本实验评价：检测方取得 GRN 训练样本后，能否识别独立测试批次中的 GRN。实现 RF、XGBoost、MLP 三个二分类模型，输出 GRN 评分和连接级判定。实验仍为离线分析，不回放网络流量。

## 1. 本阶段输入与流程

先完成 [共用数据准备](data-preparation.md)。需要原始 MAWI／GRN PCAP、按独立日期／会话分组的 captures.json，以及各比例混合测试集（包含 labels.csv、manifest.json 和上级 inventory.json）。

```text
训练 PCAP → Zeek → 训练特征 → 拟合预处理、训练候选模型
调参 PCAP → Zeek → 调参特征 → 在指定误报预算下选择候选模型
校准 PCAP → Zeek → 背景特征 → 为每个选定模型固定最终阈值
测试混合 PCAP → 同一 Zeek → 测试特征 → 固定模型与阈值 → 指标和图表
```

三模型使用相同连接特征、划分和测试输入。每个模型各自校准阈值，不强制使用 0.5。Zeek 只负责提取特征，不提供 GRN 真值。

## 2. 启用虚拟环境并安装依赖

在项目根目录运行：

```bash
source venv/bin/activate
python -m pip install -e '.[ml]'
supervised-experiment --help
```

ML 可选依赖包括 NumPy、scikit-learn、XGBoost CPU 版、joblib 和 Matplotlib。当前流程仅使用 CPU，不需要 CUDA。后续重现使用训练时记录的具体版本，不要在训练与测试之间升级环境。

Zeek 可以使用系统安装或官方容器，二选一，同一实验全程固定。

**方式 A：系统 Zeek。** 按 [Zeek 官方安装说明](https://docs.zeek.org/en/v7.2.2/install.html)为所用 Ubuntu 安装对应软件包，检查实际路径：

```bash
zeek --version
```

若 Zeek 不在 PATH，后续使用 `--zeek /opt/zeek/bin/zeek` 等实际绝对路径。本工具不自动执行需要 sudo 的系统安装。

**方式 B：仓库提供的官方 Docker 镜像适配脚本。** 当前已验证的固定版本是 Zeek 7.0.0，脚本按镜像摘要锁定，不表示它是最新版本：

```bash
docker pull zeek/zeek@sha256:03edc722834dc810a7766b1cbece6a1ee345726ec9726f3e69671600a1673c5a
scripts/zeek-docker.sh --version
```

后续所有提取命令增加 `--zeek "$PWD/scripts/zeek-docker.sh"`。脚本以当前用户身份运行，只挂载本项目目录，不使用容器网络；原始数据和输出须放在项目内部。当前开发机已下载该镜像。若使用项目要求的其他 Zeek 版本，应在开发实验前修改脚本摘要并重新提取所有分区，不要混用已有特征。

## 3. 在清单中声明训练、调参、校准和测试组

参考 `configs/captures.example.json`。保留既有 `class`、`path`、`group`、`split`、GRN 的 `target_only` 确认，并为 validation 条目增加 `role`：

```json
{
  "captures": [
    {"path":"../data/raw/mawi/train.pcap","class":"mawi","group":"mawi-date-A","split":"train"},
    {"path":"../data/raw/grn/train.pcap","class":"grn","group":"grn-run-A","split":"train","target_only":true},
    {"path":"../data/raw/mawi/tuning.pcap","class":"mawi","group":"mawi-date-B","split":"validation","role":"tuning"},
    {"path":"../data/raw/grn/tuning.pcap","class":"grn","group":"grn-run-B","split":"validation","role":"tuning","target_only":true},
    {"path":"../data/raw/mawi/calibration.pcap","class":"mawi","group":"mawi-date-C","split":"validation","role":"calibration"},
    {"path":"../data/raw/mawi/test.pcap","class":"mawi","group":"mawi-date-D","split":"test"},
    {"path":"../data/raw/grn/test.pcap","class":"grn","group":"grn-run-D","split":"test","target_only":true}
  ]
}
```

路径和分组均须按实际填写。示例仅说明结构，不代表一个文件或日期就足够；每类通常需要多个独立组。调参需要两类数据，阈值校准只要求背景；即使校准分区包含 GRN，校准程序也不使用它们的评分。

未声明 role 的 validation 默认作为 calibration；如果没有另行提供 tuning 数据，训练会拒绝执行，而不是自动按连接随机切分。训练、调参、校准之间不能共享同类别 group、同源文件哈希或同一样本 ID。工具检查可检测的重复，人工仍须核查不同文件里的同一会话及其派生版本。

已有 captures.json 不必覆盖重建，只需添加独立调参组及相应 role。清单角色不会改变数据准备工具的测试混合行为。

```bash
prepare-data validate configs/captures.json
```

不要为了凑出四个分区把同一长连接切成四份。开发样本不足时应补充独立业务批次。

## 4. 提取开发数据特征

系统 Zeek 示例：

```bash
supervised-experiment extract \
  --manifest configs/captures.json \
  --checksums all --timeout 120 \
  --output outputs/ml-development01
```

使用容器时：

```bash
supervised-experiment extract \
  --manifest configs/captures.json \
  --zeek "$PWD/scripts/zeek-docker.sh" \
  --checksums all --timeout 120 \
  --output outputs/ml-development01
```

两条命令二选一。输出目录不能已存在。程序仅提取 train 和 validation，跳过 test；每份 PCAP 在独立目录、独立 Zeek 进程中分析，保存 JSON conn.log、console.log、特征脚本和质量报告。原始 PCAP 不修改。

默认检查校验和。若原始端点抓包的卸载造成校验和异常，先审核并预先确定策略；如统一选择 `--checksums none`，所有开发与测试提取均保持一致。不得因为测试结果低而临时忽略校验和。

### 固定的十个特征

| 特征 | 定义 |
|---|---|
| duration | Zeek 记录的观测连接持续时间 |
| orig_pkts、resp_pkts | 两方向包数 |
| orig_ip_bytes、resp_ip_bytes | 两方向 IP 字节数 |
| total_pkts、total_ip_bytes | 两方向求和 |
| orig_mean_ip_len、resp_mean_ip_len | 各方向 IP 字节数／包数；无包方向为 0 |
| orig_byte_fraction | 发起方向 IP 字节数／总 IP 字节数；总数为 0 时为 0 |

发起／响应方向遵循 Zeek，不等于必然的客户端／服务端。地址、端口、协议号、绝对时间、uid、文件名、来源组和标签均不进入模型。它们仅用于匹配、追踪和数据划分。

所有非负数值先 `log1p`。缺失 duration 用训练集的中位数填充；若训练 duration 全缺失则填 0。MLP 再标准化。RF、XGBoost 不额外标准化。预处理和分类器一起保存为 pipeline，禁止独立对测试数据重新拟合。

### 连接映射与质量检查

本阶段沿用数据准备的双向五元组＋空闲超时连接段标签，Zeek 使用固定版本的默认连接行为。通过五元组和时间区间映射（允许 2 微秒精度误差），必须一对一且双向总包数／IP 字节数与标签相符，才记为 `status=ok`。

Zeek 合并多个标签连接段、拆分一个标签连接段、丢失日志或计数不符时保留该标签行，但不强行聚合或生成可评分特征：

- `no_zeek_record`：无对应记录；
- `ambiguous_or_split`：映射有歧义或存在多个候选记录；
- `packet_count_mismatch`／`ip_byte_count_mismatch`：计数不符；
- `invalid_features`：特征缺失或不合法。

单包记录缺失 duration 时使用 0；多包记录缺失 duration 保留为待训练集填补值。其他基础计数缺失则不可评分。

审核每个 capture 目录的 `extraction.json`、Zeek 日志以及总表的 status_counts。若覆盖率很低，应先定位超时差异、抓包截断、解析、校验和和采集边界问题，不能直接训练后宣称反探测有效。

## 5. 提取全部混合测试条件

下面使用系统 Zeek；容器方式追加与开发阶段相同的 `--zeek`：

```bash
supervised-experiment extract \
  --input outputs/round01 --checksums all \
  --output outputs/ml-test-features01
```

工具读取每个 ratio 目录及其上级 inventory.json，验证 PCAP 和标签哈希，保留原始来源文件哈希和源连接编号。也可以把 `--input` 指向单个 ratio 目录，且保持其上级 inventory.json 可访问。

测试特征的 Zeek 版本、二进制／适配脚本哈希、提取脚本、校验和策略、特征集合和标签超时必须与开发集一致。测试只生成特征，不参与训练决策。

## 6. 训练候选模型并在调参集选型

```bash
supervised-experiment train \
  --data outputs/ml-development01 \
  --models rf,xgb,mlp \
  --grid configs/supervised.example.json \
  --fpr 0.001 --seed 2026 --jobs 1 \
  --output outputs/ml-models01
```

`--fpr 0.001` 表示背景误报预算 0.1%，不是 0.001%。正式预算应预先确定。参数文件为每个模型声明有限候选列表，默认每类两个候选；不在测试集上扩大搜索范围。

每个候选只用 train 拟合，在 tuning 背景上临时选取满足误报预算的阈值，再比较 tuning 的目标检出率；并列时采用配置中靠前的候选。这个临时阈值仅用于选型，最终阈值由下一步的独立背景校准产生。不把 tuning 或 calibration 数据并回训练集重训。

RF 默认 `class_weight=balanced`；XGBoost 默认按训练负／正样本数设 scale_pos_weight，使用 CPU hist；MLP 默认不设类别权重、不额外重采样，禁用内部随机验证早停。三者使用相同原始训练行。记录了不同训练策略，不能将区别全部归因于模型结构。

MLP 的未收敛警告等会写入 training.json 的 trials。必须检查，不应把未充分训练的低检出当作 GRN 低可识别性。增加训练量时保持独立调参组不变，以整组样本比较学习曲线；如果持续改善，先扩充开发数据再冻结模型，测试集始终不参与。

产物包括每模型 joblib pipeline、XGBoost 原生 JSON、training.json、实际候选参数和预处理参数。XGBoost 原生 JSON 不含全套预处理，统一预测使用 pipeline。训练记录含环境版本、选型依据、警告、数据身份和提取配置。

## 7. 独立背景校准并冻结阈值

```bash
supervised-experiment calibrate \
  --models outputs/ml-models01 \
  --data outputs/ml-development01 \
  --output outputs/ml-calibration01
```

校准严格使用冻结开发表中 role=calibration、label=0、status=ok 的背景行，不使用 GRN 评分，也不修改模型。开发表的哈希必须与训练时相同。

判定采用 **score > threshold**。阈值按背景评分的降序统计量选取，在校准样本上最多允许 `floor(FPR预算 × 可评分背景数)` 个超阈值样本；同分样本不随机拆开。因此实际经验 FPR 可能比预算更低。

产物 `thresholds.json` 记录每模型阈值、允许／实际背景正判数、经验 FPR、样本量和分辨率；background-scores.csv 保存逐背景评分。当预算×样本数低于 20，low_tail_sample_support 为 true，提示尾部校准证据有限。这不是充分样本量的保证。零校准误报不代表真实误报率为零。

训练、调参、校准未提取成功的记录仍在质量报告中；不可评分样本不参与拟合和阈值经验分位数。正式结论需同时报告覆盖率。

## 8. 固定模型和阈值，统一测试

```bash
supervised-experiment evaluate \
  --models outputs/ml-models01 \
  --thresholds outputs/ml-calibration01/thresholds.json \
  --input outputs/ml-test-features01 \
  --bootstrap 1000 --seed 2026 \
  --output outputs/ml-results01
```

测试前检查全部条件的表哈希、特征配置和来源身份。与开发数据共享同源文件哈希、样本 ID 或同类别 group 时拒绝测试。相同测试样本跨比例复用允许，但不代表新增独立样本。

模型与 Python／依赖版本必须和训练时一致。joblib 是 Python 对象序列化格式，仅加载本项目生成、来源可信的模型；哈希检查用于发现变更，不能把不可信文件变为可安全加载的文件。

默认使用所有标签连接作为指标分母。不可评分连接保留、无正判定：目标计入 FN，背景计入 TN。同时提供可评分子集的 TPR／FPR、各类覆盖率和不可评分数。这使流程失败可见；不能因为无法解析背景导致总体 FPR 低，就声称分类器误报低。

这里的“端到端分母”只覆盖准备阶段的可纳入标签连接。IP 分片、其他协议等此前已排除的流量不在分母内，需结合原始 inventory 报告覆盖范围。

| 指标 | 说明 |
|---|---|
| TP、FP、FN、TN | 连接级混淆矩阵原始计数 |
| TPR、FNR | 目标检出率和漏检率；无目标时为空 |
| FPR | 背景被判为 GRN 的比例；无背景时为空 |
| Precision | 正判中目标占比；无正判时为空 |
| scoreable_tpr、scoreable_fpr | 仅可评分连接的指标 |
| grn_coverage、background_coverage | 各类可评分比例 |
| test_fpr_exceeds_budget | 实际测试 FPR 是否超过预设预算，照实报告 |
| review_required | 是否存在不可评分连接，需要质量复核 |

程序不会因测试 FPR 超标而重新选阈值，也不会重新标准化或训练。

## 9. 结果文件、置信区间和图表

```text
outputs/ml-development01/
  dataset.csv, dataset.json
  capture-manifest.json
  capture_0000/{conn.log,features.zeek,console.log,extraction.json,...}
outputs/ml-test-features01/ratio_*/{dataset.csv,dataset.json,zeek/...}
outputs/ml-models01/{rf.joblib,xgb.joblib,xgb.json,mlp.joblib,training.json,grid.json}
outputs/ml-calibration01/{thresholds.json,background-scores.csv}
outputs/ml-results01/
  summary.csv, summary.json
  ratio_0.01/rf/{predictions.csv,metrics.json,groups.csv,pr-curve.csv,pr-info.json}
  ratio_0.01/xgb/...
  ratio_0.01/mlp/...
```

pr-curve.csv 和平均精确率仅在可评分子集同时存在两类时生成。纯背景／纯目标条件没有二分类 PR 曲线。曲线使用 scikit-learn 的 `score >= threshold` 约定，冻结运行点使用严格 `>`；存在大量同分时不要直接拿曲线某行替代冻结判定。

指标 JSON 对 TPR／FPR 分别按来源 group 做 percentile cluster bootstrap：抽取完整组、再以计数和计算比例，默认 1000 次。少于两个独立组、禁用 bootstrap、全部为正判或全部无正判时区间为空。特别是零检出时，非参数 bootstrap 不能给出未见事件的上界，不能报告虚假的 [0,0] 区间。很少的组也不足以支持可靠区间，应补充独立批次并在报告说明限制。这里的区间不是预先要求的单侧严格低检出率证据。

多个比例共享目标测试池时应配对分析；多个轮次的相关性、全局多重比较以及单侧验收上界需要另行统计，程序不把各比例当独立重复。

生成各比例指标和 PR 图：

```bash
supervised-experiment plot \
  --input outputs/ml-results01 \
  --output outputs/ml-plots01
```

输出 PNG 和 SVG，比例横轴采用可包含 0 的对称对数刻度，图为点估计、不自动添加置信带；PR 图标明仅覆盖可评分连接。每轮单独绘图，不直接把多个独立轮次混成一条线。

## 10. 先做可重复的合成集成检查

系统 Zeek：

```bash
python scripts/check_supervised_pipeline.py \
  --output outputs/ml-pipeline-check01
```

容器 Zeek：

```bash
python scripts/check_supervised_pipeline.py \
  --zeek "$PWD/scripts/zeek-docker.sh" \
  --output outputs/ml-pipeline-check01
```

脚本生成具有正确 IPv4 校验和、不同连接特征的合成 UDP 两类样本；构造独立训练、调参、校准和测试组，运行真实 Zeek，生成纯背景／50%／纯目标三个条件，再训练三模型、校准并测试。检查特征覆盖完整、9 组模型×条件结果齐全和分母一致。

**这不是 MAWI 和 GRN 实测。** 脚本中的类别名仅用于检查接口，50% 比例和 10% 误报预算仅用于小型流程检查，不是正式实验参数。正式实验仍按规定的低占比和低误报预算运行。

开发时已用官方 Zeek 7.0.0 容器和三个真实分类器通过完整检查。

自动化测试：

```bash
python -m unittest discover -s tests -v
```

覆盖连接映射、歧义／计数错误、阈值同分、极低误报样本分辨率、不可评分分母、三模型训练校准测试、数据泄漏拒绝，以及既有数据准备和 Suricata 测试。

## 11. 正式实验验收和结论范围

运行前确认业务覆盖和独立批次充足，开发／测试的可观测字段一致。检查 MAWI 与自采数据的单向性、截断、丢包和采集环境差异；建议增加同环境非 GRN 业务负样本，避免只是识别采集来源。当前清单 class=mawi 表示负类来源类别；若纳入其他背景，应保留其真实来源记录，并在方案中明确说明，不能把自采背景说成 MAWI。

保存输入清单、全部质量报告、环境和 Python 依赖版本、预处理模型、参数网格、阈值、预测和最终指标。对表现最好的合格模型评价低可识别性，不能只挑最弱模型。完整连接统计只评价连接段结束后的可识别性。

当前各混合条件固定全部可用背景，按比例增加完整 GRN 连接。目标子集嵌套，但数量和业务构成可能变化，需报告各条件样本量并比较共同目标子集；不能将 TPR 变化全部归因于占比。同一目标连接特征不变时固定模型通常给出相同评分，不预设低占比一定导致低 TPR。

当前提取与训练使用内存表，适合分批预实验；没有外存训练或 TB 级优化，不应直接把最低占比的大文件全部载入内存。实际数据规模不足、模型未收敛、提取覆盖不足、误报超标时，均先报告限制，不直接宣称反探测有效。

## 官方参考

- [Zeek 安装与官方容器](https://docs.zeek.org/en/v7.2.2/install.html)
- [Zeek conn.log 的方向和 IP 字节字段](https://docs.zeek.org/en/current/reference/logs/conn.html)
- [Zeek JSON 日志](https://docs.zeek.org/en/current/tutorial/logs.html)
- [scikit-learn 缺失值处理](https://scikit-learn.org/stable/modules/generated/sklearn.impute.SimpleImputer.html)
- [XGBoost CPU 版安装](https://xgboost.readthedocs.io/en/stable/install.html)
- [XGBoost 模型保存](https://xgboost.readthedocs.io/en/release_3.0.0/python/python_api.html)

相同特征表可直接用于 [背景自编码器实验](autoencoder.md)，AE 使用独立背景预处理，不加载监督模型的预处理参数。
