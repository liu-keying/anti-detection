# Suricata 通用规则离线实验手册

本实验使用冻结的通用规则（建议 ET Open），不添加 GRN 专用识别规则，不训练模型。输入为数据准备阶段的混合 PCAP 和真实标签。主要结果是“GRN 告警连接率”和“背景告警连接率”。普通安全告警不代表 GRN 身份识别，背景告警也不能直接称为误报。

## 1. 输入和实验条件

先完成 [共用数据准备](data-preparation.md)，例如生成：

```text
outputs/round01/
  inventory.json
  ratio_0/{mixed.pcap,labels.csv,manifest.json}
  ratio_0.0001/...
  ratio_0.001/...
  ratio_0.01/...
  ratio_0.05/...
  ratio_1/...
```

上述条件依次为纯背景、GRN 字节占比 0.01%、0.1%、1%、5%、纯 GRN。0% 和所有混合条件固定同一份全部可用背景，仅调整完整 GRN 连接数量；纯 GRN 是不含背景的独立校验组。使用实际混合比例作横轴；所有检测器使用同一套输入。纯 GRN 不保证产生通用告警。

本阶段为离线文件分析，不需要网卡监听、网络回放或抓包权限。第一版处理观测到的完整连接段，不能据此评价早期检测或真实在线告警时延。

## 2. 安装软件并启用 Python 环境

在受支持的 Ubuntu 环境安装 Suricata 和规则管理工具。以下系统命令由具有 sudo 权限的用户运行：

```bash
sudo apt update
sudo apt install suricata suricata-update
suricata --build-info
suricata-update --version
```

使用系统仓库安装是起步方式；若项目要求特定版本，应使用官方安装文档选择对应包并记录来源。不要直接把某个示例版本当作实际环境版本。当前开发机的系统安装尚未执行；`suricata-experiment` 找不到引擎会明确报错。

进入本项目根目录：

```bash
source venv/bin/activate
python -m pip install -e .
suricata-experiment --help
```

本模块新增 PyYAML 依赖，已在当前项目 `venv` 中安装。之后每个新终端只需激活 `venv`。与数据准备工具相同，不需要设置 PYTHONPATH。

## 3. 获取并记录通用规则

在默认未添加额外来源的 suricata-update 配置中，默认来源是 ET Open：

```bash
mkdir -p outputs/rule-provenance
suricata-update list-enabled-sources > outputs/rule-provenance/enabled-sources.txt
sudo suricata-update
suricata --build-info > outputs/rule-provenance/build-info.txt
suricata-update --version > outputs/rule-provenance/update-version.txt
```

保存下载日期、工具输出、更新配置及 enable/disable/modify/drop 等规则调整文件。确认最终合并规则位置，常见路径为 `/var/lib/suricata/rules/suricata.rules`。`list-enabled-sources` 的输出还需要结合默认来源配置理解，不能仅凭空列表断言未使用 ET Open。

如果启用了其他来源，实验名称应包含这些来源，不能写“仅 ET Open”。初次准备可以更新；正式冻结后不再用更新后的文件替换快照。不要因测试结果调整规则。

## 4. 准备实验配置

复制系统提供的完整配置，保留协议分析、流重组、资源限制及规则变量，避免使用缺少解析配置的简化 YAML：

```bash
cp /etc/suricata/suricata.yaml configs/suricata-experiment.yaml
```

编辑 `configs/suricata-experiment.yaml`，完成以下检查：

1. **网络变量。** 按预先规定的观测场景设置 `HOME_NET` 和 `EXTERNAL_NET`。主实验不要按 GRN 真值地址区别配置。若采用“任意方向都可能出现目标”的通用离线场景，可同时设 `HOME_NET: "any"` 和 `EXTERNAL_NET: "any"`，并记录这会影响规则方向和匹配范围。不能设置 HOME_NET=any、EXTERNAL_NET=!$HOME_NET 导致外部范围为空。
2. **配置依赖。** 将 `classification-file`、`reference-config-file`、存在的 `threshold-file` 改为实际绝对路径，常见目录为 `/etc/suricata/`。复制出来的相对路径不会自动指向系统目录。
3. **规则及解析。** 检查流和 TCP 重组、应用层协议、memcap、异常策略、白名单、bypass 和阈值抑制。主实验前确定，所有条件一致。记录任何禁用或抑制规则。
4. **卸载与校验和。** 原始端点抓包可能含卸载导致的错误校验和，先核查原因。运行默认 `--checksums all`。如果预先决定忽略校验和，所有条件均显式使用 `--checksums none`，并记录原因，不能对某个结果单独放宽。
5. **外部依赖。** 当前快照工具要求单文件配置、合并单行规则；不支持 include、Lua、dataset、IP reputation 等额外外部依赖。遇到此类配置先另行实现依赖快照，不静默跳过。自定义文件路径等非标准依赖也必须人工审核。

冻结工具会明确设置 `single` 运行模式，关闭 Unix socket，启用单文件 `eve.json`，仅输出 alert、flow、累计 stats。它不会自动解决采集差异、协议不适用或缺失载荷问题。保留的系统配置中其他行为仍需审核。

## 5. 运行合成流程阳性校验

```bash
suricata-experiment selftest \
  --config configs/suricata-experiment.yaml \
  --output outputs/suricata-pipeline-check01
```

工具生成一个合法 IPv4 UDP PCAP、独立规则 SID `9900001`，执行配置检查和真实离线检测，并验证该 SID 确实产生告警。成功产物为 `selftest.json`，状态 `passed`；失败查看 console.log 和 snapshot/config-check.log。

这个规则只校验文件读取、规则加载、UDP 内容匹配和 EVE 输出路径。它不写入 GRN 数据、不添加到 ET Open、不证明 ET Open、TCP 重组或所有协议解析器均有效。

**正式实验还需 ET Open 阳性校验：**准备已知可命中当前冻结通用规则的独立 PCAP，在冻结快照下运行并检查预期 SID。记录样本来源、哈希、预期 SID、实际命中及适用的协议路径。该样本不能取自正式测试集来反向调规则。当前仓库没有提供第三方阳性流量；未完成此项时，只能标注“合成流程已校验，通用规则能力待校验”。

## 6. 冻结规则和配置

替换 `--source` 为实际来源和下载日期：

```bash
suricata-experiment freeze \
  --config configs/suricata-experiment.yaml \
  --rules /var/lib/suricata/rules/suricata.rules \
  --source 'ET Open; downloaded YYYY-MM-DD; updater configuration archived in outputs/rule-provenance' \
  --output outputs/suricata-snapshot01
```

产物包括原配置、副本规则、实验配置、分类／引用／阈值文件副本、构建信息、配置检查日志、哈希清单和引擎二进制校验值。存在输出目录则拒绝覆盖。

**人工查看 `config-check.log` 和 `check/suricata.log` 中实际加载／失败规则数及警告。** `snapshot.json` 的 `declared_rule_lines` 只是规则文本行数，不等于实际加载数量。确认预期规则加载、无未知失败后才进行正式检测。

快照内配置使用绝对路径，冻结后不要移动目录、修改规则或配置。运行前自动核对冻结文件和 Suricata 二进制哈希；共享库、操作系统、规则来源记录仍需额外保留，二进制哈希不能替代完整环境镜像。

如需查看引擎最终配置，可额外保存：

```bash
suricata -c outputs/suricata-snapshot01/experiment.yaml --dump-config \
  > outputs/rule-provenance/effective-config.txt
python -m pip freeze > outputs/rule-provenance/python-requirements.txt
```

用独立已知 ET Open 阳性 PCAP 运行快照的示例（将路径替换为实际值）：

```bash
suricata-experiment check-positive \
  --snapshot outputs/suricata-snapshot01 \
  --pcap /absolute/path/to/known-positive.pcap \
  --sid 1234567 --checksums all \
  --output outputs/et-open-positive01
```

`1234567` 是占位编号，必须替换为已知样本应命中的真实 SID；可重复传入 `--sid` 要求多个规则均命中。工具会核对所有预期 SID 并写出 `positive-check.json`，未命中则返回失败。仍应检查告警语义和协议解析。如果主实验选 `none`，该校验也使用相同策略。

## 7. 批量运行所有比例

```bash
suricata-experiment run \
  --snapshot outputs/suricata-snapshot01 \
  --input outputs/round01 \
  --checksums all \
  --output outputs/suricata-round01
```

工具逐条件校验混合 PCAP 和标签哈希；每个条件独立启动 Suricata、使用新日志目录、单独统计，不在条件之间继承流状态。命令通过 `-S` 仅加载快照规则，`-r` 离线读取 PCAP。

只跑一个条件时，`--input` 可以指向 `outputs/round01/ratio_0.01`。任何引擎错误会停止后续条件，保留日志并将 run.json 标为 failed；修复后使用新输出目录。不要把残留目录当完整实验结果。

也可对已有 EVE 单独分析：

```bash
suricata-experiment analyze \
  --condition outputs/round01/ratio_0.01 \
  --eve outputs/suricata-round01/ratio_0.01/eve.json \
  --output outputs/reanalysis-round01-ratio001
```

独立分析会校验 PCAP／标签哈希，但不会验证已有 EVE 究竟由哪个规则集产生；正式报告应使用 run.json、规则快照及日志一同确认来源。

## 8. 告警归因和统计口径

映射不直接依赖 Suricata flow_id 等于标签 ID。工具使用下列顺序：

1. EVE alert 有 `pcap_cnt`：映射到混合文件中实际包编号，并校验双向五元组。包编号无效或五元组不符则不猜测归因。
2. 没有包编号：如果同一 flow_id 的 flow 事件可用，使用双向五元组＋flow 起止区间；仅当对应一个标签连接段时归因。
3. 没有可用 flow 事件：用五元组＋告警时间匹配，允许最多 999 纳秒时间精度误差。只能唯一匹配才归因。

多个候选或无法匹配均进入 `unresolved-alerts.csv`。一个 Suricata flow 跨多个准备阶段连接段时，无包编号的告警可能无法唯一归因，应人工核查，不按标签来源强行判断。

同一标签连接无论触发多少条规则／多少次告警，告警连接数只加一。原始条数和各规则的连接数另存。

| 指标 | 计算方式 |
|---|---|
| GRN 告警连接率 | 至少有一个已归因通用告警的 GRN 连接段数／全部 GRN 标签连接段数 |
| 背景告警连接率 | 至少有一个已归因通用告警的背景连接段数／全部背景标签连接段数 |
| 规则分布 | 按 gid:sid:rev 统计原始告警条数、去重连接数和两类连接数 |
| 处理核查 | 标签包数、最后一条累计 stats.decoder.pkts、未归因告警数、flow 事件数及完整原始 stats |

0% 条件的 GRN 告警连接率为空（JSON null、CSV 空值），不是零。GRN 身份识别率一律记“不在本通用告警统计中评价”；如果发现明确指向 GRN 的规则，需要人工审核语义并另建身份识别分析。

存在未归因告警时，当前告警连接率只是可确认结果的下界，不能用于直接证明低告警。`counts_match_review_stats` 仅表示包计数相符、有 flow 记录且无未归因告警，**不是质量全部通过**。仍需审核校验和、解析错误、重组失败、资源上限、告警队列溢出／抑制／bypass 等指标。`review_required` 表示需先排查；缺少 stats 直接停止分析。

运行处理耗时仅反映离线处理效率。severity 为规则严重等级，不是检测置信度。

## 9. 输出结构和人工复核

```text
outputs/suricata-round01/
  summary.json
  summary.csv
  ratio_0.01/
    run.json                 # 命令、规则快照哈希、校验和策略、执行状态、耗时
    console.log
    suricata.log             # 具体文件由引擎生成
    eve.json
    analysis/
      metrics.json
      connections.csv        # 每个原始标签连接及 generic_alerted
      groups.csv             # 按来源类别和独立采集组统计
      alerts.csv             # 每条告警的规则、连接归因和方法
      unresolved-alerts.csv
      rules.csv
      stats.json             # 全部 stats 事件，保留诊断信息
```

人工对 GRN 命中规则逐类确认：规则描述的是普通协议行为、安全事件、采集错误，还是确实识别了 GRN。结合 MAWI 的载荷截断限制审查规则适用性。低告警可能来自没有适用规则、缺失载荷或解析失败，不可直接归因于反探测。

## 10. 多轮实验、置信区间及结论

以独立背景日期和 GRN 批次构造多轮输入，每轮共用同一个冻结快照和校验和策略。多轮输出分别保存，不把重复运行相同 PCAP 当作独立样本。

建议报告：轮次、实际字节比例、两类连接总数／告警连接数／连接率、未归因告警数、处理核查状态、主要规则。不同条件复用 GRN 时作配对比较。不要直接把各比例分母加总当独立目标样本。

当前自动统计保留连接的 group，但不自动生成置信区间。正式统计应按独立采集组／轮次进行分组估计（例如有足够独立组时采用分组 bootstrap）；只有一个组时不能声称组间稳定性。需要独立样本假设的二项区间须明确写出假设，不能机械套用到相关连接。

结论模板：

> 在指定 Suricata 版本、冻结通用规则及观测条件下，各比例 GRN 告警连接率为……，背景告警连接率为……，主要命中规则为……。输入处理、告警归因及载荷适用性核查结果为……。该结果反映所选配置下的通用告警表现；GRN 身份可识别性需结合监督分类实验另行评价。

## 11. 验证与当前边界

```bash
python -m unittest discover -s tests -v
```

测试覆盖双向包归因、重复告警去重、无效包编号、伪包 flow 区间映射、零目标条件、缺失统计拒绝、输入及快照篡改、纳秒时间戳。真实引擎验证使用 selftest；单元测试中的模拟引擎不能代替它。

也可执行三条件完整合成集成检查（纯背景、50% 混合、纯目标）：

```bash
python scripts/check_suricata_pipeline.py \
  --config configs/suricata-experiment.yaml \
  --output outputs/suricata-integration-check01
```

开发时已用真实 Suricata 7.0.3 在临时容器中通过此检查：目标样本命中、背景样本不命中、全部包数一致、无未归因告警。容器镜像为 `jasonish/suricata:7.0.3`，摘要 `sha256:01e8d513beb284c8738ce0fbd98a8e95d202f1e27a04c15b00c1c61c3a2b8fdc`。这只是合成规则集成验证；未执行真实 ET Open／GRN 正式实验。系统 Suricata 仍需按前述步骤安装。

当前分析会在内存中保存标签、包编号索引和 EVE 告警／flow 事件，适合分批预实验。它没有针对 TB 级单文件优化。没有真实 GRN／MAWI 和已知 ET Open 阳性样本时，只能完成程序和合成流程验证，不能形成正式实验结论。

## 官方参考

- [Suricata 安装](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [Suricata-Update 规则管理与默认 ET Open](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [命令行参数：-T、-S、-r、-l、-k、runmode](https://docs.suricata.io/en/suricata-8.0.4/command-line-options.html)
- [EVE 格式、pcap_cnt 与 flow 关联](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html)
