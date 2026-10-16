# 单个 PCAP 的分组拆分

命令 `split-pcap` 将一个经典 PCAP 导出为 train、tuning、calibration、test 四份，保留报文内容、原始时间戳、包序和线长，不进行网络回放。

## 1. 启用环境

```bash
source venv/bin/activate
python -m pip install -e .
mkdir -p outputs data/split
split-pcap --help
```

## 2. 自动按连接组拆分

以下输入路径需替换为实际文件。示例按组数约 50%／15%／15%／20% 分配：

```bash
split-pcap split data/raw/mawi/original.pcap \
  --source-class mawi --ratios 0.5,0.15,0.15,0.2 \
  --timeout 120 --output data/split/mawi01
```

GRN 需先确认 PCAP 只包含目标业务，再执行：

```bash
split-pcap split data/raw/grn/original.pcap \
  --source-class grn --target-only \
  --ratios 0.5,0.15,0.15,0.2 --timeout 120 \
  --output data/split/grn01
```

`--target-only` 是标签确认，不会自动筛除 SSH 等流量。已有输出目录不会覆盖。

默认将同一双向五元组的全部空闲超时连接段归到同一组，即使中途超过 timeout，也不会把相同五元组放到不同分区。按组的最早出现时间排序，再按组数量分配；不随机拆包、不按固定文件大小切断连接。

四个比例必须为正数且总和为 1。至少需要四个组；组数不足会拒绝拆分。小样本时优先保证每个分区非空，实际组数比例、包数及字节比例不保证与指定比例精确相同。

## 3. 可选：按真实业务会话组拆分

一项业务如果使用多个连接，应提供会话映射，避免仅按五元组拆开相关连接。

先导出连接编号：

```bash
split-pcap inspect data/raw/grn/original.pcap \
  --timeout 120 --output outputs/grn-flows01.csv
```

结合业务日志，填写新的 `configs/grn-business-groups.csv`：

```csv
source_flow_id,business_group
0,run-A
1,run-A
2,run-B
3,run-C
4,run-D
```

每个实际 source_flow_id 必须恰好出现一次；上表仅为格式示例。相同 business_group 的所有连接整体进入一个分区。同一双向五元组不能声明为不同业务组。

```bash
split-pcap split data/raw/grn/original.pcap \
  --source-class grn --target-only \
  --groups configs/grn-business-groups.csv \
  --ratios 0.5,0.15,0.15,0.2 --timeout 120 \
  --output data/split/grn-by-session01
```

导出映射与拆分时必须使用相同原始 PCAP 和 timeout。

## 4. 检查输出

```text
data/split/mawi01/
  train.pcap
  tuning.pcap
  calibration.pcap
  test.pcap
  excluded.pcap
  assignments.csv
  captures.json
  split.json
```

```bash
python -m json.tool data/split/mawi01/split.json
head -n 10 data/split/mawi01/assignments.csv
prepare-data validate data/split/mawi01/captures.json
```

split.json 保存输入哈希、排除原因、实际各分区组数／流数／包数／IP 字节数、文件哈希和 packet_conservation。该字段应为 true。assignments.csv 逐连接记录所属组和分区。

`excluded.pcap` 保留共用解析器未纳入的报文（例如非 TCP/UDP、IP 分片、部分 IPv6 扩展头），没有这些报文时仍输出空 PCAP。它不加入实验清单。四份分区加 excluded 的报文总数等于原始包数；原始文件不修改。

## 5. 合并 MAWI 和 GRN 清单

两份输出 captures.json 的路径分别相对各自目录，合并时转换为绝对路径：

```bash
python - <<'PY'
import json
from pathlib import Path

captures = []
for manifest in (Path('data/split/mawi01/captures.json'),
                 Path('data/split/grn01/captures.json')):
    for item in json.loads(manifest.read_text())['captures']:
        item['path'] = str((manifest.parent / item['path']).resolve())
        captures.append(item)
output = Path('configs/captures-from-split01.json')
if output.exists():
    raise SystemExit(f'Output already exists: {output}')
output.write_text(json.dumps({'captures': captures}, indent=2) + '\n')
PY
prepare-data validate configs/captures-from-split01.json
```

后续 README 中涉及 `configs/captures.json` 的命令可替换为 `configs/captures-from-split01.json`，继续混合与提取特征。若使用自定义会话输出目录，同步替换合并脚本中的路径。

## 6. 实验独立性与使用范围

该工具保证连接／已声明业务组不跨分区，不能自动证明分区是独立采集。输出 group 中的 `derived-...` 只是追踪标识，不代表独立日期；captures.json 保留 derived_from_sha256 和独立性说明，不应据此声称跨日期泛化。

各组按首次出现时间分配，但长连接跨越多个时间段时仍整体保留，因此不同分区的实际时间范围可能重叠。如果整份 PCAP 只有一个独立业务会话，即使有多个五元组也应在映射中归为同一组，工具将拒绝分成四份；需要补充独立运行批次。

同一来源的跨文件重复流量需要额外人工核查。当前特征提取以每个输出文件为一个来源组，自动置信区间也不能将该文件中的连接当成独立采集批次。

实现按包流式写出，仅连接与分组元数据保存在内存；仍需为四份输出及排除文件预留接近原始抓包保存量的磁盘空间。
