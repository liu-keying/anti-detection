"""Split classic PCAP by whole connection groups, retaining all other packets separately."""

# 文件拆分只保证已声明连接／业务组不跨分区，不自动产生独立采集批次。
import argparse
import csv
import hashlib
import json
import math
import os
import struct
from collections import defaultdict
from contextlib import ExitStack
from pathlib import Path

from .prepare import packets, decode, digest, positive, scan, write_json

# tuning 和 calibration 都属于 validation，但承担不同用途，不能混作同一验证组。
PARTS = ('train', 'tuning', 'calibration', 'test')


# 按完整业务组或双向五元组分配四个分区，返回源连接编号到分区／组的映射。
# 比例针对组数，按首次出现时间排序；保留至少一个组给每个分区。
def assignments(flows, ratios, mapping=None):
    if len(ratios) != 4 or any(not math.isfinite(r) or r <= 0 for r in ratios) or not math.isclose(sum(ratios), 1, abs_tol=1e-9):
        raise ValueError('four positive ratios summing to 1 are required: train,tuning,calibration,test')
    supplied = {}
    if mapping:
        with open(mapping, newline='') as f:
            for row in csv.DictReader(f):
                flow_id = int(row['source_flow_id'])
                group = row['business_group'].strip()
                if flow_id in supplied or not group:
                    raise ValueError('mapping has duplicate flow IDs or empty business_group')
                supplied[flow_id] = group
        if set(supplied) != {flow['id'] for flow in flows}:
            raise ValueError('mapping must cover every source_flow_id exactly once')
    groups, tuple_groups = defaultdict(list), {}
    for flow in flows:
        group = supplied[flow['id']] if mapping else 'tuple-' + hashlib.sha256(repr(flow['key']).encode()).hexdigest()[:16]
        if flow['key'] in tuple_groups and tuple_groups[flow['key']] != group:
            raise ValueError('same bidirectional tuple cannot belong to different business groups')
        tuple_groups[flow['key']] = group
        groups[group].append(flow)
    ordered = sorted(groups, key=lambda g: (min(f['start_ns'] for f in groups[g]), g))
    if len(ordered) < 4:
        raise ValueError(f'only {len(ordered)} connection/business groups; four nonempty partitions require at least four groups')
    result, start, cumulative = {}, 0, 0.0
    for index, part in enumerate(PARTS):
        cumulative += ratios[index]
        # 累计比例决定切点，并给剩余分区至少各留一组；按组数分配而不是按包截断。
        end = len(ordered) if index == 3 else max(start + 1, min(len(ordered) - (3 - index), math.floor(cumulative * len(ordered) + .5)))
        for group in ordered[start:end]:
            for flow in groups[group]:
                result[flow['id']] = (part, group)
        start = end
    return result


# 导出源连接编号、端点、时间范围及分组，支持人工填写真实业务会话映射。
def flow_rows(flows, allocation=None):
    for flow in flows:
        protocol, a, b = flow['key']
        part, group = allocation[flow['id']] if allocation else ('', '')
        yield dict(source_flow_id=flow['id'], business_group=group, partition=part,
                   protocol=protocol, endpoint_a=a[0], port_a=a[1], endpoint_b=b[0], port_b=b[1],
                   start_ns=flow['start_ns'], end_ns=flow['end_ns'], packets=flow['packets'], ip_bytes=flow['ip_bytes'])


# 保存非空连接清单；空输入不生成可能被误当成功结果的表头文件。
def write_rows(path, rows):
    rows = list(rows)
    if not rows:
        raise ValueError('no eligible TCP/UDP connections')
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


# 先统计并决定完整连接组归属，再第二遍按包流式写出四个分区。
# 无法建立连接标签的包进入 excluded.pcap，最后核对源文件未变及总包数守恒。
def split(args):
    source = Path(args.pcap).resolve()
    inventory, flows = scan(source, args.timeout)
    if not flows:
        raise ValueError('no eligible TCP/UDP connections')
    if args.source_class == 'grn' and not args.target_only:
        raise ValueError('GRN requires --target-only after confirming the input contains target business only')
    allocation = assignments(flows, [float(r) for r in args.ratios.split(',')], args.groups)
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    write_rows(out / 'assignments.csv', flow_rows(flows, allocation))
    counts = {part: dict(packets=0, ip_bytes=0, flows=0, groups=set()) for part in PARTS}
    for flow in flows:
        part, group = allocation[flow['id']]
        counts[part]['flows'] += 1
        counts[part]['groups'].add(group)
    active, next_id, excluded = {}, 0, 0
    with ExitStack() as stack:
        handles = {part: stack.enter_context(open(out / f'{part}.pcap', 'wb')) for part in (*PARTS, 'excluded')}
        first = True
        for ts, data, wirelen, linktype, snaplen in packets(source):
            if first:
                for handle in handles.values():
                    handle.write(b'\x4d\x3c\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, snaplen, linktype))
                first = False
            decoded, reason = decode(data, linktype)
            # 不支持的报文仍完整保留在排除文件中，保证拆分后的总包数守恒。
            if reason:
                part = 'excluded'
                excluded += 1
            else:
                key, ip_bytes, _ = decoded
                state = active.get(key)
                if state is None or ts - state[1] > args.timeout * 1_000_000_000:
                    state = (next_id, ts)
                    next_id += 1
                active[key] = (state[0], ts)
                part = allocation[state[0]][0]
                counts[part]['packets'] += 1
                counts[part]['ip_bytes'] += ip_bytes
            sec, fraction = divmod(ts, 1_000_000_000)
            handles[part].write(struct.pack('<IIII', sec, fraction, len(data), wirelen) + data)
    if next_id != len(flows) or digest(source) != inventory['sha256']:
        raise ValueError('source changed during splitting; output is incomplete and must not be used')
    captures = []
    for part, stats in counts.items():
        stats['groups'] = sorted(stats['groups'])
        stats['group_count'] = len(stats['groups'])
        stats['packet_fraction'] = stats['packets'] / inventory['packets']
        stats['sha256'] = digest(out / f'{part}.pcap')
        # derived 组名只表示派生文件身份；原始抓包来源及独立性限制也写进清单。
        entry = dict(path=f'{part}.pcap', **{'class': args.source_class},
                     group=f'derived-{inventory["sha256"][:12]}-{part}',
                     split=part if part in ('train', 'test') else 'validation',
                     derived_from_sha256=inventory['sha256'], independence='not_established_by_file_splitting')
        if part not in ('train', 'test'):
            entry['role'] = part
        if args.source_class == 'grn':
            entry['target_only'] = True
        captures.append(entry)
    write_json(out / 'captures.json', dict(captures=captures))
    write_json(out / 'split.json', dict(schema_version=1, source=inventory, timeout_seconds=args.timeout,
        requested_group_ratios=dict(zip(PARTS, [float(r) for r in args.ratios.split(',')])),
        grouping='business_group CSV' if args.groups else 'all observed segments of the same bidirectional tuple',
        grouping_csv_sha256=digest(args.groups) if args.groups else None, partitions=counts,
        excluded_packets=excluded, excluded_sha256=digest(out / 'excluded.pcap'),
        assignments_sha256=digest(out / 'assignments.csv'),
        packet_conservation=inventory['packets'] == excluded + sum(v['packets'] for v in counts.values()),
        warning='Derived groups are bookkeeping only, not independent captures. Time ranges can overlap. Audit business sessions before formal evaluation.'))


# 把两类拆分结果的相对路径改写成相对总清单的路径，供后续三个实验共用。
def merge_manifests(mawi_manifest, grn_manifest, output):
    out = Path(output).resolve()
    if out.exists():
        raise ValueError(f'output already exists: {out}')
    captures, source_hashes, seen_paths = [], {}, set()
    for source_class, manifest in (('mawi', mawi_manifest), ('grn', grn_manifest)):
        source = Path(manifest).resolve()
        rows = json.loads(source.read_text())['captures']
        if len(rows) != len(PARTS) or {row.get('role', row['split']) for row in rows} != set(PARTS):
            raise ValueError(f'{source}: expected one capture for each of {PARTS}')
        source_hashes[source_class] = {row.get('derived_from_sha256') for row in rows}
        for row in rows:
            if row['class'] != source_class:
                raise ValueError(f'{source}: unexpected capture class {row["class"]}')
            path = (source.parent / row['path']).resolve()
            if not path.is_file() or path in seen_paths:
                raise ValueError(f'missing or duplicate capture path: {path}')
            seen_paths.add(path)
            captures.append({**row, 'path': os.path.relpath(path, out.parent)})
    if (source_hashes['mawi'] - {None}) & (source_hashes['grn'] - {None}):
        raise ValueError('same original PCAP cannot supply both MAWI and GRN captures')
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('x') as file:
        json.dump({'captures': captures}, file, indent=2, ensure_ascii=False)
        file.write('\n')


# 拆分命令入口：inspect 导出连接编号，split 生成分区，merge 合并两类清单。
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    inspect = sub.add_parser('inspect', help='export observed flow IDs for optional business grouping')
    inspect.add_argument('pcap')
    inspect.add_argument('--timeout', type=positive, default=120)
    inspect.add_argument('--output', required=True)
    runner = sub.add_parser('split')
    runner.add_argument('pcap')
    runner.add_argument('--source-class', choices=['mawi', 'grn'], required=True)
    runner.add_argument('--target-only', action='store_true')
    runner.add_argument('--groups', help='CSV containing source_flow_id,business_group for every eligible flow')
    runner.add_argument('--ratios', default='0.5,0.15,0.15,0.2')
    runner.add_argument('--timeout', type=positive, default=120)
    runner.add_argument('--output', required=True)
    merger = sub.add_parser('merge', help='combine MAWI and GRN split manifests')
    merger.add_argument('--mawi', required=True, help='MAWI captures.json produced by split')
    merger.add_argument('--grn', required=True, help='GRN captures.json produced by split')
    merger.add_argument('--output', required=True, help='combined captures.json for prepare-data')
    args = parser.parse_args()
    try:
        if args.command == 'inspect':
            if Path(args.output).exists():
                raise ValueError('output already exists')
            _, flows = scan(args.pcap, args.timeout)
            write_rows(args.output, flow_rows(flows))
        elif args.command == 'split':
            split(args)
        else:
            merge_manifests(args.mawi, args.grn, args.output)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
