"""Dependency-free classic PCAP preparation. Original captures are never modified."""

# 共用数据口径：比例按 IP 声明字节计，标签按观测连接段计；原始文件始终保持不变。
import argparse
import csv
import hashlib
import ipaddress
import json
import random
import struct
from collections import defaultdict
from decimal import Decimal
from pathlib import Path

# 魔数同时决定文件端序和时间单位；unit 表示原始小数部分换算为纳秒的倍数。
MAGIC = {b'\xd4\xc3\xb2\xa1': ('<', 1000), b'\xa1\xb2\xc3\xd4': ('>', 1000),
         b'\x4d\x3c\xb2\xa1': ('<', 1), b'\xa1\xb2\x3c\x4d': ('>', 1)}


# 分块计算 SHA256，避免为了记录文件身份将整个 PCAP 读入内存。
def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


# 逐包读取经典 PCAP，统一返回纳秒时间戳、捕获内容、原始线长和链路信息。
# 校验长度及时间顺序；捕获长度与线上报文长度不同，不能混作流量字节量。
def packets(path):
    with open(path, 'rb') as f:
        header = f.read(24)
        if len(header) != 24 or header[:4] not in MAGIC:
            raise ValueError(f'{path}: requires classic PCAP, not PCAPNG')
        endian, unit = MAGIC[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + 'HHiIII', header[4:])
        if (major, minor) != (2, 4) or linktype not in (1, 101, 113, 276):
            raise ValueError(f'{path}: unsupported PCAP version/linktype {linktype}')
        previous = -1
        while True:
            record = f.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError(f'{path}: incomplete record header')
            sec, frac, caplen, wirelen = struct.unpack(endian + 'IIII', record)
            if frac >= 1_000_000_000 // unit or caplen > snaplen or caplen > wirelen:
                raise ValueError(f'{path}: invalid record lengths/timestamp')
            data = f.read(caplen)
            if len(data) != caplen:
                raise ValueError(f'{path}: incomplete packet')
            ts = sec * 1_000_000_000 + frac * unit
            if ts < previous:
                raise ValueError(f'{path}: timestamps out of order')
            previous = ts
            yield ts, data, wirelen, linktype, snaplen


# 解析受支持的链路／IP／传输头，返回规范化双向五元组、IP 声明长度及截断标志。
# 无法可靠建立连接标签的报文返回排除原因，不将缺失载荷等同于零长度流量。
def decode(data, linktype):
    if linktype == 1:
        if len(data) < 14:
            return None, 'short_link_header'
        offset, typ = 14, int.from_bytes(data[12:14], 'big')
        while typ in (0x8100, 0x88a8, 0x9100):
            if len(data) < offset + 4:
                return None, 'short_vlan_header'
            typ = int.from_bytes(data[offset + 2:offset + 4], 'big')
            offset += 4
        if typ not in (0x0800, 0x86dd):
            return None, 'non_ip'
    elif linktype == 113:
        if len(data) < 16:
            return None, 'short_link_header'
        if int.from_bytes(data[14:16], 'big') not in (0x0800, 0x86dd):
            return None, 'non_ip'
        offset = 16
    elif linktype == 276:
        if len(data) < 20:
            return None, 'short_link_header'
        if int.from_bytes(data[:2], 'big') not in (0x0800, 0x86dd):
            return None, 'non_ip'
        offset = 20
    else:
        offset = 0
    ip = data[offset:]
    if not ip:
        return None, 'short_ip_header'
    version = ip[0] >> 4
    if version == 4:
        if len(ip) < 20:
            return None, 'short_ip_header'
        hlen, size, proto = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], 'big'), ip[9]
        if hlen < 20 or len(ip) < hlen or size < hlen:
            return None, 'invalid_ip_header'
        if int.from_bytes(ip[6:8], 'big') & 0x3fff:
            return None, 'fragment'
        src, dst = str(ipaddress.ip_address(ip[12:16])), str(ipaddress.ip_address(ip[16:20]))
    elif version == 6:
        if len(ip) < 40:
            return None, 'short_ip_header'
        hlen, size, proto = 40, 40 + int.from_bytes(ip[4:6], 'big'), ip[6]
        src, dst = str(ipaddress.ip_address(ip[8:24])), str(ipaddress.ip_address(ip[24:40]))
        if proto in (0, 43, 44, 50, 51, 60):
            return None, 'ipv6_extension_header'
        if size == 40:
            return None, 'ipv6_empty_or_jumbo'
    else:
        return None, 'non_ip'
    if proto not in (6, 17):
        return None, 'non_tcp_udp'
    minimum = 20 if proto == 6 else 8
    if len(ip) < hlen + minimum or size < hlen + minimum:
        return None, 'short_transport_header'
    sport, dport = struct.unpack('!HH', ip[hlen:hlen + 4])
    key = (proto, *sorted(((src, sport), (dst, dport))))
    return (key, size, len(ip) < size), None


# 按双向五元组和空闲超时统计观测连接段，仅在内存保存连接元数据。
# 这里的连接段不保证与 Zeek／Suricata 的默认会话边界一致。
def scan(path, timeout):
    flows, active, excluded = [], {}, defaultdict(int)
    total = truncated = 0
    linktypes = set()
    for index, (ts, data, wirelen, linktype, snaplen) in enumerate(packets(path)):
        total += 1
        truncated += len(data) < wirelen
        linktypes.add(linktype)
        decoded, reason = decode(data, linktype)
        if reason:
            excluded[reason] += 1
            continue
        key, size, _ = decoded
        flow = active.get(key)
        if flow is None or ts - flow['end_ns'] > timeout * 1_000_000_000:
            flow = dict(id=len(flows), key=key, start_ns=ts, end_ns=ts, packets=0, ip_bytes=0)
            flows.append(flow)
            active[key] = flow
        flow['end_ns'] = ts
        flow['packets'] += 1
        flow['ip_bytes'] += size
    return dict(path=str(Path(path).resolve()), sha256=digest(path), packets=total,
                captured_truncated_packets=truncated, excluded_packets=dict(excluded),
                linktypes=sorted(linktypes), eligible_flows=len(flows),
                eligible_ip_bytes=sum(f['ip_bytes'] for f in flows)), flows


# 统一保存可读的 UTF-8 JSON；实验清单与结果均通过此入口写出。
def write_json(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n')


# 解析相对清单路径，并检查标签确认、分区合法性、组跨分区及重复文件。
# 文件哈希只能识别完全相同的文件，不能证明不同 PCAP 没有重复会话。
def load_manifest(path):
    root = Path(path).resolve().parent
    doc = json.loads(Path(path).read_text())
    rows = doc['captures']
    groups, hashes, paths = {}, {}, set()
    for row in rows:
        row['path'] = str((root / row['path']).resolve())
        if row['class'] not in ('mawi', 'grn') or row['split'] not in ('train', 'validation', 'test'):
            raise ValueError('invalid class or split')
        if not row.get('group'):
            raise ValueError('every capture requires a group (date/session leakage unit)')
        if row['class'] == 'grn' and row.get('target_only') is not True:
            raise ValueError('GRN capture requires target_only=true after checking business labels')
        group = (row['class'], row['group'])
        if group in groups and groups[group] != row['split']:
            raise ValueError(f'group crosses splits: {group}')
        groups[group] = row['split']
        if row['path'] in paths:
            raise ValueError('duplicate capture path')
        paths.add(row['path'])
        sha = digest(row['path'])
        if sha in hashes:
            raise ValueError('identical capture content appears more than once')
        hashes[sha] = row['path']
    return rows


# 固定所选分区的全部可用背景，通过完整 GRN 连接的嵌套前缀改变占比。
# 先验证所有比例及目标池容量，再建立输出，防止把部分条件误当完整实验。
def run_mix(args):
    rows = load_manifest(args.manifest)
    selected = [r for r in rows if r['split'] == args.split]
    pools = {'mawi': [], 'grn': []}
    inventories = []
    links = set()
    for row in selected:
        info, flows = scan(row['path'], args.timeout)
        inventories.append(dict(**info, source_class=row['class'], group=row['group']))
        links.update(info['linktypes'])
        for flow in flows:
            flow.update(source=row['path'], source_class=row['class'], group=row['group'])
            pools[row['class']].append(flow)
    if len(links) != 1:
        raise ValueError('all selected PCAP files must have the same linktype')
    if not pools['mawi'] or not pools['grn']:
        raise ValueError('selected split requires eligible MAWI and GRN flows')
    # Distinct original tuples ensure downstream parsers cannot merge unrelated source flows.
    owners = {}
    for flow in pools['mawi'] + pools['grn']:
        owner = (flow['source'], flow['source_class'])
        if flow['key'] in owners and owners[flow['key']] != owner:
            raise ValueError('five-tuple collision across sources; prepare collision-free inputs first')
        owners[flow['key']] = owner
    # 只打乱目标连接：相同种子产生同一前缀序列，因此不同占比使用嵌套目标子集。
    rng = random.Random(args.seed)
    rng.shuffle(pools['grn'])
    background_bytes = sum(f['ip_bytes'] for f in pools['mawi'])
    available_grn_bytes = sum(f['ip_bytes'] for f in pools['grn'])
    ratios = [Decimal(x) for x in args.ratios.split(',')]
    if any(not r.is_finite() for r in ratios) or len(set(ratios)) != len(ratios) or any(r < 0 or r > 1 for r in ratios):
        raise ValueError('ratios must be unique finite fractions between 0 and 1')
    plans = []
    for ratio in ratios:
        if ratio == 0:
            chosen, actual = pools['mawi'], 0
        elif ratio == 1:
            # Pure-target capability check is separate from fixed-background mixtures.
            chosen, actual = pools['grn'], 1
        else:
            # Decimal 用于低占比预算，降低浮点误差；背景字节量在整轮内保持固定。
            target = Decimal(background_bytes) * ratio / (1 - ratio)
            if available_grn_bytes < target:
                raise ValueError(f'insufficient GRN for ratio {ratio}; need {target} IP bytes, have {available_grn_bytes}')
            grn, size = [], 0
            for flow in pools['grn']:
                previous_size = size
                grn.append(flow)
                size += flow['ip_bytes']
                if size >= target:
                    # Nearest nonempty prefix, measured using the requested byte ratio.
                    previous_ratio = Decimal(previous_size) / (background_bytes + previous_size)
                    current_ratio = Decimal(size) / (background_bytes + size)
                    if len(grn) > 1 and abs(previous_ratio - ratio) <= abs(current_ratio - ratio):
                        grn.pop()
                        size = previous_size
                    break
            chosen = pools['mawi'] + grn
            actual = size / (background_bytes + size)
            if abs(actual - float(ratio)) / float(ratio) > args.tolerance:
                raise ValueError(f'whole-flow ratio error exceeds tolerance for {ratio}: {actual}')
        plans.append((ratio, chosen, actual))
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=False)
    write_json(out / 'inventory.json', inventories)
    for ratio, chosen, actual in plans:
        folder = out / ('ratio_' + str(ratio))
        folder.mkdir()
        export(folder, chosen, next(iter(links)), args, actual, ratio)


# 导出一个条件的 PCAP、逐连接标签和追溯清单；不改写源文件的包内容。
# 每份源抓包只做一次整体时间平移，保留其内部连接和包之间的时间关系。
def export(folder, flows, linktype, args, actual, ratio):
    by_source = defaultdict(list)
    for flow in flows:
        by_source[flow['source']].append(flow)
    records, labels = [], []
    epoch = 1_700_000_000 * 1_000_000_000
    for source, chosen in by_source.items():
        # One shift per capture preserves cross-flow timing within that capture.
        _, all_flows = scan(source, args.timeout)
        # 所有条件用同一个源时间原点，未被选中的早期目标不会改变其他连接的时间平移。
        shift = epoch - min(f['start_ns'] for f in all_flows)
        wanted = {f['id']: f for f in chosen}
        active, next_id = {}, 0
        for ts, data, wirelen, lt, snap in packets(source):
            decoded, reason = decode(data, lt)
            if reason:
                continue
            key = decoded[0]
            state = active.get(key)
            if state is None or ts - state[1] > args.timeout * 1_000_000_000:
                state = (next_id, ts)
                next_id += 1
            active[key] = (state[0], ts)
            if state[0] in wanted:
                records.append((ts + shift, data, wirelen))
        for f in chosen:
            proto, a, b = f['key']
            labels.append(dict(connection_id=f"c{len(labels):08d}", label=int(f['source_class'] == 'grn'),
                               protocol=proto, endpoint_a=a[0], port_a=a[1], endpoint_b=b[0], port_b=b[1],
                               start_ns=f['start_ns'] + shift, end_ns=f['end_ns'] + shift,
                               packets=f['packets'], ip_bytes=f['ip_bytes'], source=source,
                               source_flow_id=f['id'], group=f['group'], time_shift_ns=shift))
    records.sort(key=lambda x: x[0])
    with open(folder / 'mixed.pcap', 'wb') as f:
        f.write(b'\x4d\x3c\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, max(len(r[1]) for r in records), linktype))
        for ts, data, wirelen in records:
            sec, ns = divmod(ts, 1_000_000_000)
            f.write(struct.pack('<IIII', sec, ns, len(data), wirelen) + data)
    with open(folder / 'labels.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(labels[0]))
        writer.writeheader()
        writer.writerows(labels)
    counts = {}
    for label, name in ((0, 'mawi'), (1, 'grn')):
        subset = [f for f in labels if f['label'] == label]
        counts[name] = {k: sum(f[k] for f in subset) for k in ('packets', 'ip_bytes')}
        counts[name]['connections'] = len(subset)
    write_json(folder / 'manifest.json', dict(schema_version=2, split=args.split, seed=args.seed,
        mixing_strategy="fixed_background_variable_grn",
        condition_kind="pure_grn_control" if ratio == 1 else "fixed_background_mixture",
        timeout_seconds=args.timeout, requested_byte_ratio=str(ratio), actual_byte_ratio=actual,
        packet_ratio=counts['grn']['packets'] / len(records),
        connection_ratio=counts['grn']['connections'] / len(labels), counts=counts,
        input_manifest_sha256=digest(args.manifest), pcap_sha256=digest(folder / 'mixed.pcap'),
        labels_sha256=digest(folder / 'labels.csv'),
        exclusions='Only nonfragmented TCP/UDP with readable base transport header; see inventory.json',
        alignment='Each source capture shifted to common epoch; no address/payload modification'))


# 将命令行参数解析为正整数，用于超时、线程等不能为零的设置。
def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('must be positive')
    return number


# 数据准备命令入口：原始检查、清单校验或固定背景混合。
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    inspect = sub.add_parser('inspect')
    inspect.add_argument('pcaps', nargs='+')
    inspect.add_argument('--output', required=True)
    inspect.add_argument('--timeout', type=positive, default=120)
    check = sub.add_parser('validate')
    check.add_argument('manifest')
    mix = sub.add_parser('mix')
    mix.add_argument('manifest')
    mix.add_argument('--split', choices=['train', 'validation', 'test'], default='test')
    mix.add_argument('--output', required=True)
    mix.add_argument('--ratios', default='0,0.0001,0.001,0.01,0.05,1')
    mix.add_argument('--seed', type=int, default=2026)
    mix.add_argument('--timeout', type=positive, default=120)
    mix.add_argument('--tolerance', type=float, default=0.05, help='maximum relative byte ratio error')
    args = parser.parse_args()
    try:
        if args.command == 'inspect':
            if Path(args.output).exists():
                raise ValueError('output already exists')
            write_json(args.output, [scan(p, args.timeout)[0] for p in args.pcaps])
        elif args.command == 'validate':
            rows = load_manifest(args.manifest)
            print(f'Validated {len(rows)} captures; no group or exact-file duplication leakage')
        else:
            if not 0 <= args.tolerance <= 1:
                raise ValueError('tolerance must be between 0 and 1')
            run_mix(args)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
