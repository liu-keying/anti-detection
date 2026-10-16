"""Zeek extraction and conservative one-to-one label matching."""

# 特征接口约定：只用双方可靠可见的数值统计；所有追踪字段与模型输入分离。
import csv
import hashlib
import json
import math
import shutil
import subprocess
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

from .prepare import digest, load_manifest, scan, write_json
from .suricata import key, write_csv

# 这是模型输入白名单；修改顺序或含义后必须重新提取并训练所有模型。
FEATURES = ['duration', 'orig_pkts', 'resp_pkts', 'orig_ip_bytes', 'resp_ip_bytes',
            'total_pkts', 'total_ip_bytes', 'orig_mean_ip_len', 'resp_mean_ip_len', 'orig_byte_fraction']
SCRIPT = 'redef LogAscii::use_json = T;\nredef use_conn_size_analyzer = T;\n'
# META 仅保存追踪、分区和质量信息，不能混入用于学习的十维特征。
META = ['sample_id', 'connection_id', 'source_sha256', 'group', 'split', 'role', 'label',
        'packets', 'ip_bytes', 'status', 'zeek_uid']


# 记录 Zeek 版本、引擎文件、提取脚本和校验和策略，供开发／测试一致性检查。
def profile(binary, checksums):
    found = shutil.which(binary)
    if not found:
        raise ValueError(f'Zeek executable not found: {binary}')
    executable = str(Path(found).resolve())
    result = subprocess.run([executable, '--version'], capture_output=True, text=True, check=True)
    info = dict(zeek_version=(result.stdout + result.stderr).strip(), binary_sha256=digest(executable),
                script_sha256=hashlib.sha256(SCRIPT.encode()).hexdigest(), checksums=checksums,
                features=FEATURES, mapping='one-to-one tuple/interval and exact packet/IP-byte counts v1')
    return executable, info


# 用标签中的两个端点生成方向无关的连接键，仅用于匹配，不送入模型。
def label_key(row):
    return key(row['protocol'], row['endpoint_a'], row['port_a'], row['endpoint_b'], row['port_b'])


# 从一条 Zeek 连接记录计算十个非负统计特征，明确处理零分母和缺失时长。
def features_from_conn(conn):
    values = {}
    for name in ('orig_pkts', 'resp_pkts', 'orig_ip_bytes', 'resp_ip_bytes'):
        value = float(conn[name])
        if not math.isfinite(value) or value < 0:
            raise ValueError('invalid Zeek counters')
        values[name] = value
    op, rp = values['orig_pkts'], values['resp_pkts']
    ob, rb = values['orig_ip_bytes'], values['resp_ip_bytes']
    duration = conn.get('duration', 0 if op + rp <= 1 else None)
    duration = float(duration) if duration is not None else float('nan')
    if math.isinf(duration) or duration < 0 or op + rp <= 0:
        raise ValueError('invalid Zeek duration/packet count')
    values.update(duration=duration, total_pkts=op + rp, total_ip_bytes=ob + rb,
        orig_mean_ip_len=ob / op if op else 0, resp_mean_ip_len=rb / rp if rp else 0,
        orig_byte_fraction=ob / (ob + rb) if ob + rb else 0)
    return values


# 保守地匹配 Zeek 与真实标签：时间／五元组唯一且包数和字节数相符才可评分。
# 无法匹配的标签仍保留，避免通过丢弃困难样本抬高覆盖率或降低检出率。
def match_records(labels, conns, source_hashes, split, role):
    indexed = defaultdict(list)
    for i, row in enumerate(labels):
        indexed[label_key(row)].append(i)
    matches = defaultdict(list)
    extra, ambiguous = 0, 0
    for conn in conns:
        proto = {'tcp': 6, 'udp': 17}.get(conn.get('proto'))
        if proto is None:
            extra += 1
            continue
        try:
            ckey = key(proto, conn['id.orig_h'], conn['id.orig_p'], conn['id.resp_h'], conn['id.resp_p'])
            start = int(Decimal(str(conn['ts'])) * 1_000_000_000)
            duration = Decimal(str(conn.get('duration', 0)))
            if not duration.is_finite() or duration < 0:
                raise ValueError('invalid connection interval')
            end = start + int(duration * 1_000_000_000)
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError('malformed Zeek connection identity/time') from exc
        candidates = [i for i in indexed.get(ckey, [])
                      if int(labels[i]['start_ns']) <= end + 2000 and int(labels[i]['end_ns']) >= start - 2000]
        if len(candidates) == 1:
            matches[candidates[0]].append(conn)
        elif candidates:
            # Retain ambiguity on each affected label instead of scoring an arbitrary interval.
            ambiguous += 1
            for i in candidates:
                matches[i].append(None)
        else:
            extra += 1
    rows = []
    for i, label in enumerate(labels):
        source_sha = source_hashes[label['source']]
        row = dict(sample_id=f"{source_sha}:{label['source_flow_id']}", connection_id=label['connection_id'],
            source_sha256=source_sha, group=label['group'], split=split, role=role,
            label=int(label['label']), packets=int(label['packets']), ip_bytes=int(label['ip_bytes']),
            status='no_zeek_record', zeek_uid='')
        row.update({f: '' for f in FEATURES})
        found = matches[i]
        if len(found) != 1 or found[0] is None:
            if found:
                row['status'] = 'ambiguous_or_split'
        else:
            conn = found[0]
            row['zeek_uid'] = conn.get('uid', '')
            try:
                values = features_from_conn(conn)
                # 即使区间唯一，计数不符也说明映射／解析不完整，不能直接给出可评分特征。
                if values['total_pkts'] != row['packets']:
                    row['status'] = 'packet_count_mismatch'
                elif values['total_ip_bytes'] != row['ip_bytes']:
                    row['status'] = 'ip_byte_count_mismatch'
                else:
                    row.update({k: '' if math.isnan(v) else v for k, v in values.items()})
                    row['status'] = 'ok'
            except (ValueError, KeyError, TypeError):
                row['status'] = 'invalid_features'
        rows.append(row)
    return rows, dict(unmatched_zeek_records=extra, ambiguous_zeek_records=ambiguous,
                      label_status_counts=dict(Counter(r['status'] for r in rows)))


# 为一个 PCAP 启动独立 Zeek 进程，保留日志并将连接记录映射回真实标签。
def extract_one(binary, pcap, labels, hashes, out, split, role, checksums):
    out.mkdir(parents=True, exist_ok=False)
    script = out / 'features.zeek'
    script.write_text(SCRIPT)
    command = [binary] + (['-C'] if checksums == 'none' else []) + ['-r', str(pcap), str(script)]
    with open(out / 'console.log', 'w') as log:
        result = subprocess.run(command, cwd=out, stdout=log, stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise ValueError(f'Zeek exited {result.returncode}; see {out / "console.log"}')
    conns = []
    conn_log = out / 'conn.log'
    if conn_log.exists():
        with open(conn_log) as f:
            for line in f:
                if line.strip():
                    conns.append(json.loads(line, parse_float=Decimal))
    rows, quality = match_records(labels, conns, hashes, split, role)
    write_json(out / 'extraction.json', dict(command=command, pcap_sha256=digest(pcap),
               conn_log_sha256=digest(conn_log) if conn_log.exists() else None, **quality))
    return rows


# 保存固定列顺序的特征表和提取配置指纹，后续训练前再次核验表哈希。
def save_table(out, rows, info, inputs):
    if not rows:
        raise ValueError('no eligible labeled connections')
    write_csv(out / 'dataset.csv', rows, META + FEATURES)
    write_json(out / 'dataset.json', dict(schema_version=1, features=FEATURES,
        dataset_sha256=digest(out / 'dataset.csv'), profile=info, inputs=inputs,
        status_counts=dict(Counter(r['status'] for r in rows))))


# 开发数据从原始清单提取，测试数据从混合目录及独立标签提取。
# 验证组按采集组声明 tuning／calibration，禁止自动按连接随机分配用途。
def extract(args):
    binary, info = profile(args.zeek, args.checksums)
    out = Path(args.output).resolve()
    if args.manifest:
        captures = [r for r in load_manifest(args.manifest) if r['split'] != 'test']
        if not captures:
            raise ValueError('manifest has no development captures')
        # A validation group must have one declared use, never tuning and calibration.
        roles = {}
        for capture in captures:
            role = capture.get('role', 'calibration') if capture['split'] == 'validation' else 'train'
            if role not in ('train', 'tuning', 'calibration') or (capture['split'] == 'validation' and role == 'train'):
                raise ValueError('validation role must be tuning or calibration')
            group = (capture['class'], capture['group'])
            if group in roles and roles[group] != role:
                raise ValueError('same development group has multiple roles')
            roles[group] = role
        out.mkdir(parents=True, exist_ok=False)
        rows, inputs = [], []
        for index, capture in enumerate(captures):
            quality, flows = scan(capture['path'], args.timeout)
            labels = []
            for flow in flows:
                proto, a, b = flow['key']
                labels.append(dict(connection_id=f'raw{index}-c{flow["id"]}', protocol=proto,
                    endpoint_a=a[0], port_a=a[1], endpoint_b=b[0], port_b=b[1],
                    start_ns=flow['start_ns'], end_ns=flow['end_ns'], packets=flow['packets'], ip_bytes=flow['ip_bytes'],
                    label=int(capture['class'] == 'grn'), source=capture['path'], source_flow_id=flow['id'], group=capture['group']))
            role = roles[(capture['class'], capture['group'])]
            rows += extract_one(binary, Path(capture['path']), labels, {capture['path']: quality['sha256']},
                                out / f'capture_{index:04d}', capture['split'], role, args.checksums)
            inputs.append(dict(**quality, split=capture['split'], role=role, group=capture['group'], source_class=capture['class']))
        info['timeout_seconds'] = args.timeout
        write_json(out / 'capture-manifest.json', json.loads(Path(args.manifest).read_text()))
        save_table(out, rows, info, inputs)
    else:
        source = Path(args.input).resolve()
        conditions = [source] if (source / 'mixed.pcap').exists() else sorted(source.glob('ratio_*'))
        if not conditions:
            raise ValueError('no prepared conditions found')
        out.mkdir(parents=True, exist_ok=False)
        for condition in conditions:
            manifest = json.loads((condition / 'manifest.json').read_text())
            if manifest['split'] != 'test':
                raise ValueError('mixed extraction expects test split')
            for name, field in [('mixed.pcap', 'pcap_sha256'), ('labels.csv', 'labels_sha256')]:
                if digest(condition / name) != manifest[field]:
                    raise ValueError(f'input hash mismatch: {condition / name}')
            inventory = json.loads((condition.parent / 'inventory.json').read_text())
            hashes = {r['path']: r['sha256'] for r in inventory}
            with open(condition / 'labels.csv', newline='') as f:
                labels = list(csv.DictReader(f))
            target = out / condition.name
            target.mkdir()
            rows = extract_one(binary, condition / 'mixed.pcap', labels, hashes, target / 'zeek', 'test', 'test', args.checksums)
            condition_info = dict(info, timeout_seconds=manifest['timeout_seconds'])
            save_table(target, rows, condition_info, dict(condition=str(condition), **manifest))
