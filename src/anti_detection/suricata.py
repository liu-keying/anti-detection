"""Frozen generic-rule offline Suricata experiments (no packet transmission)."""

# 固定通用规则的离线实验；告警连接率、处理覆盖和身份识别能力分别解释。
import argparse
import csv
import datetime as dt
import ipaddress
import json
import platform
import re
import shutil
import struct
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from .prepare import digest, packets, decode, write_json


# 拒绝重复配置键，防止实验 YAML 中的后一个配置段悄悄覆盖前一个。
class UniqueLoader(yaml.SafeLoader):
    pass


# 逐项构造 YAML 映射；检测到重名键时直接报错，避免配置歧义。
def unique_mapping(loader, node):
    result = {}
    for key, value in node.value:
        key = loader.construct_object(key)
        if key in result:
            raise ValueError(f'duplicate YAML key: {key}')
        result[key] = loader.construct_object(value)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


# 使用参数数组执行外部命令并保存完整控制台日志，不通过 shell 拼接命令。
def invoke(command, log, cwd=None):
    with open(log, 'w') as f:
        result = subprocess.run(command, stdout=f, stderr=subprocess.STDOUT, cwd=cwd, check=False)
    if result.returncode:
        raise ValueError(f'command exited {result.returncode}; see {log}')


# 定位实际引擎可执行文件，用于启动及记录二进制哈希。
def engine(path):
    found = shutil.which(path)
    if not found:
        raise ValueError(f'Suricata executable not found: {path}')
    return str(Path(found).resolve())


# 复制规则与配置依赖，固定 EVE 输出和运行模式，执行配置检查后记录指纹。
# 不能完整快照的外部规则依赖直接拒绝，避免实验暗中读取变化的环境文件。
def freeze(args):
    binary = engine(args.engine)
    config = Path(args.config).resolve()
    settings = yaml.load(config.read_text(), Loader=UniqueLoader)
    if not isinstance(settings, dict) or 'include' in settings:
        raise ValueError('requires a single standalone YAML configuration without include')
    rules = Path(args.rules).resolve()
    lines = rules.read_text().splitlines()
    active = [s.strip() for s in lines if s.strip() and not s.lstrip().startswith('#')]
    if not active or any(not re.match(r'^(alert|drop|reject|pass|rejectsrc|rejectdst|rejectboth)\s', s) for s in active):
        raise ValueError('requires nonempty merged rules with one complete rule per line')
    if any(re.search(r'\b(dataset|luajit|lua|iprep)\s*:', s) for s in active):
        raise ValueError('external dataset/Lua/IP reputation rules require a separate dependency snapshot')
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(config, out / 'original.yaml')
    shutil.copyfile(rules, out / 'frozen.rules')
    for key in ('classification-file', 'reference-config-file', 'threshold-file'):
        value = settings.get(key)
        if value:
            source = Path(value)
            if not source.is_absolute():
                source = config.parent / source
            name = key + '.config'
            shutil.copyfile(source, out / name)
            settings[key] = str(out / name)
    if not settings.get('threshold-file'):
        # Avoid Suricata's implicit /etc/suricata/threshold.config dependency.
        (out / 'threshold-file.config').write_text('# No external threshold overrides configured.\n')
        settings['threshold-file'] = str(out / 'threshold-file.config')
    if settings.get('reputation-categories-file') or settings.get('default-reputation-path'):
        raise ValueError('IP reputation configuration requires a separate dependency snapshot')
    settings['default-rule-path'] = str(out)
    settings['rule-files'] = ['frozen.rules']
    settings['runmode'] = 'single'
    settings['unix-command'] = {'enabled': False}
    settings['stats'] = {'enabled': True, 'interval': 8}
    # 统一输出为单个 EVE 文件，便于同次运行关联 alert、flow 和累计 stats。
    settings['outputs'] = [{'eve-log': {'enabled': True, 'filetype': 'regular',
        'filename': 'eve.json', 'threaded': False, 'types': ['alert', 'flow', {'stats': {'totals': True, 'threads': False}}]}}]
    (out / 'experiment.yaml').write_text('%YAML 1.1\n---\n' + yaml.safe_dump(settings, sort_keys=False))
    invoke([binary, '--build-info'], out / 'build-info.txt')
    check = out / 'check'
    check.mkdir()
    invoke([binary, '-T', '-c', str(out / 'experiment.yaml'), '-S', str(out / 'frozen.rules'),
            '-l', str(check)], out / 'config-check.log', cwd=out)
    files = {p.name: digest(p) for p in out.iterdir() if p.is_file()}
    write_json(out / 'snapshot.json', dict(schema_version=1, created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        engine=binary, engine_sha256=digest(binary), rules_source=args.source,
        declared_rule_lines=len(active), files=files, platform=platform.platform(),
        note='declared_rule_lines is not the engine loaded count; inspect config-check.log and check/suricata.log'))


# 运行前校验规则、配置及引擎指纹，避免不同条件使用了不同检测能力。
def verify_snapshot(folder, binary):
    folder = Path(folder).resolve()
    snapshot = json.loads((folder / 'snapshot.json').read_text())
    for name, sha in snapshot['files'].items():
        if digest(folder / name) != sha:
            raise ValueError(f'frozen artifact changed: {name}')
    if digest(binary) != snapshot['engine_sha256']:
        raise ValueError('Suricata executable differs from frozen executable')
    return folder


# 逐混合条件启动独立进程，不继承流状态；保存命令、状态及处理结果。
def run(args):
    binary = engine(args.engine)
    frozen = verify_snapshot(args.snapshot, binary)
    source = Path(args.input).resolve()
    conditions = [source] if (source / 'mixed.pcap').is_file() else sorted(source.glob('ratio_*'))
    if not conditions:
        raise ValueError('input requires ratio folders produced by prepare-data mix')
    for folder in conditions:
        manifest = json.loads((folder / 'manifest.json').read_text())
        for name, key in [('mixed.pcap', 'pcap_sha256'), ('labels.csv', 'labels_sha256')]:
            if digest(folder / name) != manifest[key]:
                raise ValueError(f'input hash mismatch: {folder / name}')
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    summaries = []
    for folder in conditions:
        target = out / folder.name
        target.mkdir()
        command = [binary, '-c', str(frozen / 'experiment.yaml'), '-S', str(frozen / 'frozen.rules'),
                   '-r', str(folder / 'mixed.pcap'), '-l', str(target), '--runmode', 'single', '-k', args.checksums]
        metadata = dict(command=command, snapshot=str(frozen), snapshot_sha256=digest(frozen / 'snapshot.json'),
                        checksums=args.checksums, input=str(folder), status='running')
        write_json(target / 'run.json', metadata)
        start = time.monotonic()
        try:
            invoke(command, target / 'console.log', cwd=frozen)
            metadata.update(status='engine_completed', elapsed_seconds=time.monotonic() - start)
            write_json(target / 'run.json', metadata)
            result = analyze(folder, target / 'eve.json', target / 'analysis')
            summaries.append(dict(condition=folder.name, **result))
            metadata['status'] = 'analyzed'
            write_json(target / 'run.json', metadata)
        except Exception:
            metadata['status'] = 'failed'
            write_json(target / 'run.json', metadata)
            raise
    write_json(out / 'summary.json', summaries)
    flat = [{k: row[k] for k in ('condition', 'actual_byte_ratio', 'grn_connections', 'grn_alerted_connections',
            'grn_alert_connection_rate', 'background_connections', 'background_alerted_connections',
            'background_alert_connection_rate', 'unresolved_alerts', 'processing_status')} for row in summaries]
    write_csv(out / 'summary.csv', flat)


# 统一保存表头和逐行结果；空表由调用者显式指定列名。
def write_csv(path, rows, fields=None):
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields or list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


# 将带时区的 EVE 时间解析为整数纳秒，不用浮点时间戳损失原始小数精度。
def ns(value):
    # datetime handles timezone, fractional seconds are parsed separately to retain nanoseconds.
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:?\d\d)', value)
    if not match:
        raise ValueError(f'invalid EVE timestamp: {value}')
    stamp = dt.datetime.fromisoformat(match[1] + match[3].replace('Z', '+00:00'))
    delta = stamp - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int((match[2] or '').ljust(9, '0'))


# 将端点标准化并排序，使反向报文与正向报文使用同一个连接键。
def key(proto, a, ap, b, bp):
    return (int(proto), *sorted(((str(ipaddress.ip_address(a)), int(ap)), (str(ipaddress.ip_address(b)), int(bp)))))


# 从 TCP/UDP EVE 事件取得双向键，字段不足时返回空值而非猜测归属。
def event_key(event):
    proto = {'TCP': 6, 'UDP': 17}.get(event.get('proto'))
    if proto is None:
        return None
    try:
        return key(proto, event['src_ip'], event['src_port'], event['dest_ip'], event['dest_port'])
    except (KeyError, ValueError):
        return None


# 将通用告警保守归因到标签连接，去重后计算两类告警连接率。
# 未知归属独立保留；普通告警不自动解释为 GRN 身份识别。
def analyze(condition, eve, output):
    condition, output = Path(condition), Path(output)
    manifest = json.loads((condition / 'manifest.json').read_text())
    for name, field in [('mixed.pcap', 'pcap_sha256'), ('labels.csv', 'labels_sha256')]:
        if digest(condition / name) != manifest[field]:
            raise ValueError(f'input hash mismatch: {name}')
    with open(condition / 'labels.csv', newline='') as f:
        labels = list(csv.DictReader(f))
    if not labels or len({r['connection_id'] for r in labels}) != len(labels):
        raise ValueError('empty or duplicate connection labels')
    indexed = defaultdict(list)
    for row in labels:
        for field in ('label', 'protocol', 'port_a', 'port_b', 'start_ns', 'end_ns', 'packets', 'ip_bytes'):
            row[field] = int(row[field])
        if row['label'] not in (0, 1):
            raise ValueError('invalid binary label')
        indexed[key(row['protocol'], row['endpoint_a'], row['port_a'], row['endpoint_b'], row['port_b'])].append(row)
    # Map the actual packet ordinal; timestamp tolerance covers EVE microsecond rounding only.
    packet_labels = {}
    for ordinal, (stamp, data, _, lt, _) in enumerate(packets(condition / 'mixed.pcap'), 1):
        decoded, reason = decode(data, lt)
        if reason:
            continue
        candidates = [r for r in indexed[decoded[0]] if r['start_ns'] <= stamp <= r['end_ns']]
        if len(candidates) == 1:
            packet_labels[ordinal] = candidates[0]['connection_id']
    flows, events, stats = {}, [], []
    with open(eve) as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f'invalid EVE JSON at line {line_no}') from exc
            typ = event.get('event_type')
            if typ == 'flow':
                flows.setdefault(event.get('flow_id'), []).append(event)
            elif typ == 'alert':
                events.append(event)
            elif typ == 'stats':
                stats.append(event)
    if not stats:
        raise ValueError('EVE has no stats events; cannot verify processing')
    alerted, sid_connections = set(), defaultdict(set)
    signatures, resolved_rows, unresolved = Counter(), [], []
    for event in events:
        signature = event['alert']
        sid = f"{signature.get('gid', 1)}:{signature['signature_id']}:{signature.get('rev', 0)}"
        signatures[sid] += 1
        ekey = event_key(event)
        candidates = indexed.get(ekey, [])
        chosen, method = None, None
        # 包编号对应实际原始报文时优先使用；编号无效不会回退猜测到另一个连接。
        if event.get('pcap_cnt') is not None:
            candidate = packet_labels.get(event['pcap_cnt'])
            if any(r['connection_id'] == candidate for r in candidates):
                chosen, method = candidate, 'packet_ordinal'
        else:
            # A flow interval is safer than a pseudo packet's emission timestamp.
            intervals = [f['flow'] for f in flows.get(event.get('flow_id'), []) if event_key(f) == ekey]
            if intervals:
                matches = {r['connection_id'] for r in candidates for interval in intervals
                           if r['start_ns'] <= ns(interval['end']) + 999 and r['end_ns'] >= ns(interval['start']) - 999}
                if len(matches) == 1:
                    chosen, method = matches.pop(), 'unique_flow_interval'
            else:
                stamp = ns(event['timestamp'])
                matches = [r for r in candidates if r['start_ns'] - 999 <= stamp <= r['end_ns'] + 999]
                if len(matches) == 1:
                    chosen, method = matches[0]['connection_id'], 'tuple_time'
        record = dict(timestamp=event['timestamp'], flow_id=event.get('flow_id'),
            pcap_cnt=event.get('pcap_cnt'), rule=sid, signature=signature.get('signature', ''),
            category=signature.get('category', ''), severity=signature.get('severity'),
            connection_id=chosen, attribution=method or 'unresolved')
        resolved_rows.append(record)
        # 每个标签连接只计一次命中，规则／原始告警条数则另行累计。
        if chosen:
            alerted.add(chosen)
            sid_connections[sid].add(chosen)
        else:
            unresolved.append(record)
    for row in labels:
        row['generic_alerted'] = int(row['connection_id'] in alerted)
    result = dict(actual_byte_ratio=manifest['actual_byte_ratio'], raw_alerts=len(events),
        unresolved_alerts=len(unresolved), grn_identity_detection_rate=None,
        grn_identity_detection_applicability='not evaluated: generic alerts are not GRN identity labels',
        stats_events=len(stats), flow_events=sum(map(len, flows.values())),
        eve_sha256=digest(eve), pcap_sha256=manifest['pcap_sha256'], labels_sha256=manifest['labels_sha256'])
    for label, prefix in ((1, 'grn'), (0, 'background')):
        subset = [r for r in labels if r['label'] == label]
        hits = sum(r['generic_alerted'] for r in subset)
        result[prefix + '_connections'] = len(subset)
        result[prefix + '_alerted_connections'] = hits
        result[prefix + '_alert_connection_rate'] = hits / len(subset) if subset else None
    final_stats = stats[-1]['stats']
    decoded_count = final_stats.get('decoder', {}).get('pkts')
    expected = sum(r['packets'] for r in labels)
    result.update(expected_packets=expected, decoder_packets=decoded_count,
        processing_status='review_required' if unresolved or decoded_count != expected or not flows else 'counts_match_review_stats',
        rate_interpretation='resolved alerts only; lower bounds if any alert is unresolved',
        confidence_interval=None,
        confidence_interval_note='Use independent capture groups across rounds; no independent-flow binomial interval is assumed.')
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / 'metrics.json', result)
    write_json(output / 'stats.json', stats)
    write_csv(output / 'connections.csv', labels)
    group_rows = []
    for label, group in sorted({(r['label'], r['group']) for r in labels}):
        subset = [r for r in labels if r['label'] == label and r['group'] == group]
        hits = sum(r['generic_alerted'] for r in subset)
        group_rows.append(dict(label=label, group=group, connections=len(subset),
                               alerted_connections=hits, alert_connection_rate=hits / len(subset)))
    write_csv(output / 'groups.csv', group_rows)
    fields = ['timestamp', 'flow_id', 'pcap_cnt', 'rule', 'signature', 'category', 'severity', 'connection_id', 'attribution']
    write_csv(output / 'alerts.csv', resolved_rows, fields)
    write_csv(output / 'unresolved-alerts.csv', unresolved, fields)
    write_csv(output / 'rules.csv', [dict(rule=sid, alerts=count,
        resolved_connections=len(sid_connections[sid]),
        grn_connections=sum(r['label'] == 1 and r['connection_id'] in sid_connections[sid] for r in labels),
        background_connections=sum(r['label'] == 0 and r['connection_id'] in sid_connections[sid] for r in labels))
        for sid, count in sorted(signatures.items())],
        ['rule', 'alerts', 'resolved_connections', 'grn_connections', 'background_connections'])
    return result


# 生成合法 UDP 阳性包和专用流程规则，检查实际引擎能否输出预期 SID。
# 该规则仅检验管线，不混入正式 ET Open 规则，也不验证所有协议能力。
def selftest(args):
    binary = engine(args.engine)
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    payload = b'OFFLINE_PIPELINE_CHECK'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28 + len(payload), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([198, 51, 100, 1]))
    words = struct.unpack('!10H', ip)
    value = sum(words)
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    ip = ip[:10] + struct.pack('!H', (~value) & 65535) + ip[12:]
    data = bytes.fromhex('0200000000020200000000010800') + ip + struct.pack('!HHHH', 12345, 23456, 8 + len(payload), 0) + payload
    pcap = out / 'positive.pcap'
    with open(pcap, 'wb') as f:
        f.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack('<IIII', 1700000000, 0, len(data), len(data)) + data)
    rules = out / 'pipeline-only.rules'
    rules.write_text('alert udp any any -> any any (msg:"LAB offline pipeline check"; content:"OFFLINE_PIPELINE_CHECK"; sid:9900001; rev:1;)\n')
    freeze(argparse.Namespace(engine=binary, config=args.config, rules=str(rules),
        output=str(out / 'snapshot'), source='synthetic pipeline check only; never merge into ET Open'))
    logs = out / 'logs'
    logs.mkdir()
    invoke([binary, '-c', str(out / 'snapshot/experiment.yaml'), '-S', str(out / 'snapshot/frozen.rules'),
            '-r', str(pcap), '-l', str(logs), '--runmode', 'single', '-k', 'all'], out / 'console.log')
    with open(logs / 'eve.json') as f:
        hits = sum(e.get('event_type') == 'alert' and e.get('alert', {}).get('signature_id') == 9900001
                   for e in map(json.loads, filter(str.strip, f)))
    if not hits:
        raise ValueError('pipeline positive check did not produce expected SID 9900001')
    write_json(out / 'selftest.json', dict(status='passed', sid=9900001, alerts=hits,
        scope='synthetic UDP rule path only; does not validate ET Open or all protocol parsers'))


# 用独立已知样本检验冻结规则的指定 SID，并保存命中证据和输入指纹。
def check_positive(args):
    binary = engine(args.engine)
    frozen = verify_snapshot(args.snapshot, binary)
    pcap = Path(args.pcap).resolve()
    checksum = digest(pcap)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    command = [binary, '-c', str(frozen / 'experiment.yaml'), '-S', str(frozen / 'frozen.rules'),
               '-r', str(pcap), '-l', str(output), '--runmode', 'single', '-k', args.checksums]
    receipt = dict(status='running', command=command, expected_sids=args.sid,
                   pcap_sha256=checksum, snapshot_sha256=digest(frozen / 'snapshot.json'))
    write_json(output / 'positive-check.json', receipt)
    try:
        invoke(command, output / 'console.log', cwd=frozen)
        observed = Counter()
        with open(output / 'eve.json') as f:
            for line in f:
                if line.strip():
                    event = json.loads(line)
                    if event.get('event_type') == 'alert':
                        observed[event['alert']['signature_id']] += 1
        missing = sorted(set(args.sid) - observed.keys())
        receipt.update(status='failed' if missing else 'passed', observed_sids=dict(observed), missing_sids=missing,
                       eve_sha256=digest(output / 'eve.json'))
        write_json(output / 'positive-check.json', receipt)
        if missing:
            raise ValueError(f'expected positive SIDs did not fire: {missing}; see {output}')
    except Exception:
        receipt['status'] = 'failed'
        write_json(output / 'positive-check.json', receipt)
        raise


# Suricata 实验命令入口，分别提供冻结、流程校验、规则能力校验、检测与分析。
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', default='suricata')
    sub = parser.add_subparsers(dest='command', required=True)
    freeze_parser = sub.add_parser('freeze')
    freeze_parser.add_argument('--config', required=True)
    freeze_parser.add_argument('--rules', required=True)
    freeze_parser.add_argument('--source', required=True, help='rule provenance including source/download date')
    freeze_parser.add_argument('--output', required=True)
    test = sub.add_parser('selftest')
    test.add_argument('--config', required=True)
    test.add_argument('--output', required=True)
    positive = sub.add_parser('check-positive')
    positive.add_argument('--snapshot', required=True)
    positive.add_argument('--pcap', required=True)
    positive.add_argument('--sid', type=int, action='append', required=True)
    positive.add_argument('--checksums', choices=['all', 'none'], default='all')
    positive.add_argument('--output', required=True)
    runner = sub.add_parser('run')
    runner.add_argument('--snapshot', required=True)
    runner.add_argument('--input', required=True)
    runner.add_argument('--output', required=True)
    runner.add_argument('--checksums', choices=['all', 'none'], default='all')
    report = sub.add_parser('analyze')
    report.add_argument('--condition', required=True)
    report.add_argument('--eve', required=True)
    report.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'analyze':
            analyze(args.condition, args.eve, args.output)
        else:
            {'freeze': freeze, 'run': run, 'selftest': selftest, 'check-positive': check_positive}[args.command](args)
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        parser.exit(2, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
