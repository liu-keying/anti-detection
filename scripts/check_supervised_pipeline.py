"""Real-Zeek synthetic PCAP -> features -> three models -> calibration -> test check."""
import argparse
import json
import struct
from pathlib import Path

from anti_detection.features import extract
from anti_detection.prepare import run_mix, write_json
from anti_detection.supervised import calibrate, evaluate, load_table, train


# 生成具备正确 IPv4 校验和的双向 UDP 连接；两类包数／长度刻意不同以检查分类管线。
def capture(path, batch, label, count):
    with open(path, 'wb') as f:
        f.write(b'\x4d\x3c\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        for flow in range(count):
            src, dst = bytes([10, batch, label, 1]), bytes([10, batch, label, 2])
            sport, dport = 12000 + flow, 24000
            for packet_index in range(6 if label else 2):
                payload = bytes([65 + label]) * (64 if label else 8)
                a, b, ap, bp = (src, dst, sport, dport) if packet_index % 2 == 0 else (dst, src, dport, sport)
                ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28 + len(payload), flow, 0, 64, 17, 0, a, b)
                checksum = sum(struct.unpack('!10H', ip))
                while checksum >> 16:
                    checksum = (checksum & 65535) + (checksum >> 16)
                ip = ip[:10] + struct.pack('!H', (~checksum) & 65535) + ip[12:]
                data = bytes.fromhex('0200000000020200000000010800') + ip + struct.pack('!HHHH', ap, bp, 8 + len(payload), 0) + payload
                f.write(struct.pack('<IIII', 1700000000 + batch * 1000 + flow, packet_index * 10_000_000, len(data), len(data)) + data)


# 按独立合成组贯通真实 Zeek 提取、三模型训练、背景校准及三条件测试。
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zeek', default='zeek')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    captures = []
    for batch, role in enumerate(('train', 'tuning', 'calibration', 'test'), 1):
        split = role if role in ('train', 'test') else 'validation'
        for label, name in ((0, 'mawi'), (1, 'grn')):
            path = out / f'{role}-{name}.pcap'
            capture(path, batch, label, 92 if label == 0 else 12)
            captures.append(dict(path=str(path), **{'class': name}, group=f'synthetic-{role}-{name}',
                                 split=split, role=role, target_only=label == 1))
    manifest = out / 'captures.json'
    write_json(manifest, dict(captures=captures))
    extract(argparse.Namespace(manifest=str(manifest), input=None, zeek=args.zeek, checksums='all',
                               timeout=120, output=str(out / 'development')))
    run_mix(argparse.Namespace(manifest=str(manifest), split='test', ratios='0,0.5,1', seed=2026,
                               timeout=120, tolerance=.01, output=str(out / 'mixed')))
    extract(argparse.Namespace(manifest=None, input=str(out / 'mixed'), zeek=args.zeek, checksums='all',
                               timeout=120, output=str(out / 'test-features')))
    grid = out / 'grid.json'
    write_json(grid, {'rf': [{'n_estimators': 20, 'max_depth': 4}],
                     'xgb': [{'n_estimators': 20, 'max_depth': 3}],
                     'mlp': [{'hidden_layer_sizes': [16, 8], 'max_iter': 150}]})
    train(argparse.Namespace(data=str(out / 'development'), models='rf,xgb,mlp', grid=str(grid),
                             seed=2026, jobs=1, fpr=.1, output=str(out / 'models')))
    calibrate(argparse.Namespace(models=str(out / 'models'), data=str(out / 'development'), output=str(out / 'calibration')))
    evaluate(argparse.Namespace(models=str(out / 'models'), thresholds=str(out / 'calibration/thresholds.json'),
                                input=str(out / 'test-features'), bootstrap=0, seed=2026, output=str(out / 'results')))
    for folder in [out / 'development', *sorted((out / 'test-features').glob('ratio_*'))]:
        rows, _ = load_table(folder)
        if any(r['status'] != 'ok' for r in rows):
            raise ValueError(f'synthetic extraction did not achieve complete coverage: {folder}')
    results = json.loads((out / 'results/summary.json').read_text())
    if len(results) != 9 or any(r['review_required'] for r in results):
        raise ValueError('incomplete synthetic model results')
    for result in results:
        if result['tp'] + result['fn'] != result['grn_connections'] or result['fp'] + result['tn'] != result['background_connections']:
            raise ValueError('confusion matrix denominator mismatch')
    write_json(out / 'integration-check.json', dict(status='passed', models=3, conditions=3,
        scope='synthetic feature-separable UDP; not evidence about real GRN or sufficient statistical power'))
    print(f'Passed real-Zeek supervised integration check: {out}')


if __name__ == '__main__':
    main()
