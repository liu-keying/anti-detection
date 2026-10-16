"""Real-engine synthetic integration check. Never sends packets or uses ET Open."""
import argparse
import json
import struct
from pathlib import Path
from anti_detection.prepare import packets, run_mix, write_json
from anti_detection.suricata import selftest, run


# 使用真实 Suricata 验证合成正／负样本、三种条件和连接级统计，不评价真实 GRN。
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', default='suricata')
    parser.add_argument('--config', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    selftest(argparse.Namespace(engine=args.engine, config=args.config, output=str(out / 'positive-check')))
    grn = out / 'positive-check/positive.pcap'
    # Make a distinct negative UDP tuple and break the synthetic content marker.
    ts, original, wirelen, linktype, _ = next(packets(grn))
    packet = bytearray(original)
    packet[34:36] = struct.pack('!H', 34567)
    packet[-1] = ord('X')
    background = out / 'background.pcap'
    with open(background, 'wb') as f:
        f.write(b'\x4d\x3c\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, linktype))
        sec, fraction = divmod(ts, 1_000_000_000)
        f.write(struct.pack('<IIII', sec, fraction, len(packet), wirelen) + packet)
    manifest = out / 'captures.json'
    write_json(manifest, {'captures': [
        dict(path=str(grn), **{'class': 'grn'}, group='synthetic-positive', split='test', target_only=True),
        dict(path=str(background), **{'class': 'mawi'}, group='synthetic-negative', split='test')]})
    run_mix(argparse.Namespace(manifest=str(manifest), split='test', output=str(out / 'mixed'),
                              ratios='0,0.5,1', seed=2026, timeout=120, tolerance=0))
    run(argparse.Namespace(engine=args.engine, snapshot=str(out / 'positive-check/snapshot'),
                           input=str(out / 'mixed'), output=str(out / 'results'), checksums='all'))
    results = json.loads((out / 'results/summary.json').read_text())
    for result in results:
        assert result['unresolved_alerts'] == 0, result
        assert result['decoder_packets'] == result['expected_packets'], result
        assert result['background_alerted_connections'] == 0, result
        assert result['grn_alerted_connections'] == result['grn_connections'], result
        assert result['processing_status'] == 'counts_match_review_stats', result
    write_json(out / 'integration-check.json', dict(status='passed', conditions=3,
        scope='synthetic UDP positive and negative; not ET Open or real GRN evaluation'))
    print(f'Passed real-engine integration check: {out}')


if __name__ == '__main__':
    main()
