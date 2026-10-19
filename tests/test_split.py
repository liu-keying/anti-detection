# 合成夹具只验证程序行为，不用于支持真实流量的反探测结论。
import csv
import json
import struct
import tempfile
import unittest
from argparse import Namespace
from collections import Counter
from pathlib import Path

from anti_detection.prepare import load_manifest, packets, scan
from anti_detection.split import PARTS, assignments, merge_manifests, split
from test_prepare import capture


# 测试集：验证本模块的关键实验约束和边界行为，不依赖真实 GRN 数据。
class SplitTests(unittest.TestCase):
    # 构造拆分参数夹具，测试仅覆盖指定字段，其他参数保持一致。
    def args(self, source, output, **changes):
        return Namespace(**{**dict(pcap=str(source), output=str(output), timeout=120,
            ratios='0.5,0.15,0.15,0.2', groups=None, source_class='mawi', target_only=False), **changes})

    # 核对各分区连接键不重叠，所有原始包完整保留，且重复拆分逐字节一致。
    def test_whole_flows_packet_conservation_and_repeatability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source.pcap'
            capture(source, 1, 40, flow_packets=2)
            # A non-IP packet is retained separately, rather than silently lost.
            frame = bytes(12) + b'\x08\x06' + bytes(28)
            with open(source, 'ab') as f:
                f.write(struct.pack('<IIII', 200, 0, len(frame), len(frame)) + frame)
            split(self.args(source, root / 'out'))
            split(self.args(source, root / 'repeat'))
            report = json.loads((root / 'out/split.json').read_text())
            self.assertTrue(report['packet_conservation'])
            self.assertEqual(report['excluded_packets'], 1)
            self.assertEqual([report['partitions'][p]['group_count'] for p in PARTS], [10, 3, 3, 4])
            original = Counter((t, data, wire) for t, data, wire, _, _ in packets(source))
            merged = Counter()
            seen = set()
            for part in (*PARTS, 'excluded'):
                path = root / 'out' / f'{part}.pcap'
                merged.update((t, data, wire) for t, data, wire, _, _ in packets(path))
                self.assertEqual(path.read_bytes(), (root / 'repeat' / f'{part}.pcap').read_bytes())
                if part != 'excluded':
                    _, flows = scan(path, 120)
                    keys = {flow['key'] for flow in flows}
                    self.assertFalse(seen & keys)
                    seen |= keys
                    self.assertTrue(all(f['packets'] == 2 for f in flows))
            self.assertEqual(original, merged)
            self.assertEqual(len(load_manifest(root / 'out/captures.json')), 4)

    # 确认同一业务组整体分配，并拒绝覆盖不完整的人工映射。
    def test_business_groups_and_missing_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source.pcap'
            capture(source, 1, 24, flow_packets=2)
            _, flows = scan(source, 120)
            mapping = root / 'groups.csv'
            with open(mapping, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['source_flow_id', 'business_group'])
                writer.writerows((flow['id'], f'session-{flow["id"] // 2}') for flow in flows)
            allocation = assignments(flows, [.5, .15, .15, .2], mapping)
            for group in {value[1] for value in allocation.values()}:
                self.assertEqual(len({part for part, name in allocation.values() if name == group}), 1)
            mapping.write_text('source_flow_id,business_group\n0,only\n')
            with self.assertRaisesRegex(ValueError, 'cover every'):
                assignments(flows, [.5, .15, .15, .2], mapping)

    # 确认单连接、非法比例及未确认 GRN 标签时在写文件前拒绝拆分。
    def test_single_connection_and_invalid_ratios_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source.pcap'
            capture(source, 1, 8)
            with self.assertRaisesRegex(ValueError, 'at least four groups'):
                split(self.args(source, root / 'out'))
            self.assertFalse((root / 'out').exists())
            with self.assertRaisesRegex(ValueError, 'ratios'):
                split(self.args(source, root / 'out', ratios='1,1,1,1'))
            with self.assertRaisesRegex(ValueError, 'target-only'):
                split(self.args(source, root / 'out', source_class='grn'))

    # 两类分区清单合并后路径仍相对总清单可用，且不覆盖已有文件。
    def test_merge_split_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mawi, grn = root / 'mawi.pcap', root / 'grn.pcap'
            capture(mawi, 1, 40, flow_packets=2)
            capture(grn, 2, 40, flow_packets=2)
            split(self.args(mawi, root / 'mawi-split'))
            split(self.args(grn, root / 'grn-split', source_class='grn', target_only=True))
            combined = root / 'configs/captures.json'
            merge_manifests(root / 'mawi-split/captures.json', root / 'grn-split/captures.json', combined)
            rows = load_manifest(combined)
            self.assertEqual(len(rows), 8)
            self.assertEqual({(row['class'], row.get('role', row['split'])) for row in rows},
                             {(source_class, part) for source_class in ('mawi', 'grn') for part in PARTS})
            raw_rows = json.loads(combined.read_text())['captures']
            self.assertTrue(all(not Path(row['path']).is_absolute() and
                                (combined.parent / row['path']).is_file() for row in raw_rows))
            with self.assertRaisesRegex(ValueError, 'output already exists'):
                merge_manifests(root / 'mawi-split/captures.json', root / 'grn-split/captures.json', combined)
            split(self.args(mawi, root / 'wrong-grn-split', source_class='grn', target_only=True))
            with self.assertRaisesRegex(ValueError, 'same original PCAP'):
                merge_manifests(root / 'mawi-split/captures.json', root / 'wrong-grn-split/captures.json',
                                root / 'configs/invalid.json')


if __name__ == '__main__':
    unittest.main()
