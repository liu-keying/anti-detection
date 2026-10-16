# 合成夹具只验证程序行为，不用于支持真实流量的反探测结论。
import csv
import json
import struct
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from anti_detection.prepare import scan, run_mix, packets, load_manifest


# 构造确定性 PCAP 测试夹具，可控制每组连接的包数和端点，避免依赖外部抓包。
def capture(path, address, count, flow_packets=None):
    with open(path, 'wb') as f:
        f.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        for i in range(count):
            src, dst = bytes([10, 0, 0, address]), bytes([10, 0, 1, address])
            ports = (1000 + (i // flow_packets if flow_packets else 0), 2000)
            if i % 2:
                src, dst, ports = dst, src, ports[::-1]
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, 0, 0, 64, 17, 0, src, dst)
            data = bytes(12) + b'\x08\x00' + ip + struct.pack('!HHHH', *ports, 8, 0)
            f.write(struct.pack('<IIII', 100 + i, 0, len(data), len(data)) + data)


# 测试集：验证本模块的关键实验约束和边界行为，不依赖真实 GRN 数据。
class PreparationTests(unittest.TestCase):
    # 检查混合后计数、双向归并和纯类对照，且目标不足时不生成部分输出。
    def test_roundtrip_and_ratios(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture(root / 'bg.pcap', 1, 20)
            capture(root / 'grn.pcap', 2, 2)
            doc = {'captures': [dict(path='bg.pcap', **{'class': 'mawi'}, group='d1', split='test'),
                                 dict(path='grn.pcap', **{'class': 'grn'}, group='s1', split='test', target_only=True)]}
            manifest = root / 'captures.json'
            manifest.write_text(json.dumps(doc))
            args = Namespace(manifest=str(manifest), split='test', output=str(root / 'out'),
                             ratios='0,0.09,1', seed=1, timeout=120, tolerance=0.2)
            run_mix(args)
            folder = root / 'out' / 'ratio_0.09'
            report = json.loads((folder / 'manifest.json').read_text())
            self.assertAlmostEqual(report['actual_byte_ratio'], 2 / 22)
            self.assertEqual(report['counts']['grn']['connections'], 1)
            info, flows = scan(folder / 'mixed.pcap', 120)
            self.assertEqual(info['eligible_ip_bytes'], 22 * 28)
            self.assertEqual(len(flows), 2)
            with open(folder / 'labels.csv') as f:
                labels = list(csv.DictReader(f))
            self.assertEqual(sum(int(r['packets']) for r in labels), 22)
            self.assertEqual(len(list(packets(root / 'out/ratio_1/mixed.pcap'))), 2)
            self.assertEqual(len(list(packets(root / 'out/ratio_0/mixed.pcap'))), 20)
            args.output = str(root / 'insufficient')
            args.ratios = '0.5'
            with self.assertRaisesRegex(ValueError, 'insufficient'):
                run_mix(args)
            self.assertFalse(Path(args.output).exists())

    # 确认各比例背景包及时间戳完全一致、目标子集嵌套，并可按种子复现。
    def test_fixed_background_nested_targets_and_reproducibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture(root / 'bg.pcap', 1, 20)
            capture(root / 'grn.pcap', 2, 20, flow_packets=2)
            manifest = root / 'captures.json'
            manifest.write_text(json.dumps({'captures': [
                dict(path='bg.pcap', **{'class': 'mawi'}, group='d1', split='test'),
                dict(path='grn.pcap', **{'class': 'grn'}, group='s1', split='test', target_only=True)]}))
            args = Namespace(manifest=str(manifest), split='test', output=str(root / 'out'),
                             ratios='0,0.1,0.2,0.5,1', seed=3, timeout=120, tolerance=.2)
            run_mix(args)
            previous = set()
            background_reference = None
            for ratio in ('0', '0.1', '0.2', '0.5'):
                folder = root / 'out' / ('ratio_' + ratio)
                metadata = json.loads((folder / 'manifest.json').read_text())
                self.assertEqual(metadata['mixing_strategy'], 'fixed_background_variable_grn')
                self.assertEqual(metadata['counts']['mawi']['packets'], 20)
                self.assertEqual(metadata['counts']['mawi']['ip_bytes'], 560)
                with open(folder / 'labels.csv') as f:
                    rows = list(csv.DictReader(f))
                target = {r['source_flow_id'] for r in rows if r['label'] == '1'}
                self.assertTrue(previous <= target)
                previous = target
                bg = [(ts, data, wire) for ts, data, wire, _, _ in packets(folder / 'mixed.pcap')
                      if data[26:30] in (bytes([10, 0, 0, 1]), bytes([10, 0, 1, 1]))]
                if background_reference is None:
                    background_reference = bg
                self.assertEqual(bg, background_reference)
            pure = json.loads((root / 'out/ratio_1/manifest.json').read_text())
            self.assertEqual(pure['counts']['mawi']['packets'], 0)
            self.assertEqual(pure['condition_kind'], 'pure_grn_control')
            args.output = str(root / 'repeat')
            run_mix(args)
            for ratio in ('0', '0.1', '0.2', '0.5', '1'):
                self.assertEqual((root / 'out' / ('ratio_' + ratio) / 'mixed.pcap').read_bytes(),
                                 (root / 'repeat' / ('ratio_' + ratio) / 'mixed.pcap').read_bytes())

    # 确认同一来源组跨训练／测试分区时清单校验失败。
    def test_group_leakage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture(root / 'a.pcap', 1, 2)
            capture(root / 'b.pcap', 2, 2)
            doc = {'captures': [dict(path='a.pcap', **{'class': 'mawi'}, group='same', split='train'),
                                 dict(path='b.pcap', **{'class': 'mawi'}, group='same', split='test')]}
            path = root / 'manifest.json'
            path.write_text(json.dumps(doc))
            with self.assertRaisesRegex(ValueError, 'crosses splits'):
                load_manifest(path)

    # 确认物理文件记录不完整时明确报错，不把损坏包当正常捕获截断。
    def test_truncated_record_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'broken.pcap'
            capture(path, 1, 2)
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaisesRegex(ValueError, 'incomplete packet'):
                scan(path, 120)


if __name__ == '__main__':
    unittest.main()
