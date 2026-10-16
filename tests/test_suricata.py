# 合成夹具只验证程序行为，不用于支持真实流量的反探测结论。
import csv
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from anti_detection.prepare import run_mix
from anti_detection.suricata import analyze, freeze, ns, verify_snapshot
from test_prepare import capture


# 测试集：验证本模块的关键实验约束和边界行为，不依赖真实 GRN 数据。
class SuricataTests(unittest.TestCase):
    # 构造带真实标签的合成混合条件，供告警归因和完整性检查使用。
    def prepare(self, root):
        capture(root / 'bg.pcap', 1, 20)
        capture(root / 'grn.pcap', 2, 2)
        manifest = root / 'captures.json'
        manifest.write_text(json.dumps({'captures': [
            dict(path='bg.pcap', **{'class': 'mawi'}, group='d', split='test'),
            dict(path='grn.pcap', **{'class': 'grn'}, group='s', split='test', target_only=True)]}))
        run_mix(Namespace(manifest=str(manifest), split='test', output=str(root / 'mix'),
                         ratios='0,0.09', seed=1, timeout=120, tolerance=.2))
        return root / 'mix/ratio_0.09'

    # 构造 EVE 告警夹具，允许替换包编号、方向或事件字段来覆盖归因边界。
    def alert(self, **updates):
        event = dict(event_type='alert', timestamp='2023-11-14T22:13:20.000000+0000',
            flow_id=42, pcap_cnt=2, proto='UDP', src_ip='10.0.0.2', src_port=1000,
            dest_ip='10.0.1.2', dest_port=2000,
            alert=dict(signature_id=123, rev=1, signature='Generic example', severity=2))
        event.update(updates)
        return event

    # 保存带 flow 和累计 stats 的最小 EVE 日志，隔离测试告警解析与归因逻辑。
    def write_eve(self, root, alerts, count=22):
        path = root / 'eve.json'
        flow = self.alert(event_type='flow')
        flow.pop('alert')
        flow['flow'] = dict(start='2023-11-14T22:13:20.000000+0000', end='2023-11-14T22:13:21.000000+0000')
        path.write_text('\n'.join(json.dumps(e) for e in alerts + [flow,
            dict(event_type='stats', stats=dict(decoder=dict(pkts=count)))]))
        return path

    # 检查正反向包归属、重复告警去重以及无效包编号必须保留为未归因。
    def test_dedup_packet_direction_unresolved_and_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            condition = self.prepare(root)
            # Packet #2 is the GRN forward packet, #4 its reverse packet.
            events = [self.alert(), self.alert(pcap_cnt=4, src_ip='10.0.1.2', src_port=2000,
                      dest_ip='10.0.0.2', dest_port=1000), self.alert(pcap_cnt=999)]
            eve = self.write_eve(root, events)
            result = analyze(condition, eve, root / 'analysis')
            self.assertEqual(result['raw_alerts'], 3)
            self.assertEqual(result['grn_alerted_connections'], 1)
            self.assertEqual(result['background_alerted_connections'], 0)
            self.assertEqual(result['unresolved_alerts'], 1)
            self.assertEqual(result['processing_status'], 'review_required')
            self.assertIsNone(result['grn_identity_detection_rate'])

    # 确认伪包可通过唯一 flow 区间归因，纯背景条件的目标指标为空。
    def test_pseudo_packet_interval_and_empty_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            condition = self.prepare(root)
            alert = self.alert(timestamp='2023-11-14T23:00:00+0000')
            alert.pop('pcap_cnt')
            eve = self.write_eve(root, [alert])
            result = analyze(condition, eve, root / 'analysis')
            self.assertEqual(result['grn_alerted_connections'], 1)
            with open(root / 'analysis/alerts.csv') as f:
                self.assertEqual(next(csv.DictReader(f))['attribution'], 'unique_flow_interval')
            eve = self.write_eve(root, [], count=20)
            result = analyze(root / 'mix/ratio_0', eve, root / 'control')
            self.assertIsNone(result['grn_alert_connection_rate'])
            self.assertEqual(result['background_alert_connection_rate'], 0)

    # 确认缺失运行统计或输入哈希变化时停止分析，避免输出误导性低告警率。
    def test_hash_and_missing_stats_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            condition = self.prepare(root)
            eve = root / 'eve.json'
            eve.write_text('')
            with self.assertRaisesRegex(ValueError, 'no stats'):
                analyze(condition, eve, root / 'analysis')
            with open(condition / 'mixed.pcap', 'ab') as f:
                f.write(b'corruption')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                analyze(condition, eve, root / 'analysis2')

    # 确认冻结产物变化会被发现；模拟进程只验证快照机制。
    def test_snapshot_tamper_and_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config.yaml'
            config.write_text('vars:\n  address-groups:\n    HOME_NET: any\n    EXTERNAL_NET: any\n')
            rules = root / 'input.rules'
            rules.write_text('alert udp any any -> any any (sid:1;)\n')
            # 模拟外部进程输出，仅用于快照单元测试，不作为真实引擎校验依据。
            def fake_invoke(command, log, cwd=None):
                Path(log).write_text('test engine output')
            with patch('anti_detection.suricata.invoke', side_effect=fake_invoke):
                freeze(Namespace(engine='/bin/true', config=str(config), rules=str(rules),
                                 source='test', output=str(root / 'snapshot')))
            verify_snapshot(root / 'snapshot', '/bin/true')
            (root / 'snapshot/frozen.rules').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'changed'):
                verify_snapshot(root / 'snapshot', '/bin/true')

    # 检查时区换算和纳秒小数均被精确保留。
    def test_timestamp_nanoseconds(self):
        self.assertEqual(ns('2023-11-14T22:13:20.123456789+0000'), 1700000000123456789)
        self.assertEqual(ns('2023-11-15T00:13:20.123456789+02:00'), 1700000000123456789)


if __name__ == '__main__':
    unittest.main()
