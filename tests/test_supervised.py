# 合成夹具只验证程序行为，不用于支持真实流量的反探测结论。
import csv
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from anti_detection.features import FEATURES, META, match_records, save_table
from anti_detection.prepare import write_json
from anti_detection.supervised import (array, calibrate, disjoint, evaluate, evaluate_rows,
    identities, load_models, threshold_at_fpr, train)


# 测试集：验证本模块的关键实验约束和边界行为，不依赖真实 GRN 数据。
class FeatureTests(unittest.TestCase):
    # 构造有五元组、时间范围和计数的真实连接标签夹具。
    def label(self, **changes):
        row = dict(connection_id='c1', protocol=17, endpoint_a='10.0.0.1', port_a=1000,
                   endpoint_b='10.0.0.2', port_b=2000, start_ns=1_000_000_000, end_ns=2_000_000_000,
                   packets=2, ip_bytes=56, source='a', source_flow_id=0, label=1, group='run')
        return dict(row, **changes) if not changes else {**row, **changes}

    # 构造与标签对应的 Zeek JSON 连接，检查方向统计和标签映射。
    def conn(self):
        return {'ts': 1, 'duration': 1, 'uid': 'C1', 'proto': 'udp', 'id.orig_h': '10.0.0.1',
                'id.orig_p': 1000, 'id.resp_h': '10.0.0.2', 'id.resp_p': 2000,
                'orig_pkts': 1, 'resp_pkts': 1, 'orig_ip_bytes': 28, 'resp_ip_bytes': 28}

    # 检查唯一匹配的特征计算，并确认未匹配标签仍保留为空特征行。
    def test_exact_mapping_features_and_unmatched(self):
        rows, _ = match_records([self.label(), self.label(connection_id='c2', port_a=3000, source_flow_id=1)],
                                [self.conn()], {'a': 'sha'}, 'test', 'test')
        self.assertEqual(rows[0]['status'], 'ok')
        self.assertEqual(rows[0]['orig_byte_fraction'], .5)
        self.assertEqual(rows[0]['total_ip_bytes'], 56)
        self.assertEqual(rows[1]['status'], 'no_zeek_record')
        self.assertEqual(rows[1]['duration'], '')

    # 确认歧义映射和计数不符的连接不会获得可评分状态。
    def test_ambiguity_and_counter_mismatch_are_not_scored(self):
        rows, report = match_records([self.label(), self.label(connection_id='c2', source_flow_id=1)],
                                    [self.conn()], {'a': 'sha'}, 'test', 'test')
        self.assertTrue(all(r['status'] == 'ambiguous_or_split' for r in rows))
        self.assertEqual(report['ambiguous_zeek_records'], 1)
        bad = self.conn()
        bad['orig_pkts'] = 10
        rows, _ = match_records([self.label()], [bad], {'a': 'sha'}, 'test', 'test')
        self.assertEqual(rows[0]['status'], 'packet_count_mismatch')


# 测试集：验证本模块的关键实验约束和边界行为，不依赖真实 GRN 数据。
class SupervisedTests(unittest.TestCase):
    # 检查严格大于阈值的同分处理，并暴露低误报预算下的样本分辨率限制。
    def test_threshold_ties_and_zero_budget_resolution(self):
        result = threshold_at_fpr([.1, .2, .2, .9], .25)
        self.assertEqual(result['threshold'], .2)
        self.assertEqual(result['observed_false_positives'], 1)
        result = threshold_at_fpr([.1, .2, .2, .9], .001)
        self.assertEqual(result['threshold'], .9)
        self.assertEqual(result['observed_false_positives'], 0)
        self.assertTrue(result['low_tail_sample_support'])

    # 确认不可评分目标计入漏检、背景仍在分母中，并单独报告覆盖率。
    def test_end_to_end_denominator_keeps_unscoreable(self):
        rows = [dict(label=1, status='ok', group='a'), dict(label=1, status='no_zeek_record', group='b'),
                dict(label=0, status='no_zeek_record', group='c')]
        _, result = evaluate_rows(rows, [.9], .5, 0)
        self.assertEqual((result['tp'], result['fn'], result['tn']), (1, 1, 1))
        self.assertEqual(result['tpr'], .5)
        self.assertEqual(result['grn_coverage'], .5)
        self.assertIsNone(result['scoreable_fpr'])
        self.assertIsNone(result['tpr_cluster_bootstrap_95'])

    # 生成可重复且分组身份独立的特征表，用于快速验证完整模型流程。
    def make_rows(self, role, split, count=20):
        rows = []
        for label in (0, 1):
            for i in range(count):
                value = (2 if label == 0 else 50) + i % 4
                row = {name: float(value) for name in FEATURES}
                row['orig_byte_fraction'] = .5
                row.update(sample_id=f'{role}-{label}:{i}', connection_id=f'c{label}-{i}',
                    source_sha256=f'{role}-{label}', group=f'{role}-{label}-{i%2}',
                    split=split, role=role, label=label, packets=2, ip_bytes=56, status='ok', zeek_uid='test')
                rows.append(row)
        return rows

    # 实际训练三种小模型并校准测试，检查预处理只拟合训练组且拒绝开发身份复用。
    def test_all_models_train_calibrate_evaluate_and_leakage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dev, test = root / 'dev', root / 'test'
            dev.mkdir(); test.mkdir()
            rows = self.make_rows('train', 'train') + self.make_rows('tuning', 'validation') + self.make_rows('calibration', 'validation')
            for row in rows:
                if row['role'] != 'train':
                    row['duration'] = 5000 if row['role'] == 'tuning' else 100000
            profile = {'test_profile': 1}
            save_table(dev, rows, profile, [])
            save_table(test, self.make_rows('test', 'test'), profile, {'actual_byte_ratio': .01})
            grid = root / 'grid.json'
            write_json(grid, {'rf': [{'n_estimators': 5, 'max_depth': 3}],
                'xgb': [{'n_estimators': 5, 'max_depth': 2}],
                'mlp': [{'hidden_layer_sizes': [8], 'max_iter': 40}]})
            models, thresholds, output = root / 'models', root / 'thresholds', root / 'results'
            train(Namespace(data=str(dev), grid=str(grid), models='rf,xgb,mlp', seed=1, jobs=1, fpr=.1, output=str(models)))
            calibrate(Namespace(data=str(dev), models=str(models), output=str(thresholds)))
            evaluate(Namespace(models=str(models), thresholds=str(thresholds / 'thresholds.json'),
                input=str(test), output=str(output), bootstrap=10, seed=1))
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(len(summary), 3)
            self.assertTrue(all(r['tp'] + r['fn'] == 20 for r in summary))
            meta, pipelines = load_models(models)
            self.assertIn('scale', pipelines['mlp'].named_steps)
            self.assertNotIn('scale', pipelines['rf'].named_steps)
            self.assertEqual(pipelines['mlp'].n_features_in_, 10)
            import numpy as np
            expected_mean = np.log1p(array([r for r in rows if r['role'] == 'train'])).mean(axis=0)
            np.testing.assert_allclose(pipelines['mlp'].named_steps['scale'].mean_, expected_mean)
            cutoffs = json.loads((thresholds / 'thresholds.json').read_text())
            self.assertTrue(all(entry['background_samples'] == 20 for entry in cutoffs['models'].values()))
            disjoint(meta['development_identities'], identities(self.make_rows('test', 'test')))
            # A test table that reuses development identities must fail before writing output.
            leaked = root / 'leaked'; leaked.mkdir()
            save_table(leaked, [{**r, 'split': 'test', 'role': 'test'} for r in self.make_rows('train', 'train')],
                       profile, {'actual_byte_ratio': .01})
            with self.assertRaisesRegex(ValueError, 'leakage'):
                evaluate(Namespace(models=str(models), thresholds=str(thresholds / 'thresholds.json'),
                    input=str(leaked), output=str(root / 'bad-results'), bootstrap=0, seed=1))
            self.assertFalse((root / 'bad-results').exists())


if __name__ == '__main__':
    unittest.main()
