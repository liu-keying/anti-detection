# 合成夹具只验证程序行为，不用于支持真实流量的反探测结论。
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from anti_detection.autoencoder import (anomaly_metrics, calibrate, evaluate, load_model,
    reconstruction_errors, train, transformed, validate_config)
from anti_detection.features import save_table
from anti_detection.prepare import write_json
import test_supervised as fixtures


# 测试集：验证本模块的关键实验约束和边界行为，不依赖真实 GRN 数据。
class AutoencoderTests(unittest.TestCase):
    # 构造包含三种开发用途的两类样本；可扰动 GRN 以验证 AE 不会学习目标数据。
    def data(self, root, perturb=False):
        factory = fixtures.SupervisedTests()
        rows = factory.make_rows('train', 'train') + factory.make_rows('tuning', 'validation') + factory.make_rows('calibration', 'validation')
        for row in rows:
            if perturb and row['label'] == 1:
                row['duration'] = 1e12
                row['orig_ip_bytes'] = 1e15
        folder = root / 'dev'
        folder.mkdir()
        save_table(folder, rows, {'test_profile': 1}, [])
        return folder

    # 用固定种子和小型 AE 缩短测试时间，训练／调参／校准的接口仍与正式流程相同。
    def train_model(self, root, data):
        config = root / 'config.json'
        write_json(config, {'candidates': [dict(hidden_dims=[6, 2, 6], learning_rate=.01,
            weight_decay=0, max_epochs=8, batch_size=16, patience=3, min_delta=1e-6)]})
        out = root / 'model'
        train(Namespace(data=str(data), config=str(config), seed=7, threads=1, fpr=.1, output=str(out)))
        return out

    # 确认扰动 GRN 不改变 AE 预处理、历史及权重，并验证恢复的确为最佳背景轮次。
    def test_background_only_training_preprocessing_and_best_state(self):
        import numpy as np
        import torch
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a, b = root / 'a', root / 'b'
            a.mkdir(); b.mkdir()
            first = self.train_model(a, self.data(a))
            second = self.train_model(b, self.data(b, perturb=True))
            info1, process1, model1 = load_model(first)
            info2, process2, model2 = load_model(second)
            self.assertEqual(info1['ignored_grn_rows'], 60)
            self.assertEqual(info1['coverage']['train']['scoreable'], 20)
            np.testing.assert_array_equal(process1.named_steps['scale'].mean_, process2.named_steps['scale'].mean_)
            self.assertEqual(info1['trials'], info2['trials'])
            for name, value in model1.state_dict().items():
                self.assertTrue(torch.equal(value, model2.state_dict()[name]))
            tuning = [r for r in fixtures.SupervisedTests().make_rows('tuning', 'validation') if r['label'] == 0]
            errors = reconstruction_errors(model1, transformed(process1, tuning))
            self.assertAlmostEqual(float(errors.mean()), info1['trials'][0]['best_tuning_mse'], places=7)

    # 确认背景校准、异常计数和不可评分分母正确，且开发泄漏与权重篡改会被拒绝。
    def test_train_calibrate_evaluate_and_reject_leakage_or_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self.data(root)
            model = self.train_model(root, data)
            cutoff = root / 'calibration'
            calibrate(Namespace(model=str(model), data=str(data), output=str(cutoff)))
            threshold = json.loads((cutoff / 'threshold.json').read_text())
            self.assertEqual(threshold['background_samples'], 20)
            self.assertEqual(threshold['observed_false_positives'] <= 2, True)
            test = root / 'test'; test.mkdir()
            rows = fixtures.SupervisedTests().make_rows('test', 'test')
            rows[0]['status'] = 'no_zeek_record'
            save_table(test, rows, {'test_profile': 1}, {'actual_byte_ratio': .01})
            args = Namespace(model=str(model), threshold=str(cutoff / 'threshold.json'), input=str(test),
                             bootstrap=0, seed=7, output=str(root / 'results'))
            evaluate(args)
            metrics = json.loads((root / 'results/summary.json').read_text())[0]
            self.assertEqual(metrics['grn_flagged'] + metrics['grn_unflagged'], 20)
            self.assertEqual(metrics['background_unscorable'], 1)
            self.assertTrue(metrics['review_required'])
            self.assertIsNone(metrics['grn_identity_detection_rate'])
            self.assertNotIn('tpr', metrics)
            leaked = root / 'leaked'; leaked.mkdir()
            rows = [{**r, 'split': 'test', 'role': 'test'} for r in fixtures.SupervisedTests().make_rows('train', 'train')]
            save_table(leaked, rows, {'test_profile': 1}, {'actual_byte_ratio': .01})
            args.input, args.output = str(leaked), str(root / 'bad-results')
            with self.assertRaisesRegex(ValueError, 'leakage'):
                evaluate(args)
            self.assertFalse((root / 'bad-results').exists())
            with open(model / 'weights.pt', 'ab') as f:
                f.write(b'corruption')
            with self.assertRaisesRegex(ValueError, 'artifact changed'):
                load_model(model)

    # 确认不可评分连接仍在分母中，且无目标条件不输出伪造的零目标检出率。
    def test_unscoreable_and_empty_target_metrics(self):
        rows = [dict(label=0, group='b', status='no_zeek_record'), dict(label=0, group='c', status='ok')]
        predictions, metrics = anomaly_metrics(rows, [3.0], 2.0, 0, 1)
        self.assertEqual(metrics['background_anomaly_rate'], .5)
        self.assertIsNone(metrics['grn_anomaly_detection_rate'])
        self.assertEqual(predictions[0]['decision'], 'unscorable')
        self.assertIsNone(predictions[0]['reconstruction_error'])
        self.assertNotIn('prediction', predictions[0])

    # 确认无压缩瓶颈的配置不能被误当默认 AE 结构。
    def test_reject_no_bottleneck(self):
        with self.assertRaisesRegex(ValueError, 'bottleneck'):
            validate_config({'candidates': [dict(hidden_dims=[16, 16], learning_rate=.001, weight_decay=0,
                max_epochs=8, batch_size=16, patience=3, min_delta=1e-6)]})

    # 确认缺少独立背景调参／校准组时拒绝训练，不隐式拆分训练连接。
    def test_requires_background_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = fixtures.SupervisedTests().make_rows('train', 'train')
            folder = root / 'dev'; folder.mkdir()
            save_table(folder, rows, {'test_profile': 1}, [])
            with self.assertRaisesRegex(ValueError, 'background in train, tuning'):
                self.train_model(root, folder)


if __name__ == '__main__':
    unittest.main()
