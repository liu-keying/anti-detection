"""RF/XGBoost/MLP training, held-out calibration, and frozen test evaluation."""

# 数据用途必须分离：train 拟合，tuning 选型，calibration 定阈值，test 只评价。
import argparse
import csv
import importlib.metadata
import json
import math
import platform
import subprocess
import warnings
from collections import Counter
from pathlib import Path

from .features import FEATURES, extract
from .prepare import digest, positive, write_json
from .suricata import write_csv

# 有限参数搜索空间应在看测试结果之前确定，避免依据测试表现反复扩充搜索。
DEFAULT_GRID = {
    'rf': [{'n_estimators': 200, 'max_depth': None, 'min_samples_leaf': 2},
           {'n_estimators': 200, 'max_depth': 12, 'min_samples_leaf': 4}],
    'xgb': [{'n_estimators': 200, 'max_depth': 3, 'learning_rate': .05},
            {'n_estimators': 200, 'max_depth': 6, 'learning_rate': .05}],
    'mlp': [{'hidden_layer_sizes': [32, 16], 'alpha': .001, 'max_iter': 400},
            {'hidden_layer_sizes': [64, 32], 'alpha': .01, 'max_iter': 400}]
}


# 延迟导入机器学习依赖，使基础数据准备命令不要求预先安装完整 ML 环境。
def dependencies():
    try:
        import joblib
        import numpy as np
        import sklearn
        import xgboost
    except ImportError as exc:
        raise ValueError("install ML dependencies: python -m pip install -e '.[ml]'") from exc
    return np, joblib


# 记录实际使用的 Python 与模型库版本，用于冻结模型后的环境一致性校验。
def versions():
    result = {'python': platform.python_version()}
    for name in ('numpy', 'scikit-learn', 'joblib', 'xgboost-cpu', 'xgboost'):
        try:
            result[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            pass
    return result


# 读取并验证特征列、文件哈希、样本身份和数值范围，不重新拟合任何统计量。
def load_table(folder):
    folder = Path(folder).resolve()
    metadata = json.loads((folder / 'dataset.json').read_text())
    if metadata['features'] != FEATURES or metadata['dataset_sha256'] != digest(folder / 'dataset.csv'):
        raise ValueError(f'feature schema/hash mismatch: {folder}')
    with open(folder / 'dataset.csv', newline='') as f:
        rows = list(csv.DictReader(f))
    ids = set()
    for row in rows:
        if row['sample_id'] in ids:
            raise ValueError('duplicate sample_id within feature table')
        ids.add(row['sample_id'])
        row['label'] = int(row['label'])
        if row['label'] not in (0, 1) or not row['group'] or row['split'] not in ('train', 'validation', 'test'):
            raise ValueError('invalid feature row identity/split/label')
        if row['status'] == 'ok':
            values = [float(row[name]) if row[name] != '' else float('nan') for name in FEATURES]
            if any(math.isinf(v) or (math.isfinite(v) and v < 0) for v in values):
                raise ValueError('negative or infinite feature value')
            if any(not math.isfinite(v) for v in values[1:]):
                raise ValueError('non-duration counters/ratios must be finite')
    return rows, metadata


# 只按 FEATURES 白名单构造模型矩阵；地址、组、标签等追踪列不会成为输入。
def array(rows):
    np, _ = dependencies()
    return np.array([[float(r[f]) if r[f] != '' else np.nan for f in FEATURES] for r in rows], dtype=float)


# 收集样本、原始文件和类别内采集组身份，支持多层次开发／测试泄漏检查。
def identities(rows):
    return dict(sample_ids=sorted({r['sample_id'] for r in rows}),
                source_hashes=sorted({r['source_sha256'] for r in rows}),
                groups=sorted({f"{r['label']}:{r['group']}" for r in rows}))


# 任一身份集合相交即拒绝使用，避免仅检查文件名而漏掉同源样本。
def disjoint(first, second):
    for field in ('sample_ids', 'source_hashes', 'groups'):
        if set(first[field]) & set(second[field]):
            raise ValueError(f'data leakage: shared {field}')


# 对背景评分选择经验阈值，使用严格大于判定；同分样本整体保留，不随机拆分。
def threshold_at_fpr(scores, alpha):
    """Strict score > threshold. Ties are retained together, never broken randomly."""
    np, _ = dependencies()
    scores = np.asarray(scores, dtype=float)
    if not 0 < alpha < 1 or not len(scores) or not np.isfinite(scores).all():
        raise ValueError('calibration requires finite background scores and 0 < FPR budget < 1')
    # 小样本下允许误报数可能为 0；阈值取实际评分，严格 > 让同分记录整体不超限。
    allowed = math.floor(alpha * len(scores))
    threshold = float(np.sort(scores)[::-1][allowed])
    actual = float(np.mean(scores > threshold))
    return dict(threshold=threshold, comparison='score > threshold', background_samples=len(scores),
                allowed_false_positives=allowed, observed_false_positives=int(sum(scores > threshold)),
                empirical_fpr=actual, fpr_budget=alpha,
                resolution=1 / len(scores), low_tail_sample_support=alpha * len(scores) < 20)


# 建立模型与预处理流水线；所有拟合只在训练组进行，MLP 额外标准化。
# 固定随机种子和线程；XGBoost 使用 CPU，类别权重仅由训练标签决定。
def pipeline_for(model, params, seed, jobs, labels):
    np, _ = dependencies()
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import FunctionTransformer, StandardScaler
    from sklearn.impute import SimpleImputer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.neural_network import MLPClassifier
    from xgboost import XGBClassifier
    if model == 'rf':
        options = {'class_weight': 'balanced', **params}
        options.update(random_state=seed, n_jobs=jobs)
        estimator = RandomForestClassifier(**options)
    elif model == 'xgb':
        options = {'tree_method': 'hist', 'eval_metric': 'logloss', 'scale_pos_weight': labels.count(0) / labels.count(1), **params}
        options.update(random_state=seed, n_jobs=jobs, device='cpu')
        estimator = XGBClassifier(**options)
    elif model == 'mlp':
        options = dict(params)
        if 'hidden_layer_sizes' in options:
            options['hidden_layer_sizes'] = tuple(options['hidden_layer_sizes'])
        options.update(random_state=seed, early_stopping=False)
        estimator = MLPClassifier(**options)
    else:
        raise ValueError(f'unknown model: {model}')
    steps = [('log1p', FunctionTransformer(np.log1p, feature_names_out='one-to-one')),
             ('impute', SimpleImputer(strategy='median', keep_empty_features=True))]
    if model == 'mlp':
        steps.append(('scale', StandardScaler()))
    return Pipeline(steps + [('classifier', estimator)])


# 用训练组拟合候选模型，在独立调参组按误报预算比较检出率并保存最佳流水线。
# 最终阈值不在这里冻结，校准组不参与训练或候选选择。
def train(args):
    np, joblib = dependencies()
    rows, metadata = load_table(args.data)
    if any(r['split'] == 'test' for r in rows):
        raise ValueError('test data cannot be supplied to training')
    train_all = [r for r in rows if r['split'] == 'train' and r['role'] == 'train']
    tune_all = [r for r in rows if r['split'] == 'validation' and r['role'] == 'tuning']
    calibration = [r for r in rows if r['split'] == 'validation' and r['role'] == 'calibration']
    for a, b in ((train_all, tune_all), (train_all, calibration), (tune_all, calibration)):
        disjoint(identities(a), identities(b))
    train_rows, tune_rows = ([r for r in subset if r['status'] == 'ok'] for subset in (train_all, tune_all))
    for name, subset in [('training', train_rows), ('tuning', tune_rows)]:
        if {r['label'] for r in subset} != {0, 1}:
            raise ValueError(f'{name} needs scoreable samples from both classes')
    if not any(r['label'] == 0 for r in calibration):
        raise ValueError('development data needs independent background calibration groups')
    grid = json.loads(Path(args.grid).read_text()) if args.grid else DEFAULT_GRID
    models = args.models.split(',')
    if len(set(models)) != len(models) or any(m not in DEFAULT_GRID for m in models):
        raise ValueError('models must be a unique subset of rf,xgb,mlp')
    for model in models:
        if not isinstance(grid.get(model), list) or not grid[model]:
            raise ValueError(f'empty parameter grid for {model}')
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    x_train, x_tune = array(train_rows), array(tune_rows)
    y_train, y_tune = [r['label'] for r in train_rows], np.array([r['label'] for r in tune_rows])
    model_meta = {}
    for model in models:
        best, trials = None, []
        for index, params in enumerate(grid[model]):
            pipeline = pipeline_for(model, params, args.seed, args.jobs, y_train)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                pipeline.fit(x_train, y_train)
            scores = pipeline.predict_proba(x_tune)[:, 1]
            # 这里的阈值只用于候选比较，最终阈值由独立 calibration 背景重新确定。
            choice = threshold_at_fpr(scores[y_tune == 0], args.fpr)
            hits = sum(s > choice['threshold'] for r, s in zip(tune_rows, scores) if r['label'] == 1)
            total = sum(r['label'] == 1 for r in tune_all)
            tpr = hits / total
            trial = dict(candidate=index, parameters=params, tuning_tpr_end_to_end=tpr,
                         tuning_threshold=choice, warnings=[str(w.message) for w in caught])
            trials.append(trial)
            # Stable tie break favors the first predeclared candidate.
            if best is None or tpr > best[0]:
                best = (tpr, pipeline, params, index)
        joblib.dump(best[1], out / f'{model}.joblib')
        if model == 'xgb':
            best[1].named_steps['classifier'].save_model(out / 'xgb.json')
        model_meta[model] = dict(file=f'{model}.joblib', sha256=digest(out / f'{model}.joblib'),
            selected_candidate=best[3], parameters=best[2], trials=trials)
    write_json(out / 'training.json', dict(schema_version=1, versions=versions(), seed=args.seed,
        fpr_budget=args.fpr, features=FEATURES, profile=metadata['profile'], models=model_meta,
        development_identities=identities(rows), train_identities=identities(train_all),
        tune_identities=identities(tune_all), calibration_identities=identities(calibration),
        development_dataset_sha256=metadata['dataset_sha256'],
        coverage={name: dict(total=len(subset), scoreable=sum(r['status'] == 'ok' for r in subset))
                  for name, subset in [('train', train_all), ('tuning', tune_all), ('calibration', calibration)]}))
    write_json(out / 'grid.json', grid)


# 验证模型文件和环境后加载流水线；joblib 只能用于来源可信的本地模型。
def load_models(folder):
    _, joblib = dependencies()
    folder = Path(folder).resolve()
    metadata = json.loads((folder / 'training.json').read_text())
    if metadata['features'] != FEATURES or metadata['versions'] != versions():
        raise ValueError('model feature schema or Python/library versions differ; restore training environment')
    models = {}
    for name, info in metadata['models'].items():
        if digest(folder / info['file']) != info['sha256']:
            raise ValueError(f'model hash mismatch: {name}')
        models[name] = joblib.load(folder / info['file'])
    return metadata, models


# 只对独立校准组的可评分背景取分位阈值，不使用 GRN 评分或更新模型。
def calibrate(args):
    np, _ = dependencies()
    metadata, models = load_models(args.models)
    rows, data_meta = load_table(args.data)
    if data_meta['dataset_sha256'] != metadata['development_dataset_sha256']:
        raise ValueError('calibration must use the declared frozen development dataset')
    chosen = [r for r in rows if r['split'] == 'validation' and r['role'] == 'calibration']
    if identities(chosen) != metadata['calibration_identities']:
        raise ValueError('calibration identities changed')
    if data_meta['profile'] != metadata['profile']:
        raise ValueError('extraction profile differs')
    usable = [r for r in chosen if r['label'] == 0 and r['status'] == 'ok']
    if not usable:
        raise ValueError('no scoreable calibration background')
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    entries, score_rows = {}, []
    for model, pipeline in models.items():
        scores = pipeline.predict_proba(array(usable))[:, 1]
        entries[model] = threshold_at_fpr(scores, metadata['fpr_budget'])
        for row, score in zip(usable, scores):
            score_rows.append(dict(model=model, sample_id=row['sample_id'], group=row['group'], score=float(score)))
    write_csv(out / 'background-scores.csv', score_rows)
    write_json(out / 'thresholds.json', dict(training_sha256=digest(Path(args.models) / 'training.json'),
        versions=versions(), models=entries, calibration_background_total=sum(r['label'] == 0 for r in chosen),
        calibration_background_scoreable=len(usable),
        note='Thresholds use scoreable independent background only; not a guarantee on population/test FPR.'))


# 按完整采集组重采样，再以合计计数计算区间，避免假设组内连接独立。
# 极端零／全检出时不生成虚假的零宽区间，独立组不足也返回空值。
def cluster_interval(rows, label, replicates, seed):
    np, _ = dependencies()
    groups = {}
    for row in rows:
        if row['label'] == label:
            counts = groups.setdefault(row['group'], [0, 0])
            counts[0] += row['prediction']
            counts[1] += 1
    if len(groups) < 2 or replicates == 0:
        return None
    counts = np.array(list(groups.values()))
    if counts[:, 0].sum() in (0, counts[:, 1].sum()):
        return None  # A nonparametric bootstrap cannot bound unseen successes/failures.
    rng = np.random.default_rng(seed)
    rates = []
    for _ in range(replicates):
        sampled = counts[rng.integers(0, len(counts), len(counts))].sum(axis=0)
        rates.append(sampled[0] / sampled[1])
    return [float(x) for x in np.quantile(rates, [.025, .975])]


# 将固定评分和阈值映射到全部标签连接，保留不可评分记录的端到端分母。
# 未产生评分的记录没有正判定，同时单独报告可评分子集指标及覆盖率。
def evaluate_rows(rows, scores, threshold, replicates=1000, seed=2026):
    predictions = []
    score_iter = iter(scores)
    for row in rows:
        score = float(next(score_iter)) if row['status'] == 'ok' else None
        if score is not None and not math.isfinite(score):
            raise ValueError('nonfinite model score')
        predictions.append(dict(row, score=score, prediction=int(score > threshold) if score is not None else 0,
                                decision='scored' if score is not None else 'unscorable'))
    tp = sum(r['label'] == 1 and r['prediction'] == 1 for r in predictions)
    fp = sum(r['label'] == 0 and r['prediction'] == 1 for r in predictions)
    positive_count = sum(r['label'] == 1 for r in rows)
    negative_count = len(rows) - positive_count
    # 分别保留总分母和可评分分母，防止解析失败被误当作检测器的低误报能力。
    positive_scored = sum(r['label'] == 1 and r['status'] == 'ok' for r in rows)
    negative_scored = sum(r['label'] == 0 and r['status'] == 'ok' for r in rows)
    metrics = dict(tp=tp, fp=fp, fn=positive_count - tp, tn=negative_count - fp,
        grn_connections=positive_count, background_connections=negative_count,
        grn_scoreable=positive_scored, background_scoreable=negative_scored,
        tpr=tp / positive_count if positive_count else None,
        fpr=fp / negative_count if negative_count else None,
        precision=tp / (tp + fp) if tp + fp else None,
        fnr=(positive_count - tp) / positive_count if positive_count else None,
        scoreable_tpr=tp / positive_scored if positive_scored else None,
        scoreable_fpr=fp / negative_scored if negative_scored else None,
        grn_coverage=positive_scored / positive_count if positive_count else None,
        background_coverage=negative_scored / negative_count if negative_count else None,
        grn_unscorable=positive_count - positive_scored, background_unscorable=negative_count - negative_scored,
        tpr_cluster_bootstrap_95=cluster_interval(predictions, 1, replicates, seed),
        fpr_cluster_bootstrap_95=cluster_interval(predictions, 0, replicates, seed),
        ci_method='independent capture groups, percentile bootstrap, ratio of pooled counts; >=2 groups required',
        interpretation='Unscorable rows receive no positive detection; their labels remain in end-to-end denominators.')
    return predictions, metrics


# 冻结模型和阈值后逐比例测试，先对所有条件做配置与泄漏检查，再输出结果。
def evaluate(args):
    np, _ = dependencies()
    metadata, models = load_models(args.models)
    thresholds = json.loads(Path(args.thresholds).read_text())
    if thresholds['training_sha256'] != digest(Path(args.models) / 'training.json'):
        raise ValueError('thresholds do not belong to the frozen training bundle')
    source = Path(args.input).resolve()
    folders = [source] if (source / 'dataset.csv').exists() else sorted(source.glob('ratio_*'))
    if not folders:
        raise ValueError('no test feature datasets')
    # Validate every condition before making output directories.
    datasets = []
    for folder in folders:
        rows, info = load_table(folder)
        if not rows or any(r['split'] != 'test' or r['role'] != 'test' for r in rows):
            raise ValueError('evaluation requires test rows only')
        if info['profile'] != metadata['profile']:
            raise ValueError('test extraction profile differs from training')
        disjoint(metadata['development_identities'], identities(rows))
        datasets.append((folder, rows, info))
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    summary = []
    for folder, rows, info in datasets:
        target = out / folder.name
        target.mkdir()
        for name, pipeline in models.items():
            model_out = target / name
            model_out.mkdir()
            usable = [r for r in rows if r['status'] == 'ok']
            scores = pipeline.predict_proba(array(usable))[:, 1] if usable else []
            cutoff = thresholds['models'][name]['threshold']
            predictions, metrics = evaluate_rows(rows, scores, cutoff, args.bootstrap, args.seed)
            metrics.update(model=name, condition=folder.name, threshold=cutoff,
                fpr_budget=metadata['fpr_budget'], actual_byte_ratio=info['inputs']['actual_byte_ratio'],
                test_fpr_exceeds_budget=metrics['fpr'] is not None and metrics['fpr'] > metadata['fpr_budget'],
                review_required=bool(metrics['grn_unscorable'] or metrics['background_unscorable']),
                dataset_sha256=info['dataset_sha256'], training_sha256=digest(Path(args.models) / 'training.json'),
                thresholds_sha256=digest(args.thresholds))
            write_json(model_out / 'metrics.json', metrics)
            write_csv(model_out / 'predictions.csv', predictions)
            group_rows = []
            for label, group in sorted({(r['label'], r['group']) for r in predictions}):
                subset = [r for r in predictions if r['label'] == label and r['group'] == group]
                group_rows.append(dict(label=label, group=group, connections=len(subset),
                    scoreable=sum(r['status'] == 'ok' for r in subset), positives=sum(r['prediction'] for r in subset)))
            write_csv(model_out / 'groups.csv', group_rows)
            # PR curves apply only to scored rows. Coverage is reported separately.
            from sklearn.metrics import precision_recall_curve, average_precision_score
            if {r['label'] for r in usable} == {0, 1}:
                truth = [r['label'] for r in usable]
                precision, recall, cutoffs = precision_recall_curve(truth, scores)
                curve = [dict(threshold=float(c), precision=float(p), recall=float(r))
                         for c, p, r in zip(cutoffs, precision, recall)]
                curve.append(dict(threshold=None, precision=float(precision[-1]), recall=float(recall[-1])))
                write_csv(model_out / 'pr-curve.csv', curve)
                write_json(model_out / 'pr-info.json', dict(average_precision=float(average_precision_score(truth, scores)),
                    scope='scoreable rows only; sklearn curve uses score >= threshold; deployed decision uses strict >'))
            summary.append(metrics)
    write_json(out / 'summary.json', summary)
    fields = ['condition', 'model', 'actual_byte_ratio', 'threshold', 'tp', 'fp', 'fn', 'tn',
              'tpr', 'fpr', 'precision', 'fnr', 'grn_coverage', 'background_coverage',
              'test_fpr_exceeds_budget', 'review_required']
    write_csv(out / 'summary.csv', [{k: r[k] for k in fields} for r in summary])


# 从已保存结果绘制指标及 PR 图，不改变模型、阈值或预测。
def plot_results(args):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise ValueError("install plotting dependency: python -m pip install -e '.[ml]'") from exc
    source = Path(args.input).resolve()
    summary = json.loads((source / 'summary.json').read_text())
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    for metric, ylabel in [('tpr', 'GRN true positive rate'), ('fpr', 'Background false positive rate'),
                           ('precision', 'Precision')]:
        fig, ax = plt.subplots(figsize=(6.5, 4))
        for model in sorted({r['model'] for r in summary}):
            rows = sorted((r for r in summary if r['model'] == model and r[metric] is not None),
                          key=lambda r: r['actual_byte_ratio'])
            if rows:
                ax.plot([r['actual_byte_ratio'] * 100 for r in rows], [r[metric] for r in rows],
                        marker='o', label=model)
        ax.set(xlabel='Actual GRN IP-byte share (%)', ylabel=ylabel, ylim=(-.02, 1.02))
        ax.set_xscale('symlog', linthresh=.001)
        ax.grid(alpha=.3)
        if ax.lines:
            ax.legend()
        fig.tight_layout()
        fig.savefig(out / f'{metric}.png', dpi=180)
        fig.savefig(out / f'{metric}.svg')
        plt.close(fig)
    for folder in sorted(source.iterdir()):
        if not folder.is_dir():
            continue
        fig, ax = plt.subplots(figsize=(6, 4))
        for curve_path in sorted(folder.glob('*/pr-curve.csv')):
            with open(curve_path, newline='') as f:
                curve = list(csv.DictReader(f))
            ax.plot([float(r['recall']) for r in curve], [float(r['precision']) for r in curve], label=curve_path.parent.name)
        if not ax.lines:
            plt.close(fig)
            continue
        ax.set(xlabel='Recall (scoreable connections)', ylabel='Precision', title=folder.name,
               xlim=(0, 1.02), ylim=(0, 1.02))
        ax.legend()
        ax.grid(alpha=.3)
        fig.tight_layout()
        fig.savefig(out / f'{folder.name}-pr.png', dpi=180)
        fig.savefig(out / f'{folder.name}-pr.svg')
        plt.close(fig)
    write_json(out / 'plot-info.json', dict(source=str(source), summary_sha256=digest(source / 'summary.json'),
        note='Point estimates only; no confidence bands. PR curves use scoreable rows only. Do not pool independent rounds here.'))


# 监督分类命令入口；区分提取、训练、校准、测试和绘图，避免测试中隐式训练。
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    extraction = sub.add_parser('extract')
    sources = extraction.add_mutually_exclusive_group(required=True)
    sources.add_argument('--manifest')
    sources.add_argument('--input')
    extraction.add_argument('--zeek', default='zeek')
    extraction.add_argument('--checksums', choices=['all', 'none'], default='all')
    extraction.add_argument('--timeout', type=positive, default=120)
    extraction.add_argument('--output', required=True)
    trainer = sub.add_parser('train')
    trainer.add_argument('--data', required=True)
    trainer.add_argument('--models', default='rf,xgb,mlp')
    trainer.add_argument('--grid')
    trainer.add_argument('--fpr', type=float, default=.001)
    trainer.add_argument('--seed', type=int, default=2026)
    trainer.add_argument('--jobs', type=positive, default=1)
    trainer.add_argument('--output', required=True)
    calibration = sub.add_parser('calibrate')
    calibration.add_argument('--models', required=True)
    calibration.add_argument('--data', required=True)
    calibration.add_argument('--output', required=True)
    evaluation = sub.add_parser('evaluate')
    evaluation.add_argument('--models', required=True)
    evaluation.add_argument('--thresholds', required=True)
    evaluation.add_argument('--input', required=True)
    evaluation.add_argument('--bootstrap', type=int, default=1000)
    evaluation.add_argument('--seed', type=int, default=2026)
    evaluation.add_argument('--output', required=True)
    plotting = sub.add_parser('plot')
    plotting.add_argument('--input', required=True)
    plotting.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'train' and not 0 < args.fpr < 1:
            raise ValueError('FPR budget must be between 0 and 1')
        if args.command == 'evaluate' and args.bootstrap < 0:
            raise ValueError('bootstrap repetitions must be nonnegative')
        {'extract': extract, 'train': train, 'calibrate': calibrate, 'evaluate': evaluate, 'plot': plot_results}[args.command](args)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        parser.exit(2, f'Error: {exc}\n')



if __name__ == '__main__':
    main()
