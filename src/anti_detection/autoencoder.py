"""Background-only PyTorch autoencoder: reconstruction anomaly detection, not GRN identification."""

# AE 只学习背景；GRN 标签仅在最终评价阶段解释异常命中，不能视为身份识别。
import argparse
import copy
import json
import math
from pathlib import Path

from .features import FEATURES
from .prepare import digest, positive, write_json
from .supervised import (array, dependencies, disjoint, evaluate_rows, identities,
                         load_table, threshold_at_fpr, versions)
from .suricata import write_csv

# 固定结构与训练预算；候选可以增加，但只能通过背景调参损失比较。
DEFAULT_CONFIG = {'candidates': [dict(hidden_dims=[16, 8, 4, 8, 16], learning_rate=.001,
    weight_decay=.00001, max_epochs=200, batch_size=256, patience=15, min_delta=.000001)]}


# 延迟加载 PyTorch，使用户在只使用其他流程时无需导入深度学习框架。
def torch_module():
    try:
        import torch
    except ImportError as exc:
        raise ValueError('Install CPU PyTorch as described in docs/autoencoder.md') from exc
    return torch


# 在共用 ML 环境记录上补充 PyTorch 版本，校准／推理必须保持一致。
def environment():
    return dict(versions(), torch=torch_module().__version__)


# 构建十维输入／输出的全连接 AE；隐藏层 ReLU，末层保持线性以重构标准化负值。
def network(hidden):
    torch = torch_module()
    sizes = [len(FEATURES), *hidden, len(FEATURES)]
    layers = []
    for index in range(len(sizes) - 1):
        layers.append(torch.nn.Linear(sizes[index], sizes[index + 1]))
        if index < len(sizes) - 2:
            layers.append(torch.nn.ReLU())
    return torch.nn.Sequential(*layers)


# 检查预先声明的候选参数及瓶颈维度，不允许缺失训练参数或无压缩瓶颈的结构。
def validate_config(config):
    candidates = config.get('candidates')
    if not isinstance(candidates, list) or not candidates:
        raise ValueError('config requires nonempty candidates')
    expected = set(DEFAULT_CONFIG['candidates'][0])
    for params in candidates:
        if set(params) != expected:
            raise ValueError(f'each candidate must have exactly: {sorted(expected)}')
        hidden = params['hidden_dims']
        if not isinstance(hidden, list) or not hidden or any(type(n) is not int or n <= 0 for n in hidden):
            raise ValueError('hidden_dims must contain positive integer widths')
        if min(hidden) >= len(FEATURES):
            raise ValueError('autoencoder requires a bottleneck smaller than the input dimension')
        for name in ('max_epochs', 'batch_size', 'patience'):
            if type(params[name]) is not int or params[name] <= 0:
                raise ValueError(f'{name} must be a positive integer')
        for name in ('learning_rate', 'weight_decay', 'min_delta'):
            value = params[name]
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise ValueError(f'{name} must be finite and nonnegative')
        if params['learning_rate'] == 0:
            raise ValueError('learning_rate must be positive')
    return candidates


# 背景专用预处理：log1p、缺失值填补、标准化；拟合时不得传入 GRN。
def preprocess():
    np, _ = dependencies()
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import FunctionTransformer, StandardScaler
    from sklearn.impute import SimpleImputer
    return Pipeline([('log1p', FunctionTransformer(np.log1p, feature_names_out='one-to-one')),
                     ('impute', SimpleImputer(strategy='median', keep_empty_features=True)),
                     ('scale', StandardScaler())])


# 只使用已拟合背景预处理转换输入，并确认 float32 精度下数值仍然有限。
def transformed(processor, rows):
    np, _ = dependencies()
    values = processor.transform(array(rows)).astype(np.float32)
    if not np.isfinite(values).all():
        raise ValueError('preprocessed data is not finite in float32')
    return values


# 以推理模式分批计算每条连接的逐特征均方误差；评分过程不更新权重。
def reconstruction_errors(model, values, batch_size=4096):
    torch = torch_module()
    np, _ = dependencies()
    model.eval()
    errors = []
    with torch.no_grad():
        for start in range(0, len(values), batch_size):
            batch = torch.from_numpy(values[start:start + batch_size])
            errors.extend(((batch - model(batch)) ** 2).mean(dim=1).cpu().tolist())
    result = np.asarray(errors, dtype=float)
    if not np.isfinite(result).all():
        raise ValueError('nonfinite reconstruction errors')
    return result


# 仅用背景训练一个候选，以背景调参损失早停并恢复最低损失轮次的权重。
# 保存 state_dict 的深拷贝，避免后续 optimizer 更新覆盖已记录的最佳模型。
def fit_candidate(x_train, x_tuning, params, seed):
    torch = torch_module()
    torch.manual_seed(seed)
    model = network(params['hidden_dims'])
    optimizer = torch.optim.Adam(model.parameters(), lr=params['learning_rate'], weight_decay=params['weight_decay'])
    generator = torch.Generator().manual_seed(seed)
    train_tensor = torch.from_numpy(x_train)
    best_loss, best_state, best_epoch, stale = math.inf, None, 0, 0
    history = []
    for epoch in range(1, params['max_epochs'] + 1):
        model.train()
        order = torch.randperm(len(train_tensor), generator=generator)
        total_loss = 0.0
        for start in range(0, len(order), params['batch_size']):
            batch = train_tensor[order[start:start + params['batch_size']]]
            optimizer.zero_grad()
            loss = ((batch - model(batch)) ** 2).mean()
            if not torch.isfinite(loss):
                raise ValueError('nonfinite training loss')
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach()) * len(batch)
        tuning_loss = float(reconstruction_errors(model, x_tuning).mean())
        history.append(dict(epoch=epoch, training_mse=total_loss / len(train_tensor), tuning_mse=tuning_loss))
        # 小幅改善仍保存最低损失权重，但只有超过 min_delta 的改善才重置早停计数。
        meaningful = tuning_loss < best_loss - params['min_delta']
        if tuning_loss < best_loss:
            best_loss, best_state, best_epoch = tuning_loss, copy.deepcopy(model.state_dict()), epoch
        stale = 0 if meaningful else stale + 1
        if stale >= params['patience']:
            break
    model.load_state_dict(best_state)
    return model, history, dict(best_epoch=best_epoch, best_tuning_mse=best_loss,
        epochs_run=len(history), stopped_early=len(history) < params['max_epochs'],
        reached_epoch_limit=len(history) == params['max_epochs'])


# 过滤开发表中的 GRN，仅用背景拟合预处理、训练和选择候选。
# 仍保留全部开发身份，防止其他检测器训练过的 GRN 被误作共同留出测试集。
def train(args):
    np, joblib = dependencies()
    torch = torch_module()
    torch.set_num_threads(args.threads)
    torch.use_deterministic_algorithms(True)
    rows, info = load_table(args.data)
    if any(r['split'] == 'test' for r in rows):
        raise ValueError('test rows cannot be supplied to AE training')
    partitions = {
        'train': [r for r in rows if r['split'] == 'train' and r['role'] == 'train' and r['label'] == 0],
        'tuning': [r for r in rows if r['split'] == 'validation' and r['role'] == 'tuning' and r['label'] == 0],
        'calibration': [r for r in rows if r['split'] == 'validation' and r['role'] == 'calibration' and r['label'] == 0]}
    for a, b in (('train', 'tuning'), ('train', 'calibration'), ('tuning', 'calibration')):
        disjoint(identities(partitions[a]), identities(partitions[b]))
    usable = {name: [r for r in subset if r['status'] == 'ok'] for name, subset in partitions.items()}
    if any(not subset for subset in usable.values()):
        raise ValueError('AE requires scoreable background in train, tuning and independent calibration roles')
    config = json.loads(Path(args.config).read_text()) if args.config else DEFAULT_CONFIG
    candidates = validate_config(config)
    processor = preprocess()
    # 此处传入的行已被过滤为背景训练组；不复用监督分类器的混合训练预处理。
    processor.fit(array(usable['train']))
    x_train, x_tuning = transformed(processor, usable['train']), transformed(processor, usable['tuning'])
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    trials, histories, best = [], [], None
    for index, params in enumerate(candidates):
        model, history, result = fit_candidate(x_train, x_tuning, params, args.seed + index)
        trials.append(dict(candidate=index, seed=args.seed + index, parameters=params, **result))
        histories.extend(dict(candidate=index, **row) for row in history)
        if best is None or result['best_tuning_mse'] < best[0]:
            best = (result['best_tuning_mse'], model, index, params)
    joblib.dump(processor, out / 'preprocessing.joblib')
    torch.save(best[1].state_dict(), out / 'weights.pt')
    write_csv(out / 'history.csv', histories)
    write_json(out / 'config.json', config)
    files = {name: digest(out / name) for name in ('preprocessing.joblib', 'weights.pt', 'history.csv', 'config.json')}
    write_json(out / 'training.json', dict(schema_version=1, kind='background_reconstruction_autoencoder',
        features=FEATURES, profile=info['profile'], versions=environment(), device='cpu', threads=args.threads,
        seed=args.seed, fpr_budget=args.fpr, selected_candidate=best[2], hidden_dims=best[3]['hidden_dims'],
        trials=trials, files=files, development_dataset_sha256=info['dataset_sha256'],
        development_identities=identities(rows),
        background_identities={name: identities(subset) for name, subset in partitions.items()},
        coverage={name: dict(total=len(subset), scoreable=len(usable[name])) for name, subset in partitions.items()},
        ignored_grn_rows=sum(r['label'] == 1 for r in rows),
        selection='minimum background tuning MSE; GRN is never scored for preprocessing/training/model selection',
        error='mean squared reconstruction error across standardized features'))


# 先校验冻结文件与环境，再加载预处理和仅包含张量权重的 state_dict。
def load_model(folder):
    _, joblib = dependencies()
    torch = torch_module()
    folder = Path(folder).resolve()
    info = json.loads((folder / 'training.json').read_text())
    if info['kind'] != 'background_reconstruction_autoencoder' or info['features'] != FEATURES or info['versions'] != environment():
        raise ValueError('AE kind/schema/environment mismatch; restore training environment')
    for name, sha in info['files'].items():
        if digest(folder / name) != sha:
            raise ValueError(f'frozen AE artifact changed: {name}')
    torch.set_num_threads(info['threads'])
    torch.use_deterministic_algorithms(True)
    model = network(info['hidden_dims'])
    # 只恢复张量权重，不反序列化完整网络对象；网络结构由已核验元数据重建。
    model.load_state_dict(torch.load(folder / 'weights.pt', map_location='cpu', weights_only=True))
    model.eval()
    return info, joblib.load(folder / 'preprocessing.joblib'), model


# 仅用独立背景校准重构误差阈值；GRN 开发数据不会被评分或用于调阈值。
def calibrate(args):
    info, processor, model = load_model(args.model)
    rows, data_info = load_table(args.data)
    if data_info['dataset_sha256'] != info['development_dataset_sha256'] or data_info['profile'] != info['profile']:
        raise ValueError('calibration requires the original frozen development dataset/profile')
    chosen = [r for r in rows if r['label'] == 0 and r['split'] == 'validation' and r['role'] == 'calibration']
    if identities(chosen) != info['background_identities']['calibration']:
        raise ValueError('background calibration identities changed')
    usable = [r for r in chosen if r['status'] == 'ok']
    if not usable:
        raise ValueError('no scoreable calibration background')
    errors = reconstruction_errors(model, transformed(processor, usable))
    cutoff = threshold_at_fpr(errors, info['fpr_budget'])
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    write_csv(out / 'background-errors.csv', [dict(sample_id=r['sample_id'], group=r['group'], reconstruction_error=float(e))
                                            for r, e in zip(usable, errors)])
    write_json(out / 'threshold.json', dict(training_sha256=digest(Path(args.model) / 'training.json'),
        versions=environment(), **cutoff, background_total=len(chosen), background_scoreable=len(usable),
        error_definition=info['error'], note='Background-only empirical calibration; no guarantee on test/population FPR'))


# 复用共用计数和分组区间算法，但将结果明确命名为异常检出而非身份分类。
def anomaly_metrics(rows, errors, cutoff, replicates, seed):
    predictions, metrics = evaluate_rows(rows, errors, cutoff, replicates, seed)
    rename = {'tp': 'grn_flagged', 'fp': 'background_flagged', 'fn': 'grn_unflagged', 'tn': 'background_unflagged',
        'tpr': 'grn_anomaly_detection_rate', 'fpr': 'background_anomaly_rate', 'precision': 'anomaly_grn_fraction',
        'fnr': 'grn_unflagged_rate', 'scoreable_tpr': 'scoreable_grn_anomaly_rate',
        'scoreable_fpr': 'scoreable_background_anomaly_rate',
        'tpr_cluster_bootstrap_95': 'grn_anomaly_rate_cluster_bootstrap_95',
        'fpr_cluster_bootstrap_95': 'background_anomaly_rate_cluster_bootstrap_95'}
    metrics = {rename.get(k, k): v for k, v in metrics.items()}
    metrics.update(result_type='anomaly_detection_not_grn_identification',
        grn_identity_detection_rate=None,
        anomaly_grn_fraction_definition='fraction of flagged connections that are GRN; not identity classification precision')
    for row in predictions:
        row['reconstruction_error'] = row.pop('score')
        row['anomalous'] = row.pop('prediction')
    return predictions, metrics


# 使用冻结 AE、背景预处理和阈值测试共同留出集，禁止在线适应混合数据。
def evaluate(args):
    info, processor, model = load_model(args.model)
    cutoff_info = json.loads(Path(args.threshold).read_text())
    if cutoff_info['training_sha256'] != digest(Path(args.model) / 'training.json'):
        raise ValueError('threshold does not belong to this AE training bundle')
    cutoff = cutoff_info['threshold']
    if not isinstance(cutoff, (int, float)) or not math.isfinite(cutoff) or cutoff < 0:
        raise ValueError('invalid reconstruction threshold')
    if cutoff_info['comparison'] != 'score > threshold' or cutoff_info['fpr_budget'] != info['fpr_budget']:
        raise ValueError('threshold comparison/FPR budget mismatch')
    source = Path(args.input).resolve()
    folders = [source] if (source / 'dataset.csv').exists() else sorted(source.glob('ratio_*'))
    if not folders:
        raise ValueError('no test feature datasets')
    datasets = []
    for folder in folders:
        rows, metadata = load_table(folder)
        if not rows or any(r['split'] != 'test' or r['role'] != 'test' for r in rows):
            raise ValueError('AE evaluation requires test rows only')
        if metadata['profile'] != info['profile']:
            raise ValueError('test extraction profile differs from AE training')
        disjoint(info['development_identities'], identities(rows))
        datasets.append((folder, rows, metadata))
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    summary = []
    for folder, rows, metadata in datasets:
        target = out / folder.name
        target.mkdir()
        usable = [r for r in rows if r['status'] == 'ok']
        errors = reconstruction_errors(model, transformed(processor, usable)) if usable else []
        predictions, metrics = anomaly_metrics(rows, errors, cutoff, args.bootstrap, args.seed)
        metrics.update(condition=folder.name, actual_byte_ratio=metadata['inputs']['actual_byte_ratio'], threshold=cutoff,
            fpr_budget=info['fpr_budget'],
            test_background_rate_exceeds_budget=metrics['background_anomaly_rate'] is not None and metrics['background_anomaly_rate'] > info['fpr_budget'],
            review_required=bool(metrics['grn_unscorable'] or metrics['background_unscorable']),
            dataset_sha256=metadata['dataset_sha256'], training_sha256=digest(Path(args.model) / 'training.json'),
            threshold_sha256=digest(args.threshold))
        write_json(target / 'metrics.json', metrics)
        write_csv(target / 'predictions.csv', predictions)
        groups = []
        for label, group in sorted({(r['label'], r['group']) for r in predictions}):
            subset = [r for r in predictions if r['label'] == label and r['group'] == group]
            hits = sum(r['anomalous'] for r in subset)
            groups.append(dict(label=label, group=group, connections=len(subset),
                scoreable=sum(r['status'] == 'ok' for r in subset), flagged=hits, anomaly_rate=hits / len(subset)))
        write_csv(target / 'groups.csv', groups)
        summary.append(metrics)
    write_json(out / 'summary.json', summary)
    fields = ['condition', 'actual_byte_ratio', 'threshold', 'grn_connections', 'grn_flagged',
        'grn_anomaly_detection_rate', 'background_connections', 'background_flagged', 'background_anomaly_rate',
        'anomaly_grn_fraction', 'grn_coverage', 'background_coverage', 'review_required', 'test_background_rate_exceeds_budget']
    write_csv(out / 'summary.csv', [{k: r[k] for k in fields} for r in summary])


# 绘制异常率、同区间归一化误差分布及背景损失；图表不参与选型和校准。
def plot(args):
    import csv
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    np, _ = dependencies()
    source, out = Path(args.input).resolve(), Path(args.output).resolve()
    summary = json.loads((source / 'summary.json').read_text())
    out.mkdir(parents=True, exist_ok=False)
    fig, ax = plt.subplots(figsize=(6.5, 4))
    for field, label in [('grn_anomaly_detection_rate', 'GRN flagged as anomalous'), ('background_anomaly_rate', 'Background flagged as anomalous')]:
        rows = sorted((r for r in summary if r[field] is not None), key=lambda r: r['actual_byte_ratio'])
        if rows:
            ax.plot([r['actual_byte_ratio'] * 100 for r in rows], [r[field] for r in rows], marker='o', label=label)
    ax.set(xlabel='Actual GRN IP-byte share (%)', ylabel='Anomaly connection rate', ylim=(-.02, 1.02))
    ax.set_xscale('symlog', linthresh=.001)
    ax.grid(alpha=.3)
    if ax.lines:
        ax.legend()
    fig.tight_layout()
    for suffix in ('png', 'svg'):
        fig.savefig(out / f'anomaly-rates.{suffix}', dpi=180)
    plt.close(fig)
    for row in summary:
        with open(source / row['condition'] / 'predictions.csv', newline='') as f:
            predictions = list(csv.DictReader(f))
        values = {label: [math.log10(1 + float(r['reconstruction_error'])) for r in predictions
                         if int(r['label']) == label and r['reconstruction_error'] != ''] for label in (0, 1)}
        if not any(values.values()):
            continue
        bins = np.histogram_bin_edges(values[0] + values[1], bins=30)
        fig, ax = plt.subplots(figsize=(6.5, 4))
        for label, name in ((0, 'Background'), (1, 'GRN')):
            if values[label]:
                ax.hist(values[label], bins=bins, density=True, histtype='step', linewidth=1.7, label=name)
        ax.axvline(math.log10(1 + row['threshold']), color='black', linestyle='--', label='Frozen threshold')
        ax.set(xlabel='log10(1 + standardized reconstruction MSE)', ylabel='Density', title=row['condition'])
        ax.legend()
        fig.tight_layout()
        for suffix in ('png', 'svg'):
            fig.savefig(out / f'{row["condition"]}-errors.{suffix}', dpi=180)
        plt.close(fig)
    if args.model:
        with open(Path(args.model) / 'history.csv', newline='') as f:
            history = list(csv.DictReader(f))
        fig, ax = plt.subplots(figsize=(6.5, 4))
        for candidate in sorted({r['candidate'] for r in history}):
            rows = [r for r in history if r['candidate'] == candidate]
            for field, style in [('training_mse', '-'), ('tuning_mse', '--')]:
                ax.plot([int(r['epoch']) for r in rows], [float(r[field]) for r in rows], style,
                        label=f'candidate {candidate} {field}')
        ax.set(xlabel='Epoch', ylabel='Background reconstruction MSE')
        ax.legend()
        ax.grid(alpha=.3)
        fig.tight_layout()
        for suffix in ('png', 'svg'):
            fig.savefig(out / f'background-training-loss.{suffix}', dpi=180)
        plt.close(fig)
    write_json(out / 'plot-info.json', dict(summary_sha256=digest(source / 'summary.json'),
        note='Anomaly rates are point estimates; error histograms cover scoreable connections only.'))


# AE 命令入口；训练、校准、测试分离，异常标签始终不代表 GRN 身份。
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    trainer = sub.add_parser('train')
    trainer.add_argument('--data', required=True)
    trainer.add_argument('--config')
    trainer.add_argument('--fpr', type=float, default=.001)
    trainer.add_argument('--seed', type=int, default=2026)
    trainer.add_argument('--threads', type=positive, default=1)
    trainer.add_argument('--output', required=True)
    calibration = sub.add_parser('calibrate')
    calibration.add_argument('--model', required=True)
    calibration.add_argument('--data', required=True)
    calibration.add_argument('--output', required=True)
    evaluation = sub.add_parser('evaluate')
    evaluation.add_argument('--model', required=True)
    evaluation.add_argument('--threshold', required=True)
    evaluation.add_argument('--input', required=True)
    evaluation.add_argument('--bootstrap', type=int, default=1000)
    evaluation.add_argument('--seed', type=int, default=2026)
    evaluation.add_argument('--output', required=True)
    plotting = sub.add_parser('plot')
    plotting.add_argument('--input', required=True)
    plotting.add_argument('--model')
    plotting.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'train' and not 0 < args.fpr < 1:
            raise ValueError('FPR budget must be between 0 and 1')
        if args.command == 'evaluate' and args.bootstrap < 0:
            raise ValueError('bootstrap repetitions must be nonnegative')
        {'train': train, 'calibrate': calibrate, 'evaluate': evaluate, 'plot': plot}[args.command](args)
    except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
        parser.exit(2, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
