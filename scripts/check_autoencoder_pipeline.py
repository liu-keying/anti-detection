"""Check AE on prepared synthetic Zeek tables; no real GRN claims."""
import argparse
import json
from pathlib import Path
from anti_detection.autoencoder import calibrate, evaluate, plot, train
from anti_detection.prepare import write_json


# 复用合成 Zeek 特征，实际训练背景 AE、校准和推理，并检查分母与异常命名。
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--development', required=True)
    parser.add_argument('--test-features', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    config = out / 'config.json'
    write_json(config, {'candidates': [dict(hidden_dims=[16, 4, 16], learning_rate=.003,
        weight_decay=0, max_epochs=40, batch_size=32, patience=8, min_delta=1e-6)]})
    train(argparse.Namespace(data=args.development, config=str(config), seed=2026, threads=1,
                             fpr=.1, output=str(out / 'model')))
    calibrate(argparse.Namespace(model=str(out / 'model'), data=args.development, output=str(out / 'calibration')))
    evaluate(argparse.Namespace(model=str(out / 'model'), threshold=str(out / 'calibration/threshold.json'),
                                input=args.test_features, bootstrap=0, seed=2026, output=str(out / 'results')))
    plot(argparse.Namespace(input=str(out / 'results'), model=str(out / 'model'), output=str(out / 'plots')))
    summary = json.loads((out / 'results/summary.json').read_text())
    if len(summary) != 3 or any(r['review_required'] for r in summary):
        raise ValueError('expected three complete synthetic conditions')
    for row in summary:
        if row['grn_flagged'] + row['grn_unflagged'] != row['grn_connections']:
            raise ValueError('GRN denominator mismatch')
        if row['background_flagged'] + row['background_unflagged'] != row['background_connections']:
            raise ValueError('background denominator mismatch')
        if row['grn_identity_detection_rate'] is not None:
            raise ValueError('AE must not report GRN identity recognition')
    write_json(out / 'integration-check.json', dict(status='passed', conditions=3,
        scope='synthetic Zeek features, background-only training, not evidence about real GRN'))
    print(f'Passed AE pipeline check: {out}')


if __name__ == '__main__':
    main()
