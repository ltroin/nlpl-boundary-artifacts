"""Shared loading code and metrics for the RQ2 scripts (taint analysis on the 353 pairs).

All paths are relative to the root of the package, so the scripts can be started from any directory.
Standard library only.
"""
import csv
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The non-reachable set N of the paper (Def. 3).
N = frozenset({'Ignored', 'Missing Context', 'Missing Capabilities', 'Policy Refusal'})

# The 25 labels by group (taxonomy table of the paper).
GROUPS = {
    'Verbatim': ['Fragment Copy', 'Template Slotting', 'Keyword Echo'],
    'Rewrite': ['Paraphrase Rewrite', 'Persona Rewriting', 'Translation', 'Standalone Question Rewrite'],
    'Compression': ['General Summarization', 'Evidence-Constrained Summarization'],
    'Format': ['JSON-Only Template', 'Non-JSON Template', 'Behavioral Constraint'],
    'Decision': ['Binary Decision', 'Computed Number', 'Category Label', 'Ranking'],
    'Generation': ['Content Expansion', 'Code Snippet', 'CLI Commands'],
    'Gating': ['Missing Context', 'Missing Capabilities', 'Policy Refusal'],
    'Weak/None': ['Mostly Common Knowledge', 'Ignored', 'Unclassifiable'],
}
LABELS = [label for group in GROUPS.values() for label in group]
assert len(LABELS) == 25 and N <= set(LABELS)


def path(*parts):
    return os.path.join(ROOT, *parts)


def load_calls():
    """file id -> located LLM calls of the file with the labeled placeholder instances at each call."""
    return json.load(open(path('data', 'rq2_llm_calls.json'), encoding='utf-8'))


def load_pairs():
    """The 353 (placeholder x sink) pairs with ground truth and consensus labels."""
    file_id = {f['file_key']: fid for fid, f in load_calls().items()}
    pairs = json.load(open(path('data', 'eval62_pairs.json'), encoding='utf-8'))
    for p in pairs:
        p['file_id'] = file_id[p['file_key']]
        p['sink_line'] = int(p['sink_line'])
    assert len(pairs) == 353
    return pairs


def instances(call, placeholder):
    return [i for i in call['instances'] if i['placeholder'] == placeholder]


def own_calls(file_calls, placeholder):
    """The LLM calls that the placeholder enters, i.e., at which a labeled instance of it is recorded."""
    return [c for c in file_calls['llm_calls'] if instances(c, placeholder)]


def read_predictions(name):
    """predictions/<name>.csv -> {column: {gt_index: value}}"""
    out = {}
    with open(path('predictions', name + '.csv'), newline='', encoding='utf-8') as fh:
        for row in csv.DictReader(fh):
            for column, value in row.items():
                if column != 'gt_index':
                    out.setdefault(column, {})[row['gt_index']] = value
    return out


def write_predictions(name, pairs, columns):
    """columns: {column: {gt_index: value}}; one row per pair, in the order of the pairs."""
    with open(path('predictions', name + '.csv'), 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(['gt_index'] + list(columns))
        for p in pairs:
            w.writerow([p['gt_index']] + [columns[c][p['gt_index']] for c in columns])


def prf(pred, pairs):
    """pred: {gt_index: 'yes' | 'no'} -> precision, recall, F1 (percent), TP, FP, FN against the ground truth."""
    tp = sum(p['ground_truth'] == 'yes' and pred[p['gt_index']] == 'yes' for p in pairs)
    fp = sum(p['ground_truth'] == 'no' and pred[p['gt_index']] == 'yes' for p in pairs)
    fn = sum(p['ground_truth'] == 'yes' and pred[p['gt_index']] != 'yes' for p in pairs)
    precision = 100.0 * tp / (tp + fp) if tp + fp else 0.0
    recall = 100.0 * tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1, tp, fp, fn
