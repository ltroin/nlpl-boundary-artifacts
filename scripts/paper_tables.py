#!/usr/bin/env python3
"""Prints the tables of the paper that follow directly from the data files of the package.

  1. Label distribution over the 8,119 pairs (RQ1)                 data/taxonomy_labeled_dataset.json
  2. The RQ2 sample: sizes, vulnerability types, and the
     correlation of its label distribution with that of the corpus  data/eval62_pairs.json
  3. Per-label propagation rates (RQ2)                             data/eval62_pairs.json
  4. Backward slicing (RQ3)                                        slicing/

The taint-analysis table of RQ2 is printed by scripts/rq2_table5.py.
Usage: python3 scripts/paper_tables.py
Standard library only.
"""
import collections
import csv
import json
import math
import os
import re
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import rq2_data as D  # noqa: E402

TYPES = [('code-injection', 'Code injection', 'CWE-94'), ('sql-injection', 'SQL injection', 'CWE-89'),
         ('command-injection', 'Command injection', 'CWE-78'), ('ssrf', 'SSRF', 'CWE-918'),
         ('unsafe-deserialization', 'Unsafe deserialization', 'CWE-502')]
# the labels of the per-label table, in its order
PER_LABEL = ['CLI Commands', 'Code Snippet', 'Template Slotting', 'JSON-Only Template', 'Keyword Echo', 'Content Expansion',
             'Fragment Copy', 'Binary Decision', 'Category Label', 'Ignored', 'Paraphrase Rewrite', 'General Summarization']


def pearson(x, y):
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    return sum((a - mx) * (b - my) for a, b in zip(x, y)) / math.sqrt(sum((a - mx) ** 2 for a in x) * sum((b - my) ** 2 for b in y))


def frequencies(label_sets):
    count = collections.Counter(label for s in label_sets for label in set(s))
    assert set(count) <= set(D.LABELS), set(count) - set(D.LABELS)
    return [100.0 * count[label] / len(label_sets) for label in D.LABELS]


def label_distribution():
    corpus = json.load(open(D.path('data', 'taxonomy_labeled_dataset.json'), encoding='utf-8'))
    sets = [set(d['final_labels']) for d in corpus]
    count = collections.Counter(label for s in sets for label in s)
    print(f'1. Label distribution over {len(corpus):,} placeholder-output pairs (consensus labels)')
    for label, n in sorted(count.items(), key=lambda z: -z[1]):
        share = 100.0 * n / len(corpus)
        print(f'     {label:36s} {n:5,d}  ' + (f'{share:5.1f}%' if share >= 0.05 else ' <0.1%'))
    print(f'   pairs labeled Unclassifiable: {count["Unclassifiable"]}')
    print(f'   label assignments: {sum(len(s) for s in sets):,}; pairs with more than one label: {100.0 * sum(len(s) > 1 for s in sets) / len(sets):.1f}%')
    print(f'   pairs whose labels all lie in N (non-reachable): {100.0 * sum(s <= D.N for s in sets) / len(sets):.1f}%')
    return corpus


def rq2_sample(corpus):
    pairs = D.load_pairs()
    yes = [p for p in pairs if p['ground_truth'] == 'yes']
    files = {p['file_key'] for p in pairs}
    vulnerable = {p['file_key'] for p in yes}
    print()
    print(f'2. RQ2 sample: {len(pairs)} (placeholder x sink) pairs from {len(files)} files; {len(yes)} YES / {len(pairs) - len(yes)} NO; '
          f'{len(vulnerable)} files with a YES pair, {len(files - vulnerable)} without')
    print(f'     {"Vulnerability type":24s} {"CWE":8s} Files  YES pairs')
    for key, name, cwe in TYPES:
        print(f'     {name:24s} {cwe:8s} {len({p["file_key"] for p in yes if p["vuln_type"] == key}):5d}  {sum(p["vuln_type"] == key for p in yes):9d}')
    print(f'     {"Total":24s} {"":8s} {len(vulnerable):5d}  {len(yes):9d}')
    r = pearson(frequencies([d['final_labels'] for d in corpus]), frequencies([p['consensus_labels'] for p in pairs]))
    print(f'   Pearson r between the label frequencies of the {len(pairs)} pairs and of the {len(corpus):,} pairs of the corpus: {r:.2f}')
    return pairs


def per_label(pairs):
    count = collections.defaultdict(lambda: [0, 0])
    for p in pairs:
        for label in set(p['consensus_labels']):
            count[label][0 if p['ground_truth'] == 'yes' else 1] += 1
    print()
    print('3. Per-label propagation rates (share of the pairs with a label that are YES)')
    print(f'     {"Label":24s}   Y    N   Rate')
    for label in PER_LABEL:
        y, n = count[label]
        print(f'     {label:24s} {y:3d}  {n:3d}  {100.0 * y / (y + n):5.1f}%')


def slicing():
    csv.field_size_limit(10 ** 9)

    def lines(name):
        per_file = collections.defaultdict(set)
        with open(D.path('slicing', name), newline='', encoding='utf-8') as fh:
            for row in csv.reader(fh):
                per_file[row[4].lstrip('/')].add(int(row[5]))
        return per_file

    full, prop = lines('full_slice_ctrl.csv'), lines('prop_slice_final.csv')
    with_barriers = json.load(open(D.path('slicing', 'slice_reduction_clean_final.json'), encoding='utf-8'))['barrier_files']
    cut = {f: len(full[f]) - len(prop.get(f, ())) for f in full}
    reduced = {f: cut[f] / len(full[f]) for f in full if cut[f] > 0}
    print()
    print('4. Backward slicing: lines per file in the full slice and in the taxonomy-informed slice')
    print(f'     {"Scope":22s} Files  Mean reduction')
    print(f'     {"All files":22s} {len(full):5d}  {100.0 * sum(reduced.values()) / len(full):5.1f}%')
    print(f'     {"With barriers":22s} {with_barriers:5d}  {100.0 * sum(reduced.values()) / with_barriers:5.1f}%')
    print(f'     {"With >0 cut":22s} {len(reduced):5d}  {100.0 * sum(reduced.values()) / len(reduced):5.1f}%')
    print(f'   lines removed: {sum(c for c in cut.values() if c > 0)} in {len(reduced)} files')
    print(f'   top files by reduction:  {"":38s} Full  Prop   Cut  Reduction')
    for f in sorted(reduced, key=lambda f: -reduced[f])[:6]:
        print(f'     {f[-58:]:60s} {len(full[f]):4d}  {len(prop[f]):4d}  {cut[f]:4d}  {100.0 * reduced[f]:5.1f}%')
    print(f'   the two slicing queries differ only in the isBarrier predicate: {same_query()}')


def same_query():
    """slicing/queries: the taxonomy-informed query is the full-slice query plus the isBarrier predicate."""
    def body(name):
        text = open(D.path('slicing', 'queries', name), encoding='utf-8').read()
        text = text[text.index('\nimport python'):]  # the code below the header comment
        text = re.sub(r'\n  predicate isBarrier\(DataFlow::Node node\) \{.*?\n  \}\n', '\n', text, flags=re.S)
        return [line for line in text.split('\n') if line.strip()]
    return body('FullSliceFromLlmInput.ql') == body('PropSliceConsensus.ql')


def main():
    corpus = label_distribution()
    pairs = rq2_sample(corpus)
    per_label(pairs)
    slicing()


if __name__ == '__main__':
    main()
