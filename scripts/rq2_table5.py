#!/usr/bin/env python3
"""Prints the taint-analysis table of RQ2 (353 pairs, 110 YES / 243 NO) and the counts that the text derives
from it, from the per-pair predictions in predictions/.

  predictions/rq2_codeql.csv         conventional CodeQL, CodeQL with conservative propagation, CodeQL + binary label,
                                     CodeQL + eight groups, CodeQL + PRISM
                                     (written by scripts/rq2_codeql_rows.py)
  predictions/rq2_classifiers.csv    CodeBERT, random forest, 5-nearest neighbors
  predictions/rq2_llm_baseline.csv   direct LLM baseline, three models

Usage: python3 scripts/rq2_table5.py
Standard library only.
"""
import collections
import math
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import rq2_data as D  # noqa: E402

LLM = [('GPT-5.5', 'gpt-5.5'), ('Claude-Opus-4.8', 'claude-opus-4.8'), ('DeepSeek', 'deepseek')]


def wilson(k, n, z=1.959964):
    """95% Wilson score interval of k out of n, in percent."""
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return 100 * (centre - half), 100 * (centre + half)


def main():
    pairs = D.load_pairs()
    codeql, clf, llm = D.read_predictions('rq2_codeql'), D.read_predictions('rq2_classifiers'), D.read_predictions('rq2_llm_baseline')
    truth = {p['gt_index']: p['ground_truth'] for p in pairs}
    yes = sum(v == 'yes' for v in truth.values())

    llm_scores = {name: D.prf(llm[col], pairs) for name, col in LLM}
    llm_mean = tuple(sum(s[i] for s in llm_scores.values()) / len(llm_scores) for i in range(3))
    table = [('Conventional CodeQL', D.prf(codeql['conventional_codeql'], pairs)),
             ('CodeQL, conservative propagation', D.prf(codeql['codeql_conservative'], pairs)),
             ('CodeBERT', D.prf(clf['codebert'], pairs)),
             ('Random forest', D.prf(clf['random_forest'], pairs)),
             ('5-nearest neighbors (TF-IDF)', D.prf(clf['knn_tfidf'], pairs)),
             ('Direct LLM baseline (mean)', llm_mean + ('', '', '')),
             ('CodeQL + binary label', D.prf(codeql['codeql_binary_label'], pairs)),
             ('CodeQL + eight groups', D.prf(codeql['codeql_eight_groups'], pairs)),
             ('CodeQL + PRISM', D.prf(codeql['codeql_prism'], pairs))]

    print(f'Taint analysis on {len(pairs)} pairs ({yes} YES / {len(pairs) - yes} NO) from {len({p["file_id"] for p in pairs})} sink-containing files')
    print(f'{"Approach":34s}  Prec.    Rec.     F1      TP   FP   FN')
    for name, (p, r, f, tp, fp, fn) in table:
        print(f'{name:34s} {p:5.1f}%  {r:5.1f}%  {f:5.1f}%   {tp!s:>4} {fp!s:>4} {fn!s:>4}')
    print('Direct LLM baseline by model:')
    for name, (p, r, f, tp, fp, fn) in llm_scores.items():
        print(f'  {name:32s} {p:5.1f}%  {r:5.1f}%  {f:5.1f}%   {tp:4d} {fp:4d} {fn:4d}')

    f1 = {name: s[2] for name, s in table}
    trained = [s for name, s in table if name in ('CodeBERT', 'Random forest', '5-nearest neighbors (TF-IDF)')]
    best_llm = max(llm_scores, key=lambda n: llm_scores[n][2])
    print()
    print('Statements derived from the table')
    print(f'  CodeQL + PRISM has the highest F1 of the five approaches: {max(f1, key=f1.get) == "CodeQL + PRISM"} ({f1["CodeQL + PRISM"]:.1f}%).')
    print(f'  It is {f1["CodeQL + PRISM"] - f1["CodeQL, conservative propagation"]:.1f} points above CodeQL with conservative propagation '
          f'({f1["CodeQL, conservative propagation"]:.1f}%).')
    print(f'  The trained classifiers reach {min(s[2] for s in trained):.1f}-{max(s[2] for s in trained):.1f}% F1 and at most {max(s[0] for s in trained):.1f}% precision.')
    print(f'  The best single baseline run is the direct LLM baseline with {best_llm} ({llm_scores[best_llm][2]:.1f}% F1).')
    both = [name for name, s in table if s[0] >= 79.95 and s[1] >= 79.95]
    print(f'  Approaches that reach 80% on both precision and recall: {", ".join(both)}.')
    n_and_modality = D.prf(codeql['codeql_n_and_modality'], pairs)[2]
    print(f'  With a binary reachable/non-reachable label, the same analysis reaches {f1["CodeQL + binary label"]:.1f}% F1, and with every label replaced by its group '
          f'{f1["CodeQL + eight groups"]:.1f}%.')
    print(f'  With only N and the output modality, the same analysis reaches {n_and_modality:.1f}% F1.')

    cons = {k for k, v in codeql['codeql_conservative'].items() if v == 'yes'}
    prism = {k for k, v in codeql['codeql_prism'].items() if v == 'yes'}
    fp_cons = {k for k in cons if truth[k] == 'no'}
    tp_cons = {k for k in cons if truth[k] == 'yes'}
    print()
    print('CodeQL + PRISM against the conservative baseline, pair by pair')
    print(f'  The conservative baseline reports {len(cons)} pairs, CodeQL + PRISM {len(prism)}, all of them among the {len(cons)}: {prism <= cons}.')
    print(f'  The labels remove {len(fp_cons - prism)} of the {len(fp_cons)} false positives of the conservative baseline '
          f'and keep {len(tp_cons & prism)} of the {len(tp_cons)} YES pairs it reports.')
    traced = {k for k, v in codeql['candidate'].items() if v.startswith('traced')}
    assumed = {k for k, v in codeql['candidate'].items() if v == 'assumed'}
    assert traced | assumed == cons and not traced & assumed

    def yes_no(ks):
        return f'{len(ks)} pairs ({sum(truth[k] == "yes" for k in ks)} YES / {sum(truth[k] == "no" for k in ks)} NO)'
    print(f'  Of the {len(cons)} candidates, CodeQL traces the LLM output into the sink for {yes_no(traced)}, '
          f'and the path is assumed for {yes_no(assumed)}.')
    print(f'  Of the {len(tp_cons & prism)} YES pairs that CodeQL + PRISM reports, {len(tp_cons & prism & traced)} are traced and '
          f'{len(tp_cons & prism & assumed)} are among the assumed candidates.')
    binary = {k for k, v in codeql['codeql_binary_label'].items() if v == 'yes'}
    print(f'  Of these, the binary label removes {len(fp_cons - binary)} false positives and {len(tp_cons - binary)} YES pairs, '
          f'and the sink-aware refinement {len((fp_cons & binary) - prism)} false positives and {len((tp_cons & binary) - prism)} YES pairs.')
    miss = collections.Counter(v for v in codeql['miss'].values() if v)
    not_candidate = sum(n for reason, n in miss.items() if reason.startswith('not a candidate'))
    print()
    print(f'The {sum(miss.values())} YES pairs that CodeQL + PRISM misses')
    print(f'  {not_candidate:2d} are also missed by the conservative baseline')
    for reason, n in sorted(miss.items()):
        if reason.startswith('not a candidate'):
            print(f'       {n:2d} {reason[len("not a candidate: "):]}')
    print(f'  {miss["labels entirely in N"]:2d} placeholder labeled entirely inside N')
    in_n = [k for k, v in codeql['rsharp_reachable'].items() if v == 'no']
    yes_in_n = sum(truth[k] == 'yes' for k in in_n)
    low, high = wilson(yes_in_n, yes)
    print(f'       {yes_in_n} of the {yes} YES pairs = {100 * yes_in_n / yes:.1f}% (95% Wilson interval {low:.1f}-{high:.1f}%); '
          f'R# marks {len(in_n)} pairs non-reachable, {len(in_n) - yes_in_n} of them NO pairs')
    print(f'  {miss["labels do not confirm the flow"]:2d} CodeQL traces no path to the sink, and the labels do not confirm the candidate flow')
    chain = [k for k, v in codeql['candidate'].items() if v == 'traced through a later LLM call' and k in prism and truth[k] == 'yes']
    print()
    print('Chains of LLM calls')
    print(f'  {len(chain)} of the reported YES pairs are traced only through a later LLM call.')
    print(f'  {miss["not a candidate: the sink is fed by another LLM call"]} of the missed YES pairs have a sink that is fed by another LLM call '
          f'which CodeQL does not connect to the call of the placeholder.')


if __name__ == '__main__':
    main()
