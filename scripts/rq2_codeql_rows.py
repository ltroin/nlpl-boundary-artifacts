#!/usr/bin/env python3
"""The five CodeQL rows of the taint-analysis table (RQ2): conventional CodeQL, CodeQL with conservative
propagation across LLM calls, CodeQL with a binary label, CodeQL with the eight groups, and CodeQL augmented with PRISM.

Inputs
  data/eval62_pairs.json        the 353 pairs with ground truth
  data/rq2_llm_calls.json       located LLM calls of the 62 files and the labeled placeholder instances at each call
  codeql/results/*.csv          results of the three queries in codeql/queries
Output
  predictions/rq2_codeql.csv    one row per pair: the answers of the five rows and of the rule read with N and the
                                output modality only, whether R# marks the placeholder
                                reachable, how the pair is a candidate (traced, traced through a later LLM call,
                                or assumed), and, for a YES pair that CodeQL + PRISM misses, the reason

How a pair (placeholder p, sink s of type t) is decided

  Path of p.  The LLM calls that p enters, and the later LLM calls into whose prompt CodeQL traces the output
  of a call already on the path (the labels are applied at each call in sequence).
  Traced.  CodeQL traces the output of a call on the path into the sink (query LlmOutputToSink).
  Unconnected sink.  An injection or deserialization sink into which CodeQL traces no LLM output of the file
  at all (query LlmOutputToLine).

  Conventional CodeQL        CodeQL's own taint tracking finds a path from a line where p is inserted into a
                             prompt to the sink (query ConventionalTaint). The LLM calls have no summary.
  Conservative propagation   Every placeholder passes every LLM call. The pair is reported if it is traced or if
                             the sink is unconnected.
  CodeQL + binary label      A binary reachable/non-reachable label decides every candidate: a pair that is traced
                             or whose sink is unconnected is reported unless all labels of p lie in N. A later
                             call joins the path only through a reachable placeholder.
  CodeQL + PRISM             Traced: the program passes the output to the sink, and R# decides, i.e., the pair
                             is reported unless all labels of p lie in the non-reachable set N. A later call
                             joins the path only through a placeholder that is reachable under R#.
                             Unconnected sink: the pair is reported only if the labels show that the LLM emits
                             an executable artifact and that p contributes content to the output.
                             Otherwise the pair is not reported.
  CodeQL + eight groups      The rule of CodeQL + PRISM with every label replaced by its group, in the labels
                             of the placeholders and in the label sets that the rule reads.
  N and the output modality  The rule of CodeQL + PRISM without the content condition: at an unconnected sink the
                             pair is reported if the LLM emits an executable artifact and p is reachable under R#.

The label set of a placeholder is the union of the label sets of its instances at the calls it enters.
In the terms of Eq. (3) of the paper, the calls on the path of p give O(p), CONTENT is the admissible set of
the preservation dimension, and EXECUTABLE_ARTIFACT is the admissible set of the output modality.

Usage: python3 scripts/rq2_codeql_rows.py
Standard library only.
"""
import collections
import csv
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import rq2_data as D  # noqa: E402

EXECUTING_SINKS = {'sql-injection', 'code-injection', 'command-injection', 'unsafe-deserialization'}
EXECUTABLE_ARTIFACT = {'Code Snippet', 'CLI Commands'}          # labels of the output modality that such a sink runs
CONTENT = set(D.GROUPS['Verbatim']) | set(D.GROUPS['Rewrite']) | set(D.GROUPS['Generation'])
GROUP = {label: group for group, labels in D.GROUPS.items() for label in labels}

CANDIDATE_TRACED = 'traced'                                   # from a call that the placeholder enters
CANDIDATE_CHAIN = 'traced through a later LLM call'
CANDIDATE_ASSUMED = 'assumed'                                 # unconnected sink

MISS_OTHER_CALL = 'not a candidate: the sink is fed by another LLM call'
MISS_SAME_CALL = 'not a candidate: LLM call and sink in one framework call'
MISS_OTHER = 'not a candidate: other'
MISS_IN_N = 'labels entirely in N'
MISS_UNCONFIRMED = 'labels do not confirm the flow'


def read_flows(name):
    """codeql/results/<name>.csv -> {file id: {(source line, target line)}}"""
    flows = collections.defaultdict(set)
    with open(D.path('codeql', 'results', name + '.csv'), newline='', encoding='utf-8') as fh:
        for row in csv.DictReader(fh):
            flows[row['file'][:-3]].add((int(row['source_line']), int(row['target_line'])))
    return flows


def as_groups(labels):
    """Every label replaced by its group."""
    return {GROUP[label] for label in labels}


def path_of(by_id, start, to_sink, gate):
    """The calls in `start` and the later calls fed by them; a call joins through a placeholder slot that passes `gate`."""
    seen, todo = set(start), list(start)
    while todo:
        outputs = by_id[todo.pop()]['call_lines']
        for call_id, call in by_id.items():
            if call_id not in seen and any(gate(call, q) and any((x, n) in to_sink for x in outputs for n in lines)
                                           for q, lines in call['slot_lines'].items()):
                seen.add(call_id)
                todo.append(call_id)
    return [by_id[c] for c in by_id if c in seen]


def decide(pair, file_calls, to_sink, to_line, conventional):
    p, s, t = pair['placeholder_name'], pair['sink_line'], pair['vuln_type']
    by_id = {c['call_id']: c for c in file_calls['llm_calls']}
    own = D.own_calls(file_calls, p)
    labels = {label for c in own for i in D.instances(c, p) for label in i['labels']}
    reachable = not own or bool(labels - D.N)                                          # R# (Def. 5)

    start = [c['call_id'] for c in own]
    path_all = path_of(by_id, start, to_sink, lambda call, q: True)
    traced_all = any((x, s) in to_sink for c in path_all for x in c['call_lines'])
    unconnected = t in EXECUTING_SINKS and not any((x, s) in to_line for c in file_calls['llm_calls'] for x in c['call_lines'])

    def refined(view, sink_aware=True, content=True):
        """The rule of CodeQL + PRISM on what `view` shows of the labels: the labels themselves, or their groups.
        Without the sink-aware part, the binary reachable/non-reachable label decides every candidate.
        Without the content condition, the rule reads N and the output modality only."""
        non_reachable, artifact, content_labels = view(D.N), view(EXECUTABLE_ARTIFACT), view(CONTENT)

        def reachable_at(call, q):   # a placeholder without a recorded instance counts as reachable
            inst = D.instances(call, q)
            return not inst or any(view(i['labels']) - non_reachable for i in inst)
        path = path_of(by_id, start, to_sink, reachable_at)
        if any((x, s) in to_sink for c in path for x in c['call_lines']):          # traced
            return not own or bool(view(labels) - non_reachable)
        if unconnected and not sink_aware:
            return not own or bool(view(labels) - non_reachable)
        if unconnected:
            contributes = bool(view(labels) & content_labels) if content else (not own or bool(view(labels) - non_reachable))
            return any(view(i['labels']) & artifact for c in path for i in c['instances']) and contributes
        return False

    conservative = traced_all or unconnected
    own_traced = any((x, s) in to_sink for c in own for x in c['call_lines'])
    candidate = (CANDIDATE_TRACED if own_traced else CANDIDATE_CHAIN) if traced_all else CANDIDATE_ASSUMED if unconnected else ''
    prism, eight_groups, binary_label = refined(set), refined(as_groups), refined(set, sink_aware=False)
    n_and_modality = refined(set, content=False)
    conv = any((n, s) in conventional for c in own for n in c['slot_lines'].get(p, []))

    miss = ''
    if pair['ground_truth'] == 'yes' and not prism:
        if not conservative:
            if any((x, s) in to_sink for c in file_calls['llm_calls'] for x in c['call_lines']):
                miss = MISS_OTHER_CALL
            elif any(s in c['call_lines'] for c in file_calls['llm_calls']):
                miss = MISS_SAME_CALL
            else:
                miss = MISS_OTHER
        elif not reachable:
            miss = MISS_IN_N
        else:
            miss = MISS_UNCONFIRMED
    yn = lambda b: 'yes' if b else 'no'  # noqa: E731
    return {'conventional_codeql': yn(conv), 'codeql_conservative': yn(conservative), 'codeql_binary_label': yn(binary_label),
            'codeql_eight_groups': yn(eight_groups), 'codeql_prism': yn(prism), 'codeql_n_and_modality': yn(n_and_modality),
            'rsharp_reachable': yn(reachable), 'candidate': candidate, 'miss': miss}


def main():
    pairs, calls = D.load_pairs(), D.load_calls()
    to_sink, to_line, conventional = read_flows('llm_output_to_sink'), read_flows('llm_output_to_line'), read_flows('conventional_taint')
    rows = {p['gt_index']: decide(p, calls[p['file_id']], to_sink[p['file_id']], to_line[p['file_id']], conventional[p['file_id']]) for p in pairs}
    columns = ['conventional_codeql', 'codeql_conservative', 'codeql_binary_label', 'codeql_eight_groups', 'codeql_prism',
               'codeql_n_and_modality', 'rsharp_reachable', 'candidate', 'miss']
    D.write_predictions('rq2_codeql', pairs, {c: {k: r[c] for k, r in rows.items()} for c in columns})

    yes = sum(p['ground_truth'] == 'yes' for p in pairs)
    print(f'{len(pairs)} pairs ({yes} YES / {len(pairs) - yes} NO) from {len({p["file_id"] for p in pairs})} files')
    print(f'{"Approach":34s}  Prec.    Rec.     F1      TP   FP   FN')
    for name, column in (('Conventional CodeQL', 'conventional_codeql'), ('CodeQL, conservative propagation', 'codeql_conservative'),
                         ('CodeQL + binary label', 'codeql_binary_label'), ('CodeQL + eight groups', 'codeql_eight_groups'),
                         ('CodeQL + PRISM', 'codeql_prism')):
        p, r, f, tp, fp, fn = D.prf({k: row[column] for k, row in rows.items()}, pairs)
        print(f'{name:34s} {p:5.1f}%  {r:5.1f}%  {f:5.1f}%   {tp:4d} {fp:4d} {fn:4d}')


if __name__ == '__main__':
    main()
