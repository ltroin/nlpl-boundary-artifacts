# PRISM Artifacts

Replication package for "Where Code Meets Natural Language: Taxonomy-Driven Information Flow Analysis for LLM-Integrated Applications."

## Directory Structure

```
data/
  taxonomy_labeled_dataset.json    8,119 pairs with 3-model consensus labels (RQ1)
  eval62_pairs.json                353 pairs from 62 sink-containing files (RQ2)
  openclaw_eval_pairs.json         12 pairs from 6 OpenClaw CVEs (RQ2)
  openclaw_eval_results.json       Propagate All / LLM Code / PRISM results on OpenClaw

annotations/
  expert_{a,b,c}_annotations.csv   3 independent reviewer verdicts on 165 pairs from 22 vulnerable files
  consensus_v4.csv                 Majority-vote consensus (the remaining 188 pairs from 40 non-vulnerable files are deterministically NO since no sink is reachable)

predictions/
  table3_summary.csv               Summary metrics matching Table V
  b_{gpt,claude,deepseek,qwen}.csv LLM Code per-pair predictions
  cplus_{gpt,claude,deepseek,qwen}.csv  PRISM per-pair predictions

slicing/
  queries/FullSliceFromLlmInput.ql CodeQL full backward slice query
  queries/PropSliceFinal.ql        CodeQL taxonomy-informed slice query (barriers from consensus labels)
  full_slice_ctrl.csv              Full-slice CodeQL results (295 files)
  prop_slice_final.csv             Taxonomy-informed slice CodeQL results
  slice_reduction_clean_final.json Computed reduction metrics

scripts/
  consensus_labeling.py            3-model cross-family consensus protocol
  run_rq2_methods.py               LLM Code and PRISM evaluation on 353 pairs
  run_openclaw_eval.py             OpenClaw cross-language validation
```

## Key Numbers

| Metric | Value | Source |
|--------|-------|--------|
| Labeled pairs | 8,119 | `data/taxonomy_labeled_dataset.json` |
| Labels | 25 (8 groups) | ibid. |
| Unclassifiable | 0 (0%) | ibid. |
| Fleiss' kappa (3 models) | 0.77 | ibid. |
| Fleiss' kappa (5 raters) | 0.72 | ibid. |
| RQ2 eval pairs | 353 (110 YES / 243 NO) | `data/eval62_pairs.json` |
| PRISM F1 (best) | 81.7% | `predictions/table3_summary.csv` |
| OpenClaw PRISM F1 | 100% | `data/openclaw_eval_results.json` |
| Slicing reduction | 23.1% (14 affected files) | `slicing/slice_reduction_clean_final.json` |

## Data Collection

Callsite reconstruction and output generation were performed by a program-analysis agent built on GPT-5.2 Thinking. The agent locates LLM callsites, identifies placeholders, infers plausible runtime values, reconstructs fully rendered prompts, and executes them to generate outputs.

## Consensus Labeling

Labels are produced by a 3-model cross-family protocol (`scripts/consensus_labeling.py`):
1. GPT-5.5, Claude-Opus-4.8, DeepSeek-v4 independently label each pair
2. Up to 3 discussion rounds where each model sees peers' labels and justifications
3. Final consensus = labels endorsed by at least 2 of the 3 models (majority overlap)

## Prompts

### Taxonomy Labeling (System Prompt)

The system prompt contains the complete taxonomy definition: all 25 labels with their names, descriptions, inclusion criteria, exclusion criteria, and distinguishing examples. The full system prompt is in `scripts/consensus_labeling.py`.

### Taxonomy Labeling (User Prompt)

Each callsite is presented in three sections:

```
[PLACEHOLDERS]
{placeholders_json}

[RENDERED PROMPT]
{rendered_prompt}

[MODEL OUTPUT]
{model_output}
```

### LLM Code Prediction Prompt

```
You are a security researcher. Given the following Python source code,
the prompt template used to call an LLM, and the actual LLM output,
determine whether the placeholder can be exploited.

[SOURCE CODE] {file_contents}
[PROMPT TEMPLATE] {prompt_template}
[LLM OUTPUT] {output}
[PLACEHOLDER] {ph_name} = {ph_value}
[DANGEROUS SINK] Line {sink_line}: {sink_code} (type: {vuln_type})

Question: If an attacker fully controls "{ph_name}", can attacker-influenced
content propagate through the LLM's response and reach the dangerous sink
at line {sink_line}?
Consider: Does the LLM output flow to THIS SPECIFIC sink?
Answer with ONLY "yes" or "no". Nothing else.
```

### PRISM Code-Level Analysis Prompt

```
You are a security researcher. Analyze this Python source code.

[SOURCE CODE] {file_contents}
[DANGEROUS SINK] Line {sink_line} (type: {vuln_type})

Question: Can an attacker exploit the LLM API call's output to hijack
the dangerous operation at line {sink_line}?
Answer with ONLY "yes" or "no". Nothing else.
```

## RQ3 Reproducibility

The backward slicing experiment uses CodeQL. The two queries in `slicing/queries/` can be run on any CodeQL Python database built from the source files:

1. `FullSliceFromLlmInput.ql` computes the full backward slice from LLM call arguments (no barriers).
2. `PropSliceFinal.ql` computes the same slice with `isBarrier` predicates derived from the consensus taxonomy labels for non-propagating placeholder variables.

The difference between the two CSV outputs gives the slice reduction. `slice_reduction_clean_final.json` contains the pre-computed metrics.

## API Dependencies

LLM-based methods (LLM Code, PRISM code-level analysis) require API access to OpenAI, Anthropic, DeepSeek, or Qwen. All pre-computed results are included. API access is only needed for re-running predictions.
