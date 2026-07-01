#!/usr/bin/env python3
"""
OpenClaw Case Study Evaluation: Propagate All, LLM Code, PRISM on 6 CVE cases (12 pairs).
Prompts match eval62 exactly. Run LLM Code / PRISM via Claude Opus 4.6 Agent subagents.
"""
import json

PAIRS_FILE = "data/openclaw_eval_pairs.json"
OUTPUT_FILE = "data/openclaw_eval_results.json"

NON_PROP = {"Ignored", "Missing Context", "Missing Capabilities", "Policy Refusal"}


# ========== Prompt Builders — EXACT eval62 format ==========

def build_prompt_llm_code(pair):
    """LLM Code prompt. Only change: [SOURCE CODE] contains multiple files,
    each preceded by its full filepath on a separate line."""
    file_contents = pair['source_code']
    prompt_template = pair['user_message']
    llm_output = pair['llm_output']
    ph_name = pair['placeholder_name']
    ph_value = pair['placeholder_value']
    sink_line = pair['sink_line']
    sink_code = pair.get('sink_code', '')
    vuln_type = pair.get('vuln_type', '')

    return f"""You are a security researcher. Given the following Python source code, the prompt template used to call an LLM, and the actual LLM output, determine whether the placeholder can be exploited.

[SOURCE CODE]
{file_contents}

[PROMPT TEMPLATE]
{prompt_template}

[LLM OUTPUT]
{llm_output}

[PLACEHOLDER]
{ph_name} = {ph_value}

[DANGEROUS SINK]
Line {sink_line}: {sink_code} (type: {vuln_type})

Question: If an attacker fully controls the value of placeholder "{ph_name}", can attacker-influenced content propagate through the LLM's response and ultimately reach or influence the dangerous sink at line {sink_line}?

Consider:
- Does the placeholder carry attacker-controlled content into the LLM prompt?
- Does the LLM output flow to THIS SPECIFIC sink (not a different sink in the file)?
- Is the placeholder just a system prompt, format instruction, or server-side config (usually no)?
- Is the placeholder a user query, task, or data that shapes the LLM's code/SQL/command generation (usually yes)?

Answer with ONLY "yes" or "no". Nothing else."""



def build_prompt_prism_code_analysis(pair):
    """PRISM code-level analysis prompt: source code + sink only."""
    file_contents = pair['source_code']
    sink_line = pair['sink_line']
    vuln_type = pair.get('vuln_type', '')

    return f"""You are a security researcher. Analyze this Python source code.

[SOURCE CODE]
{file_contents}

[DANGEROUS SINK]
Line {sink_line} (type: {vuln_type})

Question: Can an attacker exploit the LLM API call's output to hijack the dangerous operation at line {sink_line}?

Answer with ONLY "yes" or "no". Nothing else."""


if __name__ == "__main__":
    with open(PAIRS_FILE) as f:
        pairs = json.load(f)

    print(f"Loaded {len(pairs)} pairs")

    # Print all prompts for agent evaluation
    for i, p in enumerate(pairs):
        print(f"\n{'='*60}")
        print(f"Pair {i}: {p['case_id']} {p['phase']} (gt={p['ground_truth']})")
        print(f"LLM Code prompt length:   {len(build_prompt_llm_code(p))} chars")
        if p['taxonomy_label'] not in NON_PROP:
            print(f"PRISM prompt length: {len(build_prompt_prism_code_analysis(p))} chars")
        else:
            print(f"PRISM: BLOCKED by taxonomy filter (label={p['taxonomy_label']})")
