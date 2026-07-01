"""RQ2 evaluation: LLM Code and PRISM methods on the 353-pair evaluation set.
Usage: python3 run_rq2_methods.py <b_gpt|b_claude|cplus> [analysis_model]
Checkpoint: table3_<method>.jsonl (resumable). Parallel + retry.
- b_gpt / b_claude: LLM Code baseline (source+prompt+output+sink) -> yes/no per pair.
- cplus: PRISM: taxonomy filter (consensus labels ∉ NON_PROP) + code-level analysis on source+sink.
"""
import os, sys, json, time, threading, urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = 'os.path.join(os.path.dirname(__file__), '..', 'data')'
METHOD = sys.argv[1]
VERIFIER = sys.argv[2] if len(sys.argv) > 2 else 'gemini-2.5-pro'
SET = os.getenv('SET', '863')
SUF = f'_{SET}' if SET != '863' else ''
CKPT = f'{BASE}/table3_cplus_{VERIFIER}{SUF}.jsonl' if METHOD == 'cplus' else f'{BASE}/table3_{METHOD}{SUF}.jsonl'
lock = threading.Lock()
NON_PROP = {"Ignored", "Missing Context", "Missing Capabilities", "Policy Refusal"}
SRC_CAP = int(os.getenv('SRCCAP', '16000'))

data = json.load(open(f'{BASE}/table3_eval{SET}.json'))

def prompt_llm_code(p):
    # LLM Code baseline prompt. Two branches by sink presence.
    fc = str(p['source_code']); pt = str(p['prompt']); lo = str(p['output'])
    ph_name = p['placeholder_name']; ph_value = str(p.get('placeholder_value', ''));
    sink_line = p['sink_line']; sink_code = p.get('sink_code', ''); vuln_type = p.get('vuln_type', '')
    if not vuln_type or str(sink_line) == '0':
        return f"""You are a security researcher analyzing Python code for LLM-related vulnerabilities.

[SOURCE CODE]
{fc[:6000]}

[PROMPT TEMPLATE sent to LLM]
{pt[:2000]}

[LLM OUTPUT]
{lo[:2000]}

[PLACEHOLDER]
{ph_name} = {ph_value[:500]}

Question: Does this file contain a dangerous sink (exec, eval, subprocess, SQL execute, requests.get for SSRF, yaml.unsafe_load) that receives data from the LLM output, AND can an attacker controlling the placeholder "{ph_name}" influence the LLM output to reach that sink?

Answer with ONLY "yes" or "no". Nothing else."""
    return f"""You are a security researcher. Given the following Python source code, the prompt template used to call an LLM, and the actual LLM output, determine whether the placeholder can be exploited.

[SOURCE CODE]
{fc[:8000]}

[PROMPT TEMPLATE]
{pt[:3000]}

[LLM OUTPUT]
{lo[:2000]}

[PLACEHOLDER]
{ph_name} = {ph_value[:500]}

[DANGEROUS SINK]
Line {sink_line}: {sink_code} (type: {vuln_type})

Question: If an attacker fully controls the value of placeholder "{ph_name}", can attacker-influenced content propagate through the LLM's response and ultimately reach or influence the dangerous sink at line {sink_line}?

Consider:
- Does the placeholder carry attacker-controlled content into the LLM prompt?
- Does the LLM output flow to THIS SPECIFIC sink (not a different sink in the file)?
- Is the placeholder just a system prompt, format instruction, or server-side config (usually no)?
- Is the placeholder a user query, task, or data that shapes the LLM's code/SQL/command generation (usually yes)?

Answer with ONLY "yes" or "no". Nothing else."""

def prompt_prism_code_analysis(p):
    # PRISM code-level analysis prompt: source code + sink only, no prompt template or LLM output.
    return f"""You are a security researcher. Analyze this Python source code.

[SOURCE CODE]
{str(p['source_code'])}

[DANGEROUS SINK]
Line {p['sink_line']} (type: {p['vuln_type']})

Question: Can an attacker exploit the LLM API call's output to hijack the dangerous operation at line {p['sink_line']}?

Answer with ONLY "yes" or "no". Nothing else."""

def parse_yn(t):
    t = (t or '').strip().lower()
    if t.startswith('yes'): return 'yes'
    if t.startswith('no'): return 'no'
    if 'yes' in t[:20] and 'no' not in t[:20]: return 'yes'
    if 'no' in t[:20] and 'yes' not in t[:20]: return 'no'
    return None

def call_gpt(prompt):
    # THINKING ON: gpt-5.5 high reasoning effort
    from openai import OpenAI
    c = OpenAI(api_key=os.environ['OPENAI_API_KEY'])
    r = c.responses.create(model='gpt-5.5', input=prompt, reasoning={'effort': 'high'}, max_output_tokens=8000)
    return parse_yn(r.output_text)

def call_claude(prompt):
    # THINKING ON: claude-opus-4-8 adaptive thinking, high effort (new API format)
    body = json.dumps({'model': 'claude-opus-4-8', 'max_tokens': 12000,
                       'thinking': {'type': 'adaptive'}, 'output_config': {'effort': 'high'},
                       'messages': [{'role': 'user', 'content': prompt}]}).encode()
    req = urllib.request.Request('https://api.anthropic.com/v1/messages', method='POST', data=body,
        headers={'content-type': 'application/json', 'x-api-key': os.environ['ANTHROPIC_API_KEY'], 'anthropic-version': '2023-06-01'})
    d = json.loads(urllib.request.urlopen(req, timeout=300).read())
    return parse_yn('\n'.join(b.get('text', '') for b in d.get('content', []) if b.get('type') == 'text'))

def call_deepseek(prompt):
    # THINKING ON: deepseek-reasoner (final answer in content, reasoning in reasoning_content)
    from openai import OpenAI
    c = OpenAI(api_key=os.environ['DEEPSEEK_API_KEY'], base_url='https://api.deepseek.com')
    r = c.chat.completions.create(model='deepseek-reasoner', messages=[{'role': 'user', 'content': prompt}], max_tokens=4000, timeout=300)
    return parse_yn(r.choices[0].message.content)

def call_gemini(prompt):
    # THINKING ON by default for gemini-3.1-pro; qingyun proxy native generateContent endpoint
    model = VERIFIER if VERIFIER.startswith('gemini') else 'gemini-3.1-pro-preview'
    url = f'https://GEMINI_API_PROXY/v1beta/models/{model}:generateContent?key={os.environ["GEMINI_API_KEY"]}'
    body = json.dumps({'contents': [{'parts': [{'text': prompt}]}],
                       'generationConfig': {'maxOutputTokens': 12000}}).encode()
    req = urllib.request.Request(url, method='POST', data=body, headers={'content-type': 'application/json'})
    d = json.loads(urllib.request.urlopen(req, timeout=300).read())
    parts = d['candidates'][0].get('content', {}).get('parts', [])
    return parse_yn('\n'.join(p.get('text', '') for p in parts if 'text' in p))

def call_qwen(prompt):
    # qwen3.7-plus via qingyun OpenAI-compatible endpoint
    from openai import OpenAI
    c = OpenAI(api_key=os.environ['QWEN_API_KEY'], base_url='https://QWEN_API_PROXY/v1')
    r = c.chat.completions.create(model='qwen3.7-plus', messages=[{'role': 'user', 'content': prompt}], max_tokens=4000, timeout=300)
    m = r.choices[0].message
    return parse_yn(m.content or getattr(m, 'reasoning_content', '') or '')

VERIF_CALL = {'gpt': call_gpt, 'claude': call_claude, 'deepseek': call_deepseek, 'gemini': call_gemini, 'qwen': call_qwen}
CALLER = {'b_gpt': call_gpt, 'b_claude': call_claude, 'b_deepseek': call_deepseek, 'b_gemini': call_gemini, 'b_qwen': call_qwen}.get(METHOD) or VERIF_CALL[VERIFIER if VERIFIER in VERIF_CALL else ('gemini' if VERIFIER.startswith('gemini') else VERIFIER)]

def retry(fn, arg):
    for k in range(4):
        try:
            v = fn(arg)
            if v is not None: return v
        except Exception as e:
            last = str(e)[:80]
        time.sleep(min(30, 3 * 2 ** k))
    return None

def main():
    done = {}
    if os.path.exists(CKPT):
        for l in open(CKPT):
            try: r = json.loads(l); done[r['gt_index']] = r
            except: pass
    todo = []
    for i, p in enumerate(data):
        gi = p.get('gt_index', i)
        if gi in done: continue
        if METHOD == 'cplus':
            # Taxonomy filter: blocked if ALL consensus labels in NON_PROP
            non_blocked = bool(set(p['consensus_labels']) - NON_PROP)
            if not non_blocked:
                with lock: open(CKPT, 'a').write(json.dumps({'gt_index': gi, 'pred': 'no', 'stage': 'taxonomy_filter_blocked'}) + '\n')
                continue
        todo.append((gi, p))
    P = int(os.getenv('PAR', '8'))
    print(f"method={METHOD} model={VERIFIER if METHOD=='cplus' else '-'} todo={len(todo)} done={len(done)} P={P}", flush=True)
    t0 = time.time(); c = [0]
    def work(item):
        gi, p = item
        pr = prompt_prism_code_analysis(p) if METHOD == 'cplus' else prompt_llm_code(p)
        v = retry(CALLER, pr)
        with lock: open(CKPT, 'a').write(json.dumps({'gt_index': gi, 'pred': v, 'stage': 'code_analysis' if METHOD == 'cplus' else 'llm_code'}) + '\n')
        c[0] += 1
        if c[0] % 25 == 0:
            el = time.time() - t0; rate = c[0] / el
            print(f"  {c[0]}/{len(todo)} | {rate*60:.1f}/min | ETA {(len(todo)-c[0])/rate/60:.1f}min", flush=True)
    with ThreadPoolExecutor(max_workers=P) as ex: list(ex.map(work, todo))
    print(f"DONE {METHOD} {len(todo)} in {(time.time()-t0)/60:.1f}min", flush=True)

if __name__ == '__main__':
    main()
