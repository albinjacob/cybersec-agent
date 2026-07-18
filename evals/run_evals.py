"""
Evals runner - two independent measurements against the golden cases in
evals/golden_cases.py:

1. Retrieval quality (deterministic, no LLM, always runs): precision@1 /
   recall@3 of the Policy Checker's real retrieval path against known-correct
   NIST 800-53 control families.
2. Reasoning quality (LLM-as-judge): a second, independent `reason()` call
   grades an agent-style summary 1-5 on faithfulness and relevance, repeated
   3x per case to report a mean and a consistency (stddev) signal.

Callable from the Gradio "Run Evals" button (progress_cb reports mini
progress lines) or from a plain `python -m evals.run_evals` CLI invocation.
"""

import re
import statistics
from datetime import datetime, timezone

from agents import policy_checker
from agents.llm import reason
from . import golden_cases

CONTROL_ID_RE = re.compile(r"NIST SP 800-53 - ([A-Z]+-\d+(?:\.\d+)?)")
SCORE_RE = re.compile(r"FAITHFULNESS:\s*(\d)\D*RELEVANCE:\s*(\d)", re.IGNORECASE | re.DOTALL)

_SUMMARY_SYSTEM_PROMPT = (
    "You are an incident response lead. Given a list of security findings, write a "
    "clear, executive-readable 2-4 sentence summary."
)
_JUDGE_SYSTEM_PROMPT = (
    "You are grading an AI-written incident summary against a rubric. Score it 1-5 on "
    "FAITHFULNESS (did it only state facts present in the findings, no invented details) "
    "and 1-5 on RELEVANCE (does it satisfy the rubric below). Respond in EXACTLY this format:\n"
    "FAITHFULNESS: <n>\nRELEVANCE: <n>\nREASON: <one sentence>"
)


def _matches_expected(control_id, expected_prefixes):
    """`expected_prefixes` names control *families* (e.g. "AC-6"). A retrieved
    control can be the family itself or one of its numbered enhancements
    (e.g. "AC-6.10") - both are a correct family match. Exact-string equality
    would wrongly mark "AC-6.10" as a miss against expected "AC-6"."""
    return any(control_id == p or control_id.startswith(p + ".") for p in expected_prefixes)


def _retrieve_control_ids(index, query, min_score):
    results = index.retrieve(query, top_k=3, min_score=min_score)
    ids = []
    for chunk_text, _score, _source in results:
        m = CONTROL_ID_RE.search(chunk_text)
        if m:
            ids.append(m.group(1))
    return ids


def run_retrieval_eval():
    index, embedding_mode, fallback_reason = policy_checker._get_index(policy_checker.DEFAULT_POLICY_PATH)
    min_score = (policy_checker.EMBEDDING_MIN_SCORE if embedding_mode == "embeddings"
                 else policy_checker.TFIDF_MIN_SCORE)

    cases = []
    hits_at_1 = 0
    hits_at_3 = 0
    for case in golden_cases.RETRIEVAL_CASES:
        retrieved = _retrieve_control_ids(index, case["finding_text"], min_score)
        top1_hit = bool(retrieved) and _matches_expected(retrieved[0], case["expected_prefixes"])
        any_hit = any(_matches_expected(r, case["expected_prefixes"]) for r in retrieved)
        hits_at_1 += int(top1_hit)
        hits_at_3 += int(any_hit)
        cases.append({
            "finding_text": case["finding_text"],
            "note": case["note"],
            "expected": case["expected_prefixes"],
            "retrieved": retrieved,
            "top1_hit": top1_hit,
            "any_hit": any_hit,
        })

    n = len(golden_cases.RETRIEVAL_CASES) or 1
    return {
        "embedding_mode": embedding_mode,
        "embedding_fallback_reason": fallback_reason,
        "precision_at_1": hits_at_1 / n,
        "recall_at_3": hits_at_3 / n,
        "cases": cases,
    }


def _mock_case_summary(findings):
    if not findings:
        return "No issues were found in the analyzed inputs."
    lines = [f"- [{f.get('severity')}] {f.get('detail')}" for f in findings]
    return "Findings:\n" + "\n".join(lines)


def _score_case(case, repeats=3):
    findings = case["findings"]
    user_prompt = f"Findings:\n{findings}"
    scores = []
    reasoning_mode = None
    last_summary = None
    last_judge_reason = None
    for _ in range(repeats):
        summary, mode = reason(_SUMMARY_SYSTEM_PROMPT, user_prompt,
                                mock_fn=lambda: _mock_case_summary(findings))
        reasoning_mode = mode
        last_summary = summary
        if mode == "mock":
            # A deterministic mock summary can't be meaningfully judged by a
            # live model - record a neutral score and say so plainly, rather
            # than silently skipping this case.
            scores.append((3, 3))
            last_judge_reason = "No live model configured - mock summary was not independently judged."
            continue
        judge_prompt = f"Rubric: {case['rubric']}\n\nFindings:\n{findings}\n\nSummary to grade:\n{summary}"
        judge_text, judge_mode = reason(_JUDGE_SYSTEM_PROMPT, judge_prompt)
        m = SCORE_RE.search(judge_text)
        scores.append((int(m.group(1)), int(m.group(2))) if m else (3, 3))
        last_judge_reason = judge_text
    faithfulness = [s[0] for s in scores]
    relevance = [s[1] for s in scores]
    return {
        "name": case["name"],
        "rubric": case["rubric"],
        "reasoning_mode": reasoning_mode,
        "faithfulness_mean": statistics.mean(faithfulness),
        "faithfulness_stddev": statistics.pstdev(faithfulness) if len(faithfulness) > 1 else 0.0,
        "relevance_mean": statistics.mean(relevance),
        "relevance_stddev": statistics.pstdev(relevance) if len(relevance) > 1 else 0.0,
        "sample_summary": last_summary,
        "judge_reason": last_judge_reason,
    }


def run_reasoning_eval(progress_cb=None):
    cases = []
    total = len(golden_cases.REASONING_CASES)
    for i, case in enumerate(golden_cases.REASONING_CASES):
        if progress_cb:
            progress_cb(f"Scoring reasoning case {i + 1}/{total}: {case['name']}")
        cases.append(_score_case(case))
    n = len(cases) or 1
    return {
        "faithfulness_mean": sum(c["faithfulness_mean"] for c in cases) / n,
        "relevance_mean": sum(c["relevance_mean"] for c in cases) / n,
        "reasoning_mode": cases[0]["reasoning_mode"] if cases else "mock",
        "cases": cases,
    }


def run_all(progress_cb=None):
    """Returns one structured run_record dict - what gets persisted and rendered."""
    if progress_cb:
        progress_cb("Running retrieval precision/recall against the policy corpus...")
    retrieval = run_retrieval_eval()
    reasoning = run_reasoning_eval(progress_cb=progress_cb)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "retrieval": retrieval,
        "reasoning": reasoning,
    }


if __name__ == "__main__":
    record = run_all(progress_cb=print)
    print(f"\nRetrieval precision@1: {record['retrieval']['precision_at_1']:.2f} "
          f"(mode: {record['retrieval']['embedding_mode']})")
    print(f"Reasoning faithfulness mean: {record['reasoning']['faithfulness_mean']:.2f} "
          f"(mode: {record['reasoning']['reasoning_mode']})")
