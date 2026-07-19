"""
Model Council
-------------
For CRITICAL-severity findings only (the ones a reader is told to act on
first), get a second, genuinely independent model's opinion alongside the
primary one, then a third "judge" call that reconciles them into one final
recommendation. This is the "Model Council" pattern - independent answers +
a synthesizing judge - rather than asking a single model once and trusting it.

Needs two live models to mean anything, so it's a no-op (mode="skipped-mock")
whenever no API key is configured - there is no meaningful "council" over a
mock response.
"""

import re

from .llm import DEFAULT_MODELS, current_provider, reason

# A model distinct from DEFAULT_MODELS/whatever the user configured, per
# provider, so the two opinions are asked by genuinely different models
# rather than the same model twice.
SECOND_OPINION_MODELS = {
    "anthropic": "claude-haiku-4-5",
    "openai": "gpt-4o",
    "openrouter": "anthropic/claude-haiku-4.5",
}

_OPINION_SYSTEM_PROMPT = (
    "You are a senior incident response reviewer. You will be given a CRITICAL "
    "security finding and a proposed remediation plan. Give your own independent "
    "assessment in 3-5 sentences: is the plan correct and complete, what (if "
    "anything) is missing or wrong, and is there anything more urgent to do first."
)

_JUDGE_SYSTEM_PROMPT = (
    "You are the chair of a two-reviewer incident response council. You will be "
    "given the same CRITICAL finding and two independent reviewers' opinions. "
    "Start your response with exactly one word, AGREE or DISAGREE, depending on "
    "whether the two reviewers substantively agree on what to do. Then, on a new "
    "line, give ONE final, reconciled recommendation a responder should follow."
)


def _opinion_prompt(issue_text, steps):
    steps_text = "\n".join(f"- {s}" for s in steps)
    return f"CRITICAL finding: {issue_text}\n\nProposed remediation plan:\n{steps_text}"


def _judge_prompt(issue_text, opinion_a, model_a, opinion_b, model_b):
    return (
        f"CRITICAL finding: {issue_text}\n\n"
        f"Reviewer A ({model_a}):\n{opinion_a}\n\n"
        f"Reviewer B ({model_b}):\n{opinion_b}"
    )


_AGREEMENT_RE = re.compile(r"[\s*#>_`\-]*(AGREE|DISAGREE)\b", re.IGNORECASE)


def _parse_agreement(judge_text):
    """Returns "agree", "disagree", or "unparseable". The judge is asked to
    lead with exactly one word, but models decorate ("**AGREE**", "I AGREE",
    a preamble sentence) - so match the verdict word itself, tolerant of
    leading markdown/punctuation, and say so explicitly when neither word can
    be found rather than silently defaulting to disagree."""
    m = _AGREEMENT_RE.match(judge_text or "")
    if not m:
        return "unparseable"
    return m.group(1).lower()


def run_council(issue_text, steps, llm_config: dict | None = None):
    """Returns a dict with at least a "mode" key. mode == "skipped-mock" means
    no live key is configured, so no council was run. `llm_config` is the
    per-request BYOK dict threaded down from the UI handler (see llm.reason)."""
    provider = current_provider(llm_config)
    if provider is None:
        return {"mode": "skipped-mock"}

    model_a = ((llm_config or {}).get("model")) or DEFAULT_MODELS.get(provider, "default")
    second_model = SECOND_OPINION_MODELS.get(provider)
    if second_model == model_a:
        # Same model twice isn't a second opinion. Fall back to a different
        # catalog entry so the two opinions stay genuinely independent.
        second_model = {
            "anthropic": "claude-sonnet-5",
            "openai": "gpt-4o-mini",
            "openrouter": "openai/gpt-4o-mini",
        }.get(provider, second_model)

    user_prompt = _opinion_prompt(issue_text, steps)
    opinion_a, mode_a, _ = reason(_OPINION_SYSTEM_PROMPT, user_prompt, config=llm_config)
    if mode_a == "mock":
        return {"mode": "skipped-mock"}

    opinion_b, mode_b, _ = reason(_OPINION_SYSTEM_PROMPT, user_prompt,
                                  model_override=second_model, config=llm_config)
    if mode_b == "mock":
        return {"mode": "skipped-mock"}

    judge_text, judge_mode, _ = reason(
        _JUDGE_SYSTEM_PROMPT,
        _judge_prompt(issue_text, opinion_a, model_a, opinion_b, second_model),
        config=llm_config,
    )
    if judge_mode == "mock":
        return {"mode": "skipped-mock"}

    return {
        "mode": "live",
        "opinion_a": opinion_a,
        "model_a": model_a,
        "opinion_b": opinion_b,
        "model_b": second_model,
        "judge_verdict": judge_text,
        "agreement": _parse_agreement(judge_text),
    }
