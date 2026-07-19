# Project Background

## The hackathon topic

Built for an AI Engineering Accelerator hackathon, from this brief:

> An AI-powered cybersecurity system made of multiple agents that can
> monitor logs, find security issues, and suggest fixes automatically:
> Log Monitor Agent, Threat Intelligence Agent, Vulnerability Scanner
> Agent, Incident Response Agent, Policy Checker Agent (against
> ISO/NIST/SOC2). Shows how RAG and AI agents work together for real-time
> threat detection, analysis, and response.

The accelerator's curriculum covered prompt engineering, n8n, Gradio/Hugging
Face front ends, RAG (LanceDB/LlamaIndex), evals, and LangChain/LangGraph
multi-agent orchestration — this project draws on the RAG, Gradio, and
LangGraph modules directly.

## Why Gradio

Chosen over an n8n-based front end or a full Next.js/React stack because it
was taught twice for exactly this shape of problem — a Python ML/agent
pipeline needing a demoable web UI. `app.py` is a Gradio Blocks skin over
`orchestrator.py`'s LangGraph pipeline.

## Current state

Every integration described in [`README.md`](../README.md) is real and
live (LangGraph, Trivy, the NVD API, semantic RAG embeddings, Slack
notifications) — none of it is a mocked stand-in. Each still has an
automatic offline fallback so a demo never hard-fails on a flaky
connection or missing binary; see README's "Real integrations, with
graceful fallback" table for the live/fallback pairing per component.

For the design decisions behind the current architecture, see
[`DECISIONS.md`](DECISIONS.md).
