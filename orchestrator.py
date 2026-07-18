"""
Orchestrator
------------
Wires the 5 analysis agents plus a terminal notification/action stage together
as a real LangGraph `StateGraph`. Log Monitor and Vulnerability Scanner have
independent inputs and run in parallel (both edge from START); Threat
Intelligence joins on both before running; Incident Response and Policy
Checker follow sequentially; Notify runs last, dispatching Slack/email alerts
for findings at or above a configured severity. This matches the architecture
diagram in README.md.
"""

from typing import TypedDict, Any
from langgraph.graph import StateGraph, START, END

from agents import log_monitor, threat_intel, vuln_scanner, incident_response, policy_checker, notify


class PipelineState(TypedDict, total=False):
    log_path: str
    dockerfile_path: str
    requirements_path: str
    policy_path: str
    log_monitor: dict
    vuln_scanner: dict
    threat_intel: dict
    incident_response: dict
    policy_checker: dict
    notify: dict


def node_log_monitor(state):
    result = log_monitor.run(state["log_path"])
    return {"log_monitor": result}


def node_vuln_scanner(state):
    result = vuln_scanner.run(state["dockerfile_path"], state["requirements_path"])
    return {"vuln_scanner": result}


def node_threat_intel(state):
    # runs after both log_monitor and vuln_scanner have joined, so CVE
    # matching covers both log-derived and dependency-derived keywords
    result = threat_intel.run(
        state["log_monitor"]["findings"],
        dependency_names=state["vuln_scanner"]["dependency_names"],
    )
    return {"threat_intel": result}


def node_incident_response(state):
    result = incident_response.run(
        state["log_monitor"]["findings"],
        state["vuln_scanner"]["findings"],
    )
    return {"incident_response": result}


def node_policy_checker(state):
    all_findings = state["log_monitor"]["findings"] + state["vuln_scanner"]["findings"]
    result = policy_checker.run(state["policy_path"], all_findings)
    return {"policy_checker": result}


def node_notify(state):
    # terminal action stage: dispatches Slack/email alerts for findings at or
    # above the configured severity threshold. Not a reasoning agent - it does
    # fixed routing over data the other nodes already produced.
    result = notify.run(state)
    return {"notify": result}


def build_graph():
    graph = StateGraph(PipelineState)
    graph.add_node("log_monitor", node_log_monitor)
    graph.add_node("vuln_scanner", node_vuln_scanner)
    graph.add_node("threat_intel", node_threat_intel)
    graph.add_node("incident_response", node_incident_response)
    graph.add_node("policy_checker", node_policy_checker)
    graph.add_node("notify", node_notify)

    graph.add_edge(START, "log_monitor")
    graph.add_edge(START, "vuln_scanner")
    graph.add_edge("log_monitor", "threat_intel")
    graph.add_edge("vuln_scanner", "threat_intel")
    graph.add_edge("threat_intel", "incident_response")
    graph.add_edge("incident_response", "policy_checker")
    graph.add_edge("policy_checker", "notify")
    graph.add_edge("notify", END)

    return graph.compile()


def _initial_state(log_path, dockerfile_path, requirements_path, policy_path):
    return {
        "log_path": log_path,
        "dockerfile_path": dockerfile_path,
        "requirements_path": requirements_path,
        "policy_path": policy_path,
    }


def run_pipeline(log_path, dockerfile_path, requirements_path, policy_path):
    app = build_graph()
    return app.invoke(_initial_state(log_path, dockerfile_path, requirements_path, policy_path))


def stream_pipeline(log_path, dockerfile_path, requirements_path, policy_path):
    """
    Generator variant of run_pipeline for live UIs: yields
    (node_name, accumulated_state) the moment each agent node completes,
    using LangGraph's native .stream() ("updates" mode emits each node's
    returned state delta as it finishes - parallel nodes arrive in whatever
    order they actually complete). The final yield's accumulated_state is
    equivalent to run_pipeline()'s return value.
    """
    app = build_graph()
    state = _initial_state(log_path, dockerfile_path, requirements_path, policy_path)
    for chunk in app.stream(state):
        for node_name, update in chunk.items():
            state.update(update)
            yield node_name, dict(state)
