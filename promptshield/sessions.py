"""Per-session state the action guard needs: taint, earlier findings, and call counts.

Kept in memory, deliberately: it holds fingerprints of secrets the agent read, which shouldn't be
written to disk. A restart forgets it, so a new process starts every session clean. The number of
sessions is bounded, oldest first out, so a flood of session ids can't exhaust memory.
"""

import hashlib
import json
from collections import Counter, OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field

from promptshield.models import Finding, Severity, ToolCall
from promptshield.policy.engine import OutboundSignals
from promptshield.policy.schema import ToolClass
from promptshield.taint import TaintSettings, TaintTracker


def _call_key(tool_call: ToolCall) -> str:
    """Same tool, same arguments, whatever the key order."""
    canonical = json.dumps(tool_call.args, sort_keys=True, default=str)
    payload = f"{tool_call.server}.{tool_call.tool}\n{canonical}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class SessionState:
    session_id: str
    taint: TaintTracker
    high_finding_seen: bool = False
    egress_count: int = 0
    call_counts: Counter[str] = field(default_factory=Counter)

    def record_result(
        self, source: str, texts: Iterable[str], findings: Iterable[Finding], sensitive: bool
    ) -> None:
        """Called for every tool result: even allowed content is untrusted."""
        self.taint.record(source, texts, sensitive)
        if any(finding.severity.rank >= Severity.HIGH.rank for finding in findings):
            self.high_finding_seen = True

    def signals_for(self, tool_call: ToolCall, tool_class: ToolClass) -> OutboundSignals:
        """Counts this call, then reports. Counting first means a blocked call still counts,
        so a loop that keeps retrying a refused call still hits the limit."""
        key = _call_key(tool_call)
        self.call_counts[key] += 1
        egress = tool_class == "egress"
        if egress:
            self.egress_count += 1
        return OutboundSignals(
            tool_call=tool_call,
            sensitive_data=egress and self.taint.carries_sensitive_data(tool_call.args),
            high_finding_earlier=self.high_finding_seen,
            egress_count=self.egress_count if egress else 0,
            identical_calls=self.call_counts[key],
        )


class SessionStore:
    def __init__(self, max_sessions: int, taint: TaintSettings) -> None:
        self._max = max_sessions
        self._taint = taint
        self._sessions: OrderedDict[str, SessionState] = OrderedDict()

    def __len__(self) -> int:
        return len(self._sessions)

    def get(self, session_id: str) -> SessionState:
        state = self._sessions.get(session_id)
        if state is None:
            state = SessionState(session_id, TaintTracker(self._taint))
            self._sessions[session_id] = state
            if len(self._sessions) > self._max:
                self._sessions.popitem(last=False)
        else:
            self._sessions.move_to_end(session_id)
        return state

    def forget(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
