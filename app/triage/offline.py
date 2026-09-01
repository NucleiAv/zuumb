"""Keyword-heuristic stand-in for the LLM triage call.

Used by `--offline` runs of scripts/run_poc.py and eval/run_eval.py so the
pipeline and the eval harness work with no API key / no cost. Not production triage.
Same signature as agent._call_llm: (system, user) -> verdict dict.
"""
from __future__ import annotations


def _v(verdict: str, conf: float, why: str, mitre: str | None) -> dict:
    return {"verdict": verdict, "confidence": conf,
            "reasoning": f"[offline heuristic] {why}.", "mitre_technique": mitre}


def offline_verdict(system: str, user: str) -> dict:
    u = user.lower()
    if any(k in u for k in ("union select", "sql injection", "cgi-bin")):
        return _v("malicious", 0.9, "exploit of a public-facing app", "T1190")
    if any(k in u for k in ("reverse shell", "netcat", "mimikatz", "lsass", ".locked",
                            "defender disabled", "ransom", "psexec", "lateral movement",
                            "scheduled task", "exfiltration", "(persistence)", "/dev/tcp",
                            "vssadmin", "shadow cop", "suid-root", "root shell",
                            "privilege escalation", "cve-2021", "mass file encryption")):
        return _v("malicious", 0.9, "known-bad tooling / post-exploitation", "T1059")
    if "brute force" in u:
        return _v("suspicious", 0.55, "repeated auth failures", "T1110")
    if any(k in u for k in ("non-existent user", "encodedcommand", "useradd",
                            "firewall rule", "failed sudo", "port scan")):
        return _v("suspicious", 0.55, "anomalous but not conclusive", "T1078")
    return _v("benign", 0.6, "no attack indicators", None)
