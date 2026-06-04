#!/usr/bin/env python3
"""DepsGuard-AI: a lightweight dependency vulnerability scanner for CI.

The tool parses a ``requirements.txt`` file, queries the free OSV.dev API for
known vulnerabilities (CVEs) for every pinned dependency and produces a single
structured JSON report. It is designed to run inside GitHub Actions on every
Pull Request, but it also works perfectly fine as a standalone CLI tool.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any

import urllib.error
import urllib.request

OSV_API_URL = "https://api.osv.dev/v1/query"
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL = "gpt-4o-mini"
OPENAI_TIMEOUT = 30  # seconds for the OpenAI triage request
DEFAULT_TIMEOUT = 15  # seconds for every network request
USER_AGENT = "DepsGuard-AI/1.0 (+https://github.com/)"

# Matches lines like ``package==1.2.3`` while ignoring comments / blank lines.
# We intentionally only handle exact pins (``==``) because OSV needs a concrete
# version to return meaningful results.
REQUIREMENT_RE = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)   # package name (PEP 503-ish)
    \s*==\s*
    (?P<version>[A-Za-z0-9][A-Za-z0-9.\-+_!]*)  # exact version
    \s*
    (?:[;#].*)?                              # optional env marker / comment
    $
    """,
    re.VERBOSE,
)


@dataclass
class Dependency:
    """A single pinned dependency parsed from requirements.txt."""

    name: str
    version: str

    def __str__(self) -> str:  # pragma: no cover - cosmetic only
        return f"{self.name}=={self.version}"


@dataclass
class VulnerabilityReport:
    """Aggregated result for a single dependency."""

    dependency: Dependency
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    @property
    def is_vulnerable(self) -> bool:
        return bool(self.vulnerabilities)


def parse_requirements(path: str) -> list[Dependency]:
    """Parse a ``requirements.txt`` file into a list of pinned dependencies.

    Only exact pins (``package==version``) are considered. Comments, blank
    lines, options (``-r other.txt``) and non-pinned specifiers are skipped.
    """

    dependencies: list[Dependency] = []

    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        raise SystemExit(f"[ERROR] requirements file not found: {path}")
    except OSError as exc:
        raise SystemExit(f"[ERROR] could not read {path}: {exc}")

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        match = REQUIREMENT_RE.match(line)
        if not match:
            # Not an exact pin; skip silently but note it for the user.
            print(f"[WARN] skipping unsupported requirement line: {line!r}")
            continue

        dependencies.append(
            Dependency(name=match.group("name"), version=match.group("version"))
        )

    return dependencies


def query_osv(dependency: Dependency, timeout: int = DEFAULT_TIMEOUT) -> VulnerabilityReport:
    """Query the OSV.dev API for a single dependency.

    Returns a :class:`VulnerabilityReport`. Network/parse errors are captured in
    the ``error`` field instead of raising, so a single failure never aborts the
    whole scan.
    """

    payload = {
        "version": dependency.version,
        "package": {"name": dependency.name, "ecosystem": "PyPI"},
    }
    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        OSV_API_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            parsed = json.loads(body)
    except urllib.error.HTTPError as exc:
        return VulnerabilityReport(
            dependency=dependency,
            error=f"HTTP {exc.code} from OSV API: {exc.reason}",
        )
    except urllib.error.URLError as exc:
        # Covers timeouts, DNS failures, refused connections, etc.
        return VulnerabilityReport(
            dependency=dependency,
            error=f"network error contacting OSV API: {exc.reason}",
        )
    except (TimeoutError, json.JSONDecodeError) as exc:
        return VulnerabilityReport(
            dependency=dependency,
            error=f"unexpected error processing OSV response: {exc}",
        )

    vulns = parsed.get("vulns", []) if isinstance(parsed, dict) else []
    return VulnerabilityReport(dependency=dependency, vulnerabilities=vulns)


def _summarise_vuln(vuln: dict[str, Any]) -> dict[str, Any]:
    """Extract the most useful fields from a raw OSV vulnerability entry."""

    aliases = vuln.get("aliases", []) or []
    cves = [alias for alias in aliases if str(alias).upper().startswith("CVE-")]

    severity = vuln.get("severity", []) or []
    severity_scores = [
        {"type": item.get("type"), "score": item.get("score")}
        for item in severity
        if isinstance(item, dict)
    ]

    return {
        "id": vuln.get("id"),
        "summary": vuln.get("summary") or vuln.get("details", "")[:200],
        "aliases": aliases,
        "cves": cves,
        "severity": severity_scores,
        "references": [ref.get("url") for ref in vuln.get("references", []) if isinstance(ref, dict)],
    }


def build_report(reports: list[VulnerabilityReport]) -> dict[str, Any]:
    """Assemble all per-dependency results into one structured JSON report."""

    findings: list[dict[str, Any]] = []
    scan_errors: list[dict[str, str]] = []
    total_vulns = 0

    for report in reports:
        if report.error:
            scan_errors.append(
                {"package": str(report.dependency), "error": report.error}
            )
            continue

        if report.is_vulnerable:
            summarised = [_summarise_vuln(v) for v in report.vulnerabilities]
            total_vulns += len(summarised)
            findings.append(
                {
                    "package": report.dependency.name,
                    "version": report.dependency.version,
                    "vulnerability_count": len(summarised),
                    "vulnerabilities": summarised,
                }
            )

    return {
        "tool": "DepsGuard-AI",
        "ecosystem": "PyPI",
        "summary": {
            "packages_scanned": len(reports),
            "vulnerable_packages": len(findings),
            "total_vulnerabilities": total_vulns,
            "scan_errors": len(scan_errors),
        },
        "findings": findings,
        "errors": scan_errors,
    }


def analyze_report_with_openai(report: dict[str, Any]) -> str:
    """Run an optional OpenAI-powered triage step over the vulnerability report.

    Behaviour:

    * If ``OPENAI_API_KEY`` is not set, the function silently returns an empty
      string so the tool keeps working with zero OpenAI dependency.
    * Otherwise it sends a ``POST`` request to the OpenAI chat completions API
      using only :mod:`urllib.request` (no third-party ``requests`` package).
      The model acts as a Senior Security Engineer and returns a short, blunt
      markdown verdict for the repository maintainer.

    All network and API errors are caught and logged: a failure here never
    aborts the surrounding scanner. On any failure an empty string is returned.
    """

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        # Silently skip - no key configured.
        return ""

    system_prompt = (
        "You are a Senior Security Engineer reviewing a dependency vulnerability "
        "report for an open-source repository. Be concise, blunt, and practical. "
        "Analyze the provided JSON security report and produce a short markdown "
        "verdict for the repository maintainer, written in English, with EXACTLY "
        "these two sections:\n\n"
        "## Risk Assessment\n"
        "A few sentences judging the overall severity, which CVEs are most "
        "dangerous, and how exploitable they realistically are for a typical "
        "project. No fluff.\n\n"
        "## Action Items\n"
        "A prioritized, actionable checklist (most urgent first), naming the "
        "package and the minimum safe version to upgrade to where possible.\n\n"
        "Do not restate the entire JSON. Keep the whole answer tight."
    )

    user_prompt = (
        "Here is the DepsGuard-AI security report in JSON. Analyze the critically "
        "of these CVEs for our project and give your verdict:\n\n"
        f"```json\n{json.dumps(report, indent=2)}\n```"
    )

    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
    }
    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        OPENAI_API_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=OPENAI_TIMEOUT) as response:
            body = response.read().decode("utf-8")
            parsed = json.loads(body)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")
        except Exception:  # noqa: BLE001 - best-effort error detail only
            pass
        print(f"[WARN] OpenAI API returned HTTP {exc.code}: {exc.reason} {detail}".strip())
        return ""
    except urllib.error.URLError as exc:
        print(f"[WARN] network error contacting OpenAI API: {exc.reason}")
        return ""
    except (TimeoutError, json.JSONDecodeError) as exc:
        print(f"[WARN] unexpected error processing OpenAI response: {exc}")
        return ""

    try:
        verdict = parsed["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError) as exc:
        print(f"[WARN] unexpected OpenAI response shape: {exc}")
        return ""

    return verdict


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan a requirements.txt for known vulnerabilities via OSV.dev",
    )
    parser.add_argument(
        "requirements",
        nargs="?",
        default="requirements.txt",
        help="path to the requirements file (default: requirements.txt)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="write the JSON report to this file in addition to stdout",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"per-request network timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--ai-output",
        help="write the AI triage verdict (if any) to this text file",
    )
    parser.add_argument(
        "--fail-on-vuln",
        action="store_true",
        help="exit with a non-zero status code if any vulnerability is found",
    )
    args = parser.parse_args(argv)

    dependencies = parse_requirements(args.requirements)
    if not dependencies:
        print("[INFO] no pinned dependencies (package==version) found - nothing to scan.")
        empty = build_report([])
        print(json.dumps(empty, indent=2))
        return 0

    print(f"[INFO] scanning {len(dependencies)} dependencies against OSV.dev ...")
    reports = [query_osv(dep, timeout=args.timeout) for dep in dependencies]

    report = build_report(reports)

    rendered = json.dumps(report, indent=2)
    print("\n===== DepsGuard-AI Report =====")
    print(rendered)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(rendered)
            print(f"[INFO] report written to {args.output}")
        except OSError as exc:
            print(f"[WARN] could not write report to {args.output}: {exc}")

    # Optional AI triage (only runs when OPENAI_API_KEY is configured).
    ai_verdict = analyze_report_with_openai(report)
    if ai_verdict:
        print("\n===== AI Security Triage =====")
        print(ai_verdict)

    if args.ai_output:
        try:
            with open(args.ai_output, "w", encoding="utf-8") as handle:
                handle.write(ai_verdict)
            if ai_verdict:
                print(f"[INFO] AI verdict written to {args.ai_output}")
        except OSError as exc:
            print(f"[WARN] could not write AI verdict to {args.ai_output}: {exc}")

    summary = report["summary"]
    print(
        f"\n[SUMMARY] {summary['vulnerable_packages']} vulnerable package(s), "
        f"{summary['total_vulnerabilities']} vulnerability(ies), "
        f"{summary['scan_errors']} scan error(s)."
    )

    if args.fail_on_vuln and summary["total_vulnerabilities"] > 0:
        print("[FAIL] vulnerabilities detected and --fail-on-vuln is set.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
