# DepsGuard-AI 🛡️🤖

An ultra-lightweight, zero-dependency security scanner built for GitHub Actions. It automatically audits Python dependencies against the Google OSV database during Pull Requests and leverages OpenAI models to triage findings, eliminating vulnerability noise for maintainers.

## Key Features
* **Zero Runtime Dependencies:** Built entirely using Python's standard library (`urllib`). Safe from supply-chain attacks.
* **OSV.dev Integration:** Fast data fetching from the open-source vulnerability database.
* **AI Security Triage:** Cuts through the noise by using LLMs to evaluate whether a CVE actually impacts your specific codebase.
* **Sticky PR Comments:** Seamlessly upserts security reports directly into Pull Requests without spamming the timeline.

## Why it matters for open source

Open-source projects rarely have a dedicated security team, yet they pull in
dozens of transitive dependencies — any of which can ship a critical CVE. Most
existing scanners require accounts, API tokens, paid tiers, or heavy toolchains.

DepsGuard-AI is different: it's a single Python file with no `pip install` step,
it reads from the free OSV.dev database (maintained by Google and the OpenSSF),
and it degrades gracefully — network failures, timeouts, and API errors are
captured in the report instead of crashing your CI.

## How it works

1. **Parse** — read `requirements.txt` and extract exact pins
   (`package==version`).
2. **Scan** — `POST` each dependency to `https://api.osv.dev/v1/query`.
3. **Report** — aggregate all findings into one JSON document with a summary,
   per-package findings, extracted CVE aliases, severity scores, and references.
4. **AI Triage** *(optional)* — when `OPENAI_API_KEY` is set, the report is sent
   to `gpt-4o-mini`, which acts as a Senior Security Engineer and returns a tight
   markdown verdict (`Risk Assessment` + `Action Items`).
5. **Comment** — in CI, the verdict is upserted as a single sticky Pull Request
   comment.

## Usage

### Run locally

```bash
# Scan the default requirements.txt
python main.py

# Scan a specific file and save the JSON report
python main.py path/to/requirements.txt --output report.json

# Also save the AI verdict to a text file (requires OPENAI_API_KEY)
python main.py --output report.json --ai-output ai_output.txt

# Fail (non-zero exit) if any vulnerability is found — great for CI gates
python main.py --fail-on-vuln

# Tune the per-request network timeout (seconds)
python main.py --timeout 30
```

Requires Python 3.9+ and outbound HTTPS access to `api.osv.dev` (and
`api.openai.com` when AI triage is enabled).

### Run in GitHub Actions

The workflow in [`.github/workflows/deps-guard.yml`](.github/workflows/deps-guard.yml)
runs automatically on every Pull Request that changes `requirements.txt`,
prints the report to the build logs, uploads it as an artifact, posts the AI
triage as a sticky PR comment, and fails the check when vulnerabilities are
detected. You can also trigger it manually from the **Actions** tab via
`workflow_dispatch`.

### Enable AI triage

AI triage is fully implemented and uses only `urllib` — no extra packages.
To turn it on:

1. Add an `OPENAI_API_KEY` secret to your repository (or export it locally).
2. That's it. When the key is present, DepsGuard-AI calls the OpenAI API and
   prints/saves the verdict; when it's absent, the step is silently skipped.

When enabled, the model evaluates each CVE's relevance to your codebase, judges
likely exploitability, and returns a prioritized remediation checklist.

## Example report

```json
{
  "tool": "DepsGuard-AI",
  "ecosystem": "PyPI",
  "summary": {
    "packages_scanned": 3,
    "vulnerable_packages": 2,
    "total_vulnerabilities": 5,
    "scan_errors": 0
  },
  "findings": [
    {
      "package": "requests",
      "version": "2.20.0",
      "vulnerability_count": 1,
      "vulnerabilities": [
        {
          "id": "GHSA-x84v-xcm2-53pg",
          "summary": "Insufficiently Protected Credentials in requests",
          "aliases": ["CVE-2018-18074"],
          "cves": ["CVE-2018-18074"],
          "severity": [],
          "references": ["https://github.com/..."]
        }
      ]
    }
  ],
  "errors": []
}
```

## Project structure

```
.
├── main.py                          # Scanner CLI (stdlib only)
├── requirements.txt                 # Sample deps incl. a vulnerable pin
├── README.md
└── .github/
    └── workflows/
        └── deps-guard.yml           # GitHub Actions workflow
```

## License

Released under the MIT License. Contributions welcome — this is a tool *for* the
open-source community, *by* the open-source community.
