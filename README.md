# DepsGuard-AI

> A lightweight, zero-dependency security automation tool that scans your Python
> dependencies for known vulnerabilities (CVEs) on every Pull Request.

DepsGuard-AI parses your `requirements.txt`, queries the free
[OSV.dev](https://osv.dev/) vulnerability database for each pinned package, and
produces a single structured JSON report. It is purpose-built for GitHub Actions
but runs just as happily on your laptop.

## Why it matters for open source

Open-source projects rarely have a dedicated security team, yet they pull in
dozens of transitive dependencies — any of which can ship a critical CVE. Most
existing scanners require accounts, API tokens, paid tiers, or heavy toolchains.

DepsGuard-AI is different:

- **Zero runtime dependencies.** Pure Python standard library — nothing to
  `pip install`, nothing to break.
- **Free data source.** Uses the public OSV.dev API maintained by Google and the
  OpenSSF, which aggregates GitHub Advisories, PyPA, and many other feeds.
- **CI-native.** Drops into any repository as a single GitHub Actions workflow
  and gates Pull Requests automatically.
- **Resilient.** Network failures, timeouts, and API errors never crash the run;
  they are captured in the report so the scan degrades gracefully.
- **AI-ready.** Ships with a clean hook for optional OpenAI-powered triage that
  ranks CVEs by how critical they really are *for your project*.

## How it works

1. **Parse** — read `requirements.txt` and extract exact pins
   (`package==version`).
2. **Scan** — `POST` each dependency to `https://api.osv.dev/v1/query`.
3. **Report** — aggregate all findings into one JSON document with a summary,
   per-package findings, extracted CVE aliases, severity scores, and references.
4. **(Optional) Analyze** — pass the report to `analyze_report_with_openai()` to
   have GPT assess real-world criticality and recommend fixes (stubbed by
   default; enable with an API key).

## Usage

### Run locally

```bash
# Scan the default requirements.txt
python main.py

# Scan a specific file and save the report
python main.py path/to/requirements.txt --output report.json

# Fail (non-zero exit) if any vulnerability is found — great for CI gates
python main.py --fail-on-vuln

# Tune the per-request network timeout (seconds)
python main.py --timeout 30
```

Requires Python 3.9+ and outbound HTTPS access to `api.osv.dev`.

### Run in GitHub Actions

The workflow in [`.github/workflows/deps-guard.yml`](.github/workflows/deps-guard.yml)
runs automatically on every Pull Request that changes `requirements.txt`,
prints the report to the build logs, uploads it as an artifact, and fails the
check when vulnerabilities are detected.

You can also trigger it manually from the **Actions** tab via
`workflow_dispatch`.

### Optional: enable AI triage

1. `pip install openai`
2. Add an `OPENAI_API_KEY` secret to your repository (or export it locally).
3. Uncomment the integration block inside `analyze_report_with_openai()` in
   `main.py`.

When enabled, DepsGuard-AI asks the model to evaluate each CVE's relevance to
your codebase, judge likely exploitability, and rank remediations by urgency.

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
