# SAST Claude Toolkit

[Italiano](README.md) · **English**

A tool for re-assessing, with Claude Code, the results of an **HCL AppScan** SAST scan (or of another tool that exports **SARIF**) and for preparing fixes, with an explicit approval from the developer at every important step.

> The toolkit works in Italian: Claude's questions, the plans, the reports and the script messages are in Italian. This page describes them in English; texts you will see or type are quoted as they appear, followed by a translation.

- It starts from the scanner's findings and **re-assesses them against the source code**: the scanner's severity is not the verdict.
- It accepts the AppScan report as **CSV** (with optional XML) or one or more **SARIF 2.1.0** files, including from different tools: the output is the same.
- It adds a **security review of all the sources** using the method of Claude Code's `/security-review` command: confirmed vulnerabilities become `OBS` observations, in the same report.
- It produces a controlled triage: verdict, evidence, a readable report, a CSV file and a JSON file for the next phase.
- It prepares fix **proposals** (diffs, proposed replacements, verification steps). It never applies anything on its own.
- Every developer, on every application, gets plans and reports with the same structure.

## Components

- **`sast-triage`**: for each finding it determines whether the problem is real and how severe it is (`High`, `Medium`, `Low`, `False Positive`, `Unknown - Needs Review`), then runs the five standard checks and the security review of all the sources. It starts from a plan that you must approve.
- **`sast-remediation`**: reads the triage result and, one finding at a time, prepares a fix plan, the proposed change and the verification instructions. It has two approvals: the overall plan and the plan for each fix.

## Requirements

- Claude Code.
- Python 3, available as `python` or `python3`. No external Python packages.
- The source code being analysed.
- The scanner report (required): AppScan as **CSV**, with the optional XML report, **or** one or more **SARIF 2.1.0** files from AppScan or other SAST tools. The SCA report is optional.

## Quick installation

From the project folder (recommended):

```
python <toolkit-path>/install.py
```

or by passing the project folder:

```
python install.py "<project-folder>"
```

Alternatively, copy `skills/sast-triage` and `skills/sast-remediation` by hand into `<project>/.claude/skills/`.

Options (their names are Italian): `--controlla` ("check": shows what it would do, without writing), `--personale` ("personal": installs for all your projects), `--sovrascrivi` ("overwrite": replaces a different version that is already installed).

After installing, open a **new** Claude Code session in the project, type `/` and check that `sast-triage` and `sast-remediation` are listed.

## Quick flow

```
/sast-triage
  → point to the files or have them found (sources, CSV report or one or more SARIF)
  → read PIANO_TRIAGE.md (the triage plan) and approve
  → triage of the findings, standard checks, security review
  → read TRIAGE_REPORT.md, TRIAGE_REPORT.csv and triage.json

/sast-remediation
  → choose triage.json and the source folder
  → read the remediation plan and approve
  → choose a finding
  → read the fix plan and approve
  → review diffs, proposed replacements and verification
```

**The toolkit never applies fixes to the sources.** It stops at the proposal: you review it and apply it yourself.

## What the toolkit does not do

- It does not replace the scanner: it does not blindly trust its severity, and the security review only adds observations confirmed by evidence.
- It does not modify the sources and does not apply fixes automatically.
- It does not run a triage or a fix without your explicit approval.
- It does not write secret values in any file it produces.

## Documentation

- [`docs/DEVELOPER_GUIDE.md`](docs/DEVELOPER_GUIDE.md): complete technical guide for developers: installation, triage, SARIF reports, assessment method, security review, remediation, output files, how to apply a fix, secrets and good practices.
- Regression tests: `python -m unittest discover -s tests` from the toolkit folder (standard library only).
