# SAST Claude Toolkit — Developer guide

[Italiano](GUIDA_SVILUPPATORE.md) · **English**

## 1. What SAST Claude Toolkit is

The toolkit helps you re-assess the results of an **HCL AppScan** SAST scan (or of another tool that exports **SARIF**) by checking them against the source code and the available evidence, and helps you prepare controlled fixes.

> The toolkit works in Italian: Claude's questions, the plans, the reports and the script messages are in Italian. This guide describes them in English; texts you will see or type are quoted as they appear, followed by a translation.

- **It does not replace the scanner**: the scanner produces the findings; the toolkit re-assesses them and adds a security review of all the sources.
- The scanner's severity is an **input**, not the final verdict: every finding is checked again in the source code.
- Fixes are **proposals**: you review them and apply them.
- You always make the decisions: there are explicit approvals before the triage and before every fix.

Two Claude Code skills:

- **`sast-triage`**: for each finding, determines whether the problem is real and how severe it is; then runs the standard checks and the security review.
- **`sast-remediation`**: reads the triage result and prepares, one finding at a time, a fix plan, a proposed change and a verification.

**The toolkit never modifies the sources automatically.**

## 2. Requirements

- Claude Code.
- Python 3, available as `python` or `python3`. No third-party Python packages.
- The application's source code.
- The scanner report (required): AppScan as **CSV**, with the optional AppScan **XML** report, **or** one or more **SARIF 2.1.0** files from AppScan or other SAST tools.
- The **SCA** report (optional).

Git is not required.

## 3. Installation

### Per-project installation (recommended)

From the project folder:

```
python <toolkit-path>/install.py
```

or by passing the folder:

```
python install.py "<project-folder>"
```

When you run `python install.py` from the toolkit folder, the script asks `Cartella del progetto >` ("Project folder >"): paste or drag in the path (quotes and spaces are fine); pressing Enter on an empty line cancels without writing anything.

The script creates `<project>/.claude/skills/`, copies the two skills and checks their integrity. It never overwrites anything that differs and does not touch other skills or settings; if something goes wrong, it leaves no half-finished installation behind.

Options:

- `--controlla` ("check"): shows what it would do, without writing anything.
- `--personale` ("personal"): installs into `~/.claude/skills`, for **all** projects; this is why it is not the recommended default.
- `--sovrascrivi` ("overwrite"): replaces an installed version that differs (see chapter 14).

### Manual alternative

Copy the folders

```
skills/sast-triage
skills/sast-remediation
```

into

```
<project>/.claude/skills/
```

### Check

1. Open a **new** Claude Code session in the project.
2. Type `/`.
3. Check that `sast-triage` and `sast-remediation` appear.

## 4. Overall flow

```
/sast-triage
→ input
→ detected context
→ plan
→ approval
→ triage (findings, standard checks, security review)
→ report + triage.json

/sast-remediation
→ remediation plan
→ approval
→ choice of a finding
→ fix plan
→ approval
→ proposal + verification
```

## 5. Triage

Start:

```
/sast-triage
```

Claude asks «Come vuoi indicarmi i file?» ("How do you want to give me the files?"):

- **Cercali tu nella cartella di lavoro** ("Find them in the working folder"): Claude searches, read-only, **only inside the folder where you opened Claude Code** and offers you the candidates to choose from. The search never starts unless you choose it.
- **Li indico io** ("I'll give you the paths"): you type the paths; Claude does not search the disk.

Always required:

- the **source folder**;
- the **scanner report**: the **AppScan CSV** or one or more **SARIF** files (they are alternatives: if you give CSV and SARIF together, Claude asks which to use; CSV files are used one at a time).

Optional: the **XML** report (only with the CSV), the **SCA** report and a baseline or additional context (constraints, a previous triage: it is context only and never decides the verdict).

### SARIF reports

SARIF replaces the CSV + XML pair: it contains the findings and, in `codeFlows`, the data-flow traces. The SARIF export from AppScan (on Cloud, 360°, Source) works, as does SARIF 2.1.0 from another SAST tool. It is read by `parse_sarif.py`, which produces the same intermediate data as the CSV: the plan, report, CSV and `triage.json` have the same format.

- **One finding per result**, in file order, numbered `AS-001`, `AS-002`… even if the SARIF does not come from AppScan.
- **Scanner severity**, on the scale `Critical` · `High` · `Medium` · `Low` · `Informational`, taken in this order from:
  1. the tool's severity field (e.g. AppScan's `properties.Severity`);
  2. `security-severity` (CVSS score: from 9.0 `Critical`, from 7.0 `High`, from 4.0 `Medium`, from 0.1 `Low`);
  3. `level` (`error` `High`, `warning` `Medium`, `note` `Low`, `none` `Informational`).
- **Files**: paths become relative to the sources, as with the CSV. For compiled code AppScan gives the class instead of the file (e.g. `Azienda.Modulo.Repositories.OrderRepository.cs`): the parser finds `OrderRepository.cs` in the folder that matches the namespace. The AppScan on Cloud CSV uses the same form in the `Source File` column, but its parser is still the one from version 1.0.0 and does not resolve it: those findings are reported as «non trovati» ("not found") in the sources and `/sast-remediation` does not accept them. To work on them, use the SARIF export of the same scan.
- **Traces and titles**: compared with the CSV + XML pair of the same scan, the SARIF has traces only for findings with a data flow (the XML also gives the highlighted line of code for the others); the title is the SARIF message, which matches the CSV issue type in most cases and is more descriptive in the others (e.g. «Throwing generic exceptions in C#» instead of «ErrorHandling»).
- **Excluded**, and counted: results suppressed in the tool (unless explicitly requested), results that are no longer present (`baselineState` `absent`) and results that are not problems (`kind` `pass`, `notApplicable`, `informational`).
- **Report date**: the one declared in the `invocations`. AppScan's SARIF export does not include it: the report shows «data non disponibile» ("date not available").
- **Several SARIF files**, for example from different tools or modules, are read together:
  - a single `AS-xxx` numbering, in the order in which you list the files;
  - a result already read from an earlier file (same tool, rule, file, line and identifier) counts only once: the script excludes it and reports it. Different tools on the same spot remain separate findings, analysed in the same group;
  - in the report, the name becomes the list of files joined by « + » (e.g. `appscan.sarif + semgrep.sarif`), with the folder only when two files have the same name, and the date is the most recent one;
  - listing the same file twice is an error.

You are asked for the **exposure**, one of:

- `Internet`
- `Rete interna` (internal network)
- `Solo locale` (local only)
- `Non nota` (unknown: Claude assumes the reasonable worst case and states it)

The release model is inferred from the project and shown as «Rilascio: … (rilevato)» ("Release: … (detected)"); you are asked only if it cannot be inferred.

Then Claude:

1. inspects the available evidence (project, build, release) and **shows the detected context**, which you can correct;
2. creates `sast-output/triage/PIANO_TRIAGE.md`, the triage plan (analysis groups, five standard checks, security review, planned checks, no verdicts);
3. **shows the complete plan in the chat**, identical to the file;
4. stops and waits.

**No triage starts without an explicit approval** («Approvo», «Va bene, procedi»: "I approve", "Fine, go ahead"). A question, a comment, a request for an explanation or an ambiguous answer («ok, ma…», "ok, but…") **is not an approval**: Claude answers and waits. If you ask for changes, Claude regenerates the plan and shows it to you again in full.

## 6. Assessment method

For each finding Claude checks four gates:

- **G1 reachability**: is the code executed in a real flow?
- **G2 controllability**: can an attacker influence the data?
- **G3 presence in the artefact**: is the code part of what is released?
- **G4 relevant effect**: does the result reach an effect that is useful to an attacker?

Canonical verdicts: `High`, `Medium`, `Low`, `False Positive`, `Unknown - Needs Review`. The scanner's severity remains a separate field.

- `False Positive` requires **explicit evidence** on all four gates.
- If the evidence is incomplete, the verdict is `Unknown - Needs Review`, stating which evidence is missing. It is a valid outcome, not an error.
- A real software defect **without an exploitable security impact** can be a `False Positive`, and the report says so explicitly.
- Public code in a **shared library** is not considered unreachable just because it has no callers in the analysed product: if the external consumers cannot be established, the verdict is `Unknown - Needs Review`.
- The cost and difficulty of the fix never change the verdict.

After the findings, Claude runs **five standard checks**, the same for every application: authentication and authorization of exposed endpoints; secrets; transport and CORS; SQL and commands; cryptography. For each area the outcome is: no confirmed observation, one or more observations, or not verifiable with the available evidence. Only **confirmed** problems become `OBS-xxx`, kept separate from the scanner's findings. It is not a general audit.

Finally, the **third analysis**: a **security review of the whole source folder** using the method of Claude Code's `/security-review` command (same categories, exclusions and false-positive filter, confidence threshold 8 out of 10). The native command only examines the branch diff against `origin/HEAD` and requires Git: this is why the skill applies its instructions to all the sources, without invoking it. Each candidate vulnerability is then checked again in the source code with the toolkit's rules: only those that are confirmed and not already covered by a finding or another observation become `OBS-xxx`. In the report you can recognise them because their summary starts with «Security review:»; if they fall into one of the five areas, they also appear in the standard checks table. The review is announced in the plan, so it is covered by your approval.

The complete rules are in the skills' references (in Italian); here it is enough to know that they rely on evidence, not on the scanner's severity.

## 7. Triage output

The `sast-output/` folder is created next to the folder given as the source root. As a consequence, if you give the project root itself as the sources, `sast-output/` is created in the parent directory.

```
sast-output/triage/
├── PIANO_TRIAGE.md
├── TRIAGE_REPORT.md
├── TRIAGE_REPORT.csv
├── triage.json
└── _work/
```

- `PIANO_TRIAGE.md`: the plan you approved.
- `TRIAGE_REPORT.md`: the report to read, always with the same sections (summary, confirmed findings, `False Positive`, `Unknown - Needs Review`, standard checks, additional observations).
- `TRIAGE_REPORT.csv`: one row for each finding and observation, to open in Excel (`;` separator, UTF-8).
- `triage.json`: the **stable, validated contract** between `sast-triage` and `sast-remediation`. In short, it contains: project and scanner report metadata, detected context, findings with verdict, evidence and gates G1–G4, the outcome of the five standard checks and the additional observations (including those from the security review). `/sast-remediation` starts from this validated result instead of redoing the triage.
- `_work/`: internal working data, not the main result. `_work/security-review.json` records each security review candidate with its outcome (observation, duplicate or discarded, and why).

The file format is the same whatever the starting report (CSV or SARIF).

## 8. Remediation

Start:

```
/sast-remediation
```

It uses `sast-output/triage/triage.json` and the source folder. If the file exists at the canonical path, Claude offers it as the first choice; otherwise you can give another path. For the sources, it offers the top-level folders that contain the files cited by the triage. If the triage has not been produced yet, run `/sast-triage` first.

Flow:

1. **overall plan** (`PIANO_REMEDIATION.md`, the remediation plan), shown in full in the chat;
2. **first approval**: until you approve, no fix is prepared;
3. **guided choice** of a finding or of a confirmed observation (by severity, by plan step or a single one);
4. **technical analysis** of the root cause on the current source code;
5. **fix plan** (`PIANO_FIX.md`, at most 500 words), shown in full;
6. **second approval**: no diff or proposed file before it;
7. **generation of the proposal** and of the verification.

Work proceeds **one finding at a time**: once the proposal is ready, the skill stops and does not move on to the next one by itself.

Related findings can depend on each other. The remediation plan gives their order; before release, dependent changes must be verified together as a single consistent change.

Only `High`, `Medium`, `Low` and the confirmed `OBS-xxx` are candidates. `False Positive` and `Unknown - Needs Review` are not proposed for fixing. Here too, questions and requests for changes do not count as approval.

## 9. Remediation output

```
sast-output/remediation/
├── PIANO_REMEDIATION.md
├── REMEDIATION.md
├── _work/
└── fixes/
    └── <ID>/
        ├── PIANO_FIX.md
        ├── VERIFICA.md
        ├── *.diff
        ├── *.proposto
        └── PROPOSTE.json
```

`<ID>` can be a scanner finding, such as `AS-xxx`, or a confirmed additional observation (from the standard checks or the security review), such as `OBS-xxx`.

**Not every fix produces every type of file.** The remediation never writes into `sast-output/triage/`.

- `REMEDIATION.md`: the status of each candidate (`Da fare`, `Piano fix pronto`, `Piano fix approvato`, `Fix proposto`, `Applicato dallo sviluppatore`, `Verificato`, that is: to do, fix plan ready, fix plan approved, fix proposed, applied by the developer, verified) and the decisions still open.
- `*.diff`: a safe patch, with relative paths, for the files that can be shown without revealing secrets.
- `*.proposto` ("proposed"): a safe proposed replacement for a file whose diff would not be safe. **It is not applied automatically.** The path and SHA-256 of the original are recorded in the manifest and in `VERIFICA.md`.
- `PROPOSTE.json` ("proposals"): the manifest of the artefacts, file by file.
- `VERIFICA.md` ("verification"): checks to run before and after applying the fix, what has not been built or tested, rollback.

## 10. Applying a fix

**The toolkit proposes, the developer applies. The toolkit never changes the source files.**

Recommended procedure:

1. work on a **dedicated branch**;
2. one fix at a time;
3. read `PIANO_FIX.md`;
4. review the diff or the proposal;
5. apply it by hand or with your usual development tools;
6. build and run the planned tests;
7. commit;
8. only then tell the skill «Applicato dallo sviluppatore» ("applied by the developer");
9. only after a real verification confirm «Verificato» ("verified").

A diff is applied, from the source root, with:

```
git apply <file>.diff
```

Git is not needed to generate the toolkit's output: you only need it if you choose to apply the patch this way. Before replacing a file with a `.proposto` proposal, compare the SHA-256 of the original file with the recorded one (PowerShell: `Get-FileHash <file> -Algorithm SHA256`; elsewhere `sha256sum <file>`): if it has changed, the proposal must be regenerated.

You can also ask Claude, **in a normal development session outside the skill**, to apply a proposal you have already reviewed, for example on a new branch.

## 11. Secrets

- Never paste secret values (passwords, keys, tokens) into the conversation.
- The output files do not expose secret values: they describe where the secrets are and what type they are.
- A file that contains a secret can be left out of the diff; the other files of the same fix still get their diff.
- A `.proposto` file is produced only if it is safe; otherwise the skill gives instructions in words.
- Rotating or revoking an exposed credential may be necessary, **outside** the code change: the fix plan and the verification say so.

## 12. Permissions and sources

- Claude Code may ask your permission to run Python or to create the output files: this is normal.
- The toolkit's access to the sources is **read-only**.
- The outputs live in `sast-output/`, separate from the sources.

## 13. Good practices

- Read the complete plan before approving.
- Do not invent missing evidence: `Unknown - Needs Review` is a valid outcome.
- Never share secret values.
- Work on one fix at a time.
- Review every proposal.
- Build and run the planned tests before marking a fix as verified.

## 14. Updating and removal

**Updating.** To deliberately replace an installed version that differs:

```
python <toolkit-path>/install.py --sovrascrivi
```

If the terminal is already open in the toolkit folder, the shorter form `python install.py --sovrascrivi` is equivalent. Without this option, a different skill is left unchanged.

**Removal.** For a per-project installation, delete:

```
<project>/.claude/skills/sast-triage
<project>/.claude/skills/sast-remediation
```

No uninstall script is needed.
