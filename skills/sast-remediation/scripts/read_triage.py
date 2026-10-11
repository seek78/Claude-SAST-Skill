# -*- coding: utf-8 -*-
"""Valida triage.json e riepiloga cosa può entrare in remediation. Non modifica nulla.

Uso:
  python read_triage.py TRIAGE.json --sources CARTELLA_SORGENTI

Controlla (regole in triage_contract.py, descritte in references/output-contract.md): JSON leggibile,
schema_version "1.0", metadati, esposizione a valori fissi, verdetti ammessi, defect_present (true/false solo
per False Positive, altrimenti null), percorsi relativi sicuri, cancelli G1-G4 per High/Medium/Low/False Positive,
missing_evidence per Unknown, le cinque verifiche standard (standard_checks), e che i file citati dai candidati
esistano nei sorgenti.

Stampa anche la cartella di output della remediation: `sast-output/remediation`, accanto alla cartella
`triage` che contiene triage.json. La remediation non scrive mai nella cartella del triage.

Candidati alla remediation: finding High/Medium/Low e osservazioni aggiuntive confermate.
Esclusi: False Positive e Unknown - Needs Review.

Con --suggest-sources CARTELLA_DI_LAVORO elenca solo le cartelle di primo livello che contengono file citati dai
candidati, per proporre la cartella dei sorgenti (nessuna ricerca ricorsiva).

Esito: 0 ok | 1 contratto non utilizzabile | 2 uso errato | 3 contratto valido ma file non trovati nei sorgenti
"""

import argparse
import io
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from triage_contract import CONFIRMED, UNKNOWN, validate  # noqa: E402


def remediation_output(triage_path, sources):
    """Cartella in cui scrive la remediation: sast-output/remediation, accanto a quella 'triage' che contiene triage.json.
    Se triage.json non sta in una cartella 'triage', o il risultato cadrebbe dentro i sorgenti, si usa
    'sast-output/remediation' accanto ai sorgenti. Mai dentro la cartella del triage."""
    folder = os.path.dirname(os.path.abspath(triage_path))
    if os.path.basename(folder).lower() == "triage":
        out = os.path.join(os.path.dirname(folder), "remediation")
    else:
        out = os.path.join(os.path.dirname(os.path.abspath(sources)), "sast-output", "remediation")
    src = os.path.normcase(os.path.realpath(sources))
    real = os.path.normcase(os.path.realpath(out))
    if real == src or real.startswith(src + os.sep):
        out = os.path.join(os.path.dirname(os.path.abspath(sources)), "sast-output", "remediation")
    return out.replace("\\", "/")


def candidate_files(item):
    files = {item["location"]["file"]}
    files.update(e["file"] for e in item["evidence"])
    return sorted(files)


def suggest_sources(data, workdir):
    """Cartelle di PRIMO livello della cartella di lavoro che contengono file citati dai candidati. Nessuna ricerca ricorsiva."""
    cands = [f for f in data["findings"] if f["verdict"] in CONFIRMED] + data["additional_observations"]
    cited = sorted({rel for c in cands for rel in candidate_files(c)})
    found = []
    for name in sorted(os.listdir(workdir)):
        folder = os.path.join(workdir, name)
        if name.startswith(".") or name.lower() == "sast-output" or not os.path.isdir(folder):
            continue
        hits = sum(1 for rel in cited if os.path.isfile(os.path.join(folder, *rel.split("/"))))
        if hits:
            found.append((name, hits))
    found.sort(key=lambda x: (-x[1], x[0]))
    return found, len(cited)


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("triage", help="file triage.json")
    ap.add_argument("--sources", help="cartella dei sorgenti a cui si riferiscono i percorsi")
    ap.add_argument("--suggest-sources", metavar="CARTELLA_DI_LAVORO",
                    help="elenca le cartelle di primo livello che contengono file citati dal triage (nessuna ricerca ricorsiva)")
    args = ap.parse_args(argv)
    if not args.sources and not args.suggest_sources:
        ap.error("serve --sources (oppure --suggest-sources per proporre la cartella dei sorgenti)")

    try:
        with io.open(args.triage, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except OSError:
        print("Errore: file non trovato o non leggibile: {0}".format(args.triage), file=sys.stderr)
        return 1
    except ValueError as e:
        print("Errore: triage.json non è un JSON valido ({0}).".format(e), file=sys.stderr)
        return 1
    errors = validate(data)
    if errors:
        print("triage.json NON utilizzabile ({0} problemi). Non viene riparato:".format(len(errors)), file=sys.stderr)
        for e in errors:
            print(" - " + e, file=sys.stderr)
        print("Correggi il triage con /sast-triage e riprova.", file=sys.stderr)
        return 1
    if args.suggest_sources:
        if not os.path.isdir(args.suggest_sources):
            print("Errore: cartella di lavoro non trovata: {0}".format(args.suggest_sources), file=sys.stderr)
            return 1
        found, total = suggest_sources(data, args.suggest_sources)
        print("File citati dai candidati: {0}.".format(total))
        if found:
            print("Cartelle di primo livello della cartella di lavoro che li contengono:")
            for name, hits in found:
                print(" - {0}: {1} su {2} file citati".format(name, hits, total))
        else:
            print("Nessuna cartella di primo livello contiene i file citati: chiedi il percorso («Altro percorso»).")
        return 0
    if not os.path.isdir(args.sources):
        print("Errore: cartella dei sorgenti non trovata: {0}".format(args.sources), file=sys.stderr)
        return 1

    findings, observations, ctx = data["findings"], data["additional_observations"], data["context"]
    cands = [f for f in findings if f["verdict"] in CONFIRMED] + observations
    fps = [f for f in findings if f["verdict"] == "False Positive"]
    unknown = [f for f in findings if f["verdict"] == UNKNOWN]
    by = Counter(f["verdict"] for f in findings if f["verdict"] in CONFIRMED)

    print("Triage valido: {0} finding, {1} {2}.".format(
        len(findings), len(observations), "osservazione aggiuntiva" if len(observations) == 1 else "osservazioni aggiuntive"))
    meta = data["metadata"]
    print("Output remediation: {0} (la cartella del triage non viene mai modificata).".format(
        remediation_output(args.triage, args.sources)))
    print("Progetto: {0}; report scanner {1} ({2}); toolkit {3}.".format(
        meta["project_name"], meta["scanner_report_name"],
        meta["scanner_report_date"] or "data non disponibile", meta["toolkit_version"]))
    print("Contesto: stack {0}; esposizione {1}{2}; rilascio {3}.".format(
        ", ".join(ctx["stack"]) or "n/d", ctx["exposure"],
        " ({0})".format(ctx["exposure_detail"]) if ctx["exposure_detail"].strip() else "",
        ctx["release_model"] or "n/d"))
    for label, key in (("Vincoli", "constraints"), ("Assunzioni", "assumptions")):
        if ctx[key]:
            print("{0}: {1}".format(label, "; ".join(ctx[key])))
    print("\nCandidati alla remediation ({0}): finding High {1} · Medium {2} · Low {3} + osservazioni {4}".format(
        len(cands), by["High"], by["Medium"], by["Low"], len(observations)))
    for c in cands:
        tag = " (osservazione aggiuntiva)" if c["id"].startswith("OBS-") else ""
        loc = c["location"]
        print(" - {0} [{1}]{2} {3} - {4}:{5}".format(c["id"], c["verdict"], tag, c["title"], loc["file"], loc["line"] or "?"))
    print("\nEsclusi: {0} {1}{2}.".format(len(fps), "falso positivo" if len(fps) == 1 else "falsi positivi",
                                         " ({0})".format(", ".join(f["id"] for f in fps)) if fps else ""))
    if unknown:
        print("Non ancora in remediation ({0} da verificare):".format(len(unknown)))
        for f in unknown:
            print(" - {0}: {1}".format(f["id"], "; ".join(f["missing_evidence"])))

    missing = {}
    for c in cands:
        for rel in candidate_files(c):
            if not os.path.isfile(os.path.join(args.sources, *rel.split("/"))):
                missing.setdefault(rel, []).append(c["id"])
    total = len({r for c in cands for r in candidate_files(c)})
    print("\nFile citati dai candidati: {0} trovati, {1} non trovati.".format(total - len(missing), len(missing)))
    for rel, who in sorted(missing.items()):
        print(" - non trovato: {0} (usato da {1})".format(rel, ", ".join(who)))
    if missing:
        print("Verifica la cartella dei sorgenti: deve corrispondere ai percorsi del triage.")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
