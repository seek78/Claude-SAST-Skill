# -*- coding: utf-8 -*-
"""Genera TRIAGE_REPORT.md e TRIAGE_REPORT.csv dal solo triage.json (già valido). Nessun testo scritto a mano.

Uso:
  python make_report.py TRIAGE.json [-o CARTELLA]

  -o  cartella di uscita (default: la cartella di TRIAGE.json). Scrive TRIAGE_REPORT.md e TRIAGE_REPORT.csv.

Il contenuto di giudizio (sintesi, motivi) arriva da triage.json; sezioni, ordine, etichette, conteggi e
formattazione li decide questo script. Stesso triage.json => stessi byte, sempre:
  - nessuna data o ora corrente, nessuna data di file;
  - ordinamento per numero di id (AS-001, AS-002...), mai alfabetico e mai dipendente dalla lingua;
  - Markdown in UTF-8 senza BOM con fine riga "\\n"; CSV in UTF-8 con BOM, separatore ';', fine riga "\\r\\n".
Le celle del CSV che iniziano con = + - @ sono neutralizzate (apice iniziale) contro le formule di Excel.

Esito: 0 scritto | 1 triage.json non valido (nessun file scritto) | 2 uso errato
"""

import argparse
import csv
import io
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from triage_contract import (AREA_LABELS, AREAS, CONFIRMED, FALSE_POSITIVE, UNKNOWN, VERDICTS,  # noqa: E402
                             id_number, validate)

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")
NOTE_DEFECT = "Difetto presente, nessun impatto di sicurezza."
STATUS_LABELS = {"confirmed_observation": "Osservazione confermata", "no_observation": "Nessuna osservazione",
                 "not_verifiable": "Non verificabile"}
CSV_COLUMNS = ("ID", "Titolo", "Gravità scanner", "Verdetto", "File", "Riga", "Sintesi", "Difetto presente", "Prove mancanti")


def one_line(text):
    return " ".join(str(text).split())


def table_cell(text):
    return one_line(text).replace("|", "\\|")


def position(item):
    loc = item["location"]
    return "{0}:{1}".format(loc["file"], loc["line"]) if loc["line"] else loc["file"]


def ordered(items):
    return sorted(items, key=lambda i: id_number(i["id"]))


def severity_line(findings):
    got = Counter(f["scanner_severity"] for f in findings)
    labels = list(SEVERITY_ORDER) + sorted(set(got) - set(SEVERITY_ORDER))
    return " · ".join("{0} {1}".format(s, got.get(s, 0)) for s in labels)


def finding_block(f, extra=()):
    lines = ["### `{0}` · {1}".format(f["id"], one_line(f["title"])),
             "- Verdetto: `{0}` · Scanner: `{1}`".format(f["verdict"], f["scanner_severity"]),
             "- Posizione: `{0}`".format(position(f)),
             "- Sintesi: {0}".format(one_line(f["analysis_summary"]))]
    lines.extend(extra)
    return lines + [""]


def render_markdown(data):
    meta, ctx = data["metadata"], data["context"]
    findings, observations = ordered(data["findings"]), ordered(data["additional_observations"])
    by = Counter(f["verdict"] for f in findings)
    confirmed = [f for f in findings if f["verdict"] in CONFIRMED]
    false_pos = [f for f in findings if f["verdict"] == FALSE_POSITIVE]
    unknown = [f for f in findings if f["verdict"] == UNKNOWN]
    L = ["# Report di triage SAST", "", "## Contesto", ""]
    L.append("- Progetto: `{0}`".format(meta["project_name"]))
    L.append("- Report scanner: `{0}` ({1})".format(meta["scanner_report_name"],
                                                    meta["scanner_report_date"] or "data non disponibile"))
    L.append("- Versione toolkit: `{0}`".format(meta["toolkit_version"]))
    L.append("- Stack: {0}".format("; ".join(one_line(s) for s in ctx["stack"]) or "n/d"))
    detail = " — {0}".format(one_line(ctx["exposure_detail"])) if ctx["exposure_detail"].strip() else ""
    L.append("- Esposizione: {0}{1}".format(ctx["exposure"], detail))
    L.append("- Rilascio: {0}".format(one_line(ctx["release_model"]) or "n/d"))
    L.append("- Vincoli: {0}".format("; ".join(one_line(c) for c in ctx["constraints"]) or "Nessuno"))
    L.append("- Assunzioni: {0}".format("; ".join(one_line(a) for a in ctx["assumptions"]) or "Nessuna"))
    L += ["", "## Riepilogo", "", "| Verdetto | Finding |", "|---|---|"]
    for v in VERDICTS:
        L.append("| `{0}` | {1} |".format(v, by.get(v, 0)))
    L.append("| Totale | {0} |".format(len(findings)))
    L += ["", "- Gravità dello scanner: {0}".format(severity_line(findings)),
          "- Falsi positivi con difetto presente: {0}".format(sum(1 for f in false_pos if f["defect_present"])),
          "- Osservazioni aggiuntive confermate: {0}".format(len(observations)), ""]

    L += ["## Finding confermati", ""]
    if confirmed:
        for f in confirmed:
            L += finding_block(f)
    else:
        L += ["Nessuno.", ""]

    L += ["## Falsi positivi", ""]
    if false_pos:
        for f in false_pos:
            L += finding_block(f, ["- Nota: {0}".format(NOTE_DEFECT)] if f["defect_present"] else [])
    else:
        L += ["Nessuno.", ""]

    if unknown:
        L += ["## Da verificare", ""]
        for f in unknown:
            L += finding_block(f, ["- Prove mancanti: {0}".format("; ".join(one_line(m) for m in f["missing_evidence"]))])

    L += ["## Verifiche standard oltre lo scanner", "", "| Area | Esito | Dettaglio |", "|---|---|---|"]
    for check in data["standard_checks"]:
        if check["status"] == "confirmed_observation":
            detail = ", ".join("`{0}`".format(i) for i in sorted(check["observation_ids"], key=id_number))
        elif check["status"] == "not_verifiable":
            detail = table_cell("; ".join(check["missing_evidence"]))
        else:
            detail = "—"
        L.append("| {0} | {1} | {2} |".format(AREA_LABELS[check["area"]], STATUS_LABELS[check["status"]], detail))
    L.append("")

    if observations:
        L += ["## Osservazioni aggiuntive", ""]
        for o in observations:
            L += ["### `{0}` · {1}".format(o["id"], one_line(o["title"])),
                  "- Verdetto: `{0}`".format(o["verdict"]),
                  "- Posizione: `{0}`".format(position(o)),
                  "- Sintesi: {0}".format(one_line(o["analysis_summary"])), ""]
    return "\n".join(L).rstrip("\n") + "\n"


def safe_cell(value):
    """Testo su una riga; se inizia con = + - @ si antepone un apice: Excel non lo esegue come formula."""
    text = one_line("" if value is None else value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def render_csv(data):
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, delimiter=";", quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for f in ordered(data["findings"]):
        dp = "" if f["defect_present"] is None else ("Sì" if f["defect_present"] else "No")
        writer.writerow([safe_cell(x) for x in (
            f["id"], f["title"], f["scanner_severity"], f["verdict"], f["location"]["file"],
            f["location"]["line"], f["analysis_summary"], dp, "; ".join(f["missing_evidence"]))])
    for o in ordered(data["additional_observations"]):
        writer.writerow([safe_cell(x) for x in (
            o["id"], o["title"], "", o["verdict"], o["location"]["file"], o["location"]["line"],
            o["analysis_summary"], "", "")])
    return buf.getvalue().encode("utf-8-sig")


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("triage", help="triage.json (già prodotto da build_triage.py)")
    ap.add_argument("-o", "--output", help="cartella di uscita (default: quella di triage.json)")
    args = ap.parse_args(argv)
    try:
        with io.open(args.triage, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except OSError:
        print("Errore: file non trovato o non leggibile: {0}".format(args.triage), file=sys.stderr)
        return 2
    except ValueError as e:
        print("Errore: triage.json non è un JSON valido ({0}).".format(e), file=sys.stderr)
        return 1
    errors = validate(data)
    if errors:
        print("triage.json NON valido ({0} problemi). Nessun file scritto:".format(len(errors)), file=sys.stderr)
        for e in errors:
            print(" - " + e, file=sys.stderr)
        return 1
    folder = args.output or os.path.dirname(os.path.abspath(args.triage))
    md, csv_bytes = render_markdown(data).encode("utf-8"), render_csv(data)
    os.makedirs(folder, exist_ok=True)
    for name, payload in (("TRIAGE_REPORT.md", md), ("TRIAGE_REPORT.csv", csv_bytes)):
        with open(os.path.join(folder, name), "wb") as fh:
            fh.write(payload)
    by = Counter(f["verdict"] for f in data["findings"])
    print("Report scritto: {0} finding ({1}), {2} osservazioni aggiuntive.".format(
        len(data["findings"]), ", ".join("{0} {1}".format(v, by[v]) for v in VERDICTS if by[v]),
        len(data["additional_observations"])))
    print("  {0}".format(os.path.join(folder, "TRIAGE_REPORT.md").replace("\\", "/")))
    print("  {0}".format(os.path.join(folder, "TRIAGE_REPORT.csv").replace("\\", "/")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
