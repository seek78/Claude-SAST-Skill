# -*- coding: utf-8 -*-
"""Genera PIANO_TRIAGE.md da parsed.json e da un piccolo file di contenuti scritto da Claude. Il piano non contiene verdetti.

Uso:
  python make_plan.py --parsed parsed.json --input plan-input.json -o PIANO_TRIAGE.md

  --parsed  uscita di parse_appscan.py (conteggi, nome del progetto e del report, XML/SCA: li calcola lo script)
  --input   contenuti di giudizio di Claude (templates/plan-input.json): contesto rilevato, gruppi di analisi
            con un breve motivo, al massimo 3 controlli trasversali, al massimo 2 punti aperti
  -o        file di uscita

Sezioni fisse, nello stesso ordine: Input · Contesto · Scanner · Gruppi di analisi · Verifiche standard oltre lo
scanner · Controlli trasversali · Punti aperti · Approvazione. Stesso input => stessi byte (UTF-8, fine riga "\\n",
nessuna data o ora corrente, gruppi e id ordinati per numero). Ogni finding del report deve stare in un solo gruppo.

Esito: 0 scritto | 1 contenuti non validi (nessun file scritto) | 2 uso errato o file illeggibile
"""

import argparse
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_secrets import find_secrets  # noqa: E402
from triage_contract import AREA_LABELS, AREAS, EXPOSURES, filled, id_number  # noqa: E402

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")
INPUT_KEYS = ("context", "groups", "transversal_checks", "open_points")
CTX_KEYS = ("stack", "exposure", "exposure_detail", "release_model", "constraints", "assumptions")
GROUP_KEYS = ("name", "reason", "finding_ids")
MAX_TRANSVERSAL, MAX_OPEN = 3, 2
MAX_NAME, MAX_TEXT = 80, 200


def one_line(text):
    return " ".join(str(text).split())


def cell(text):
    return one_line(text).replace("|", "\\|")


def text_list(value, label, err, maximum=None, limit=MAX_TEXT):
    if not (isinstance(value, list) and all(filled(x) for x in value)):
        err.append("{0} deve essere un elenco di frasi non vuote.".format(label))
        return []
    if maximum is not None and len(value) > maximum:
        err.append("{0}: al massimo {1} voci (trovate {2}).".format(label, maximum, len(value)))
    for x in value:
        if len(one_line(x)) > limit:
            err.append("{0}: una voce supera {1} caratteri: va resa breve.".format(label, limit))
    return value


def validate_input(data, parsed):
    err = []
    if not isinstance(data, dict):
        return ["Il file dei contenuti deve essere un oggetto JSON."]
    for k in INPUT_KEYS:
        if k not in data:
            err.append("Manca il campo '{0}'.".format(k))
    for k in data:
        if k not in INPUT_KEYS:
            err.append("Campo non previsto: '{0}'.".format(k))
    ctx = data.get("context")
    if not isinstance(ctx, dict) or set(ctx) != set(CTX_KEYS):
        err.append("context deve contenere esattamente: {0}.".format(", ".join(CTX_KEYS)))
    else:
        if ctx["exposure"] not in EXPOSURES:
            err.append("context.exposure non valido: {0!r}. Valori ammessi: {1}.".format(ctx["exposure"], ", ".join(EXPOSURES)))
        for k in ("exposure_detail", "release_model"):
            if not isinstance(ctx[k], str):
                err.append("context.{0} deve essere un testo.".format(k))
        for k in ("stack", "constraints", "assumptions"):
            if not (isinstance(ctx[k], list) and all(isinstance(x, str) for x in ctx[k])):
                err.append("context.{0} deve essere un elenco di testi.".format(k))
    report_ids = [f["id"] for f in parsed["findings"]]
    seen = {}
    groups = data.get("groups")
    if not isinstance(groups, list) or not groups:
        err.append("groups deve essere un elenco non vuoto.")
        groups = []
    for n, g in enumerate(groups, 1):
        where = "Il gruppo #{0}".format(n)
        if not isinstance(g, dict) or set(g) != set(GROUP_KEYS):
            err.append("{0} deve contenere esattamente: {1}.".format(where, ", ".join(GROUP_KEYS)))
            continue
        for k, limit in (("name", MAX_NAME), ("reason", MAX_TEXT)):
            if not filled(g[k]):
                err.append("{0}: {1} è vuoto.".format(where, k))
            elif len(one_line(g[k])) > limit:
                err.append("{0}: {1} supera {2} caratteri.".format(where, k, limit))
        ids = g["finding_ids"]
        if not (isinstance(ids, list) and ids and all(isinstance(i, str) for i in ids)):
            err.append("{0}: finding_ids deve essere un elenco non vuoto di id.".format(where))
            continue
        for i in ids:
            if i not in report_ids:
                err.append("{0}: {1} non è nel report dello scanner.".format(where, i))
            elif i in seen:
                err.append("{0} compare nei gruppi #{1} e #{2}: ogni finding sta in un solo gruppo.".format(i, seen[i], n))
            else:
                seen[i] = n
    missing = [i for i in report_ids if i not in seen]
    if missing:
        err.append("{0} finding del report non stanno in nessun gruppo: {1}.".format(len(missing), ", ".join(missing)))
    text_list(data.get("transversal_checks"), "transversal_checks", err, MAX_TRANSVERSAL)
    text_list(data.get("open_points"), "open_points", err, MAX_OPEN)
    if not err:
        strings = [one_line(x) for x in _strings(data)]
        for s in strings:
            for _, kind in find_secrets(s):
                err.append("Possibile segreto in chiaro ({0}) nei contenuti del piano: il valore non viene mostrato.".format(kind))
    return err


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def render(data, parsed):
    ctx = data["context"]
    findings = parsed["findings"]
    L = ["# Piano di triage", "", "## Input"]
    L.append("- Progetto: `{0}`".format(parsed["project_name"]))
    L.append("- Report scanner: `{0}` ({1})".format(parsed["report"], parsed.get("report_date") or "data non disponibile"))
    src = parsed.get("sources")
    L.append("- Sorgenti: {0}".format("file del report trovati {0} su {1}".format(src["found"], len(findings)) if src else "non verificati"))
    xml = parsed.get("xml")
    L.append("- XML: {0}".format("{0} finding abbinati su {1}".format(xml["matched"], len(findings)) if xml else "non fornito"))
    sca = parsed.get("sca_summary")
    L.append("- SCA: {0}".format("{0} problemi (solo contesto)".format(sca["total"]) if sca else "non fornito"))
    L += ["", "## Contesto"]
    L.append("- Stack: {0}".format("; ".join(one_line(s) for s in ctx["stack"]) or "n/d"))
    detail = " — {0}".format(one_line(ctx["exposure_detail"])) if ctx["exposure_detail"].strip() else ""
    L.append("- Esposizione: {0}{1}".format(ctx["exposure"], detail))
    L.append("- Rilascio: {0}".format(one_line(ctx["release_model"]) or "n/d"))
    L.append("- Vincoli: {0}".format("; ".join(one_line(c) for c in ctx["constraints"]) or "Nessuno"))
    L.append("- Assunzioni: {0}".format("; ".join(one_line(a) for a in ctx["assumptions"]) or "Nessuna"))
    by = parsed["counts"]["by_scanner_severity"]
    labels = list(SEVERITY_ORDER) + sorted(set(by) - set(SEVERITY_ORDER))
    L += ["", "## Scanner", "- Finding: {0}".format(len(findings)),
          "- Gravità: {0}".format(" · ".join("{0} {1}".format(s, by.get(s, 0)) for s in labels))]
    L += ["", "## Gruppi di analisi", "| Gruppo | Finding | ID | Motivo |", "|---|---|---|---|"]
    groups = [dict(g, finding_ids=sorted(g["finding_ids"], key=id_number)) for g in data["groups"]]
    for g in sorted(groups, key=lambda g: id_number(g["finding_ids"][0])):
        L.append("| {0} | {1} | {2} | {3} |".format(cell(g["name"]), len(g["finding_ids"]), ", ".join(g["finding_ids"]), cell(g["reason"])))
    L += ["", "Raggruppamento provvisorio: un'istanza che differisce si analizza a parte.",
          "", "## Verifiche standard oltre lo scanner",
          " · ".join(AREA_LABELS[a] for a in AREAS), "",
          "Dopo i finding. Non è un audit generale: producono solo osservazioni `OBS` confermate, separate dai finding.",
          "", "## Controlli trasversali"]
    L += ["- {0}".format(one_line(c)) for c in data["transversal_checks"]] or ["Nessuno."]
    L += ["", "## Punti aperti"]
    L += ["- {0}".format(one_line(p)) for p in data["open_points"]] or ["Nessuno."]
    L += ["", "## Approvazione", "Il piano non anticipa verdetti. Approvi il piano, vuoi modifiche o annulli?"]
    return "\n".join(L) + "\n"


def load(path, label):
    try:
        with io.open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except OSError:
        print("Errore: {0} non trovato o non leggibile: {1}".format(label, path), file=sys.stderr)
    except ValueError as e:
        print("Errore: {0} non è un JSON valido ({1}).".format(label, e), file=sys.stderr)
    return None


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--parsed", required=True, help="uscita di parse_appscan.py")
    ap.add_argument("--input", required=True, help="contenuti del piano (plan-input.json)")
    ap.add_argument("-o", "--output", required=True, help="PIANO_TRIAGE.md di uscita")
    args = ap.parse_args(argv)
    parsed, data = load(args.parsed, "parsed"), load(args.input, "contenuti del piano")
    if parsed is None or data is None:
        return 2
    if not isinstance(parsed, dict) or not isinstance(parsed.get("findings"), list) or not parsed["findings"] \
            or not filled(parsed.get("project_name")) or not filled(parsed.get("report")):
        print("Errore: parsed.json non è valido o manca project_name: riesegui parse_appscan.py con --sources.", file=sys.stderr)
        return 2
    errors = validate_input(data, parsed)
    if errors:
        print("Contenuti del piano NON validi ({0} problemi). Nessun file scritto:".format(len(errors)), file=sys.stderr)
        for e in errors:
            print(" - " + e, file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "wb") as fh:
        fh.write(render(data, parsed).encode("utf-8"))
    print("Piano scritto: {0} ({1} finding in {2} gruppi).".format(args.output, len(parsed["findings"]), len(data["groups"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
