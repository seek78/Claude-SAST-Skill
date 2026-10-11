# -*- coding: utf-8 -*-
"""Valida l'analisi di Claude e scrive il file triage.json del contratto.

Lo script NON decide verdetti e NON ripara nulla: se qualcosa non torna elenca gli errori
in italiano, esce con 1 e non scrive il file. Claude deve correggere l'analisi.
Il file assemblato è controllato con le stesse regole (triage_contract.py) usate da make_report.py
e da read_triage.py, comprese le cinque verifiche standard (standard_checks).

Uso:
  python build_triage.py --parsed parsed.json --analysis analysis.json --security-review security-review.json -o triage.json

  --parsed           uscita di parse_appscan.py o di parse_sarif.py (elenco autorevole dei finding)
  --analysis         JSON dell'analisi, nella forma del contratto (references/output-contract.md).
                     Per ogni finding servono: id, verdict, analysis_summary, evidence, gates,
                     missing_evidence, defect_present, e al livello principale standard_checks.
                     title, scanner_severity e location, se presenti, devono
                     coincidere con il report; se assenti vengono presi dal report.
  --security-review  esiti della terza analisi (references/security-review.md,
                     templates/security-review-input.json): una voce per ogni candidata, anche scartata.
                     Non entra in triage.json: serve a controllare esiti, riferimenti e provenienza
                     delle osservazioni (ogni OBS viene da una verifica standard o dalla security review).
  -o                 triage.json di uscita

I metadati (project_name, scanner_report_name, scanner_report_date, toolkit_version) NON si
scrivono nell'analisi: li aggiunge lo script da parsed.json e dalla costante TOOLKIT_VERSION.

Esito: 0 scritto | 1 analisi non valida (nessun file scritto) | 2 uso errato o file illeggibile
"""

import argparse
import copy
import datetime
import io
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_secrets import find_secrets  # noqa: E402
from triage_contract import AREAS, validate as validate_final  # noqa: E402

TOOLKIT_VERSION = "1.1.0"   # unico punto in cui si definisce la versione del toolkit

VERDICTS = ("High", "Medium", "Low", "False Positive", "Unknown - Needs Review")
CONFIRMED = ("High", "Medium", "Low")
FALSE_POSITIVE = "False Positive"
UNKNOWN = "Unknown - Needs Review"
GATES = ("g1", "g2", "g3", "g4")
EXPOSURES = ("Internet", "Rete interna", "Solo locale", "Non nota")
TOP = ("schema_version", "context", "findings", "additional_observations", "standard_checks")   # ciò che scrive Claude
CTX = ("stack", "exposure", "exposure_detail", "release_model", "constraints", "assumptions")
FINDING_KEYS = ("id", "title", "scanner_severity", "verdict", "defect_present", "location",
                "analysis_summary", "evidence", "gates", "missing_evidence")
OBS_KEYS = ("id", "title", "verdict", "location", "analysis_summary", "evidence")
IT_VERDICT = {"High": "Grave", "Medium": "Medio", "Low": "Basso",
              "False Positive": "Falso positivo", UNKNOWN: "Da verificare"}
# Terza analisi (references/security-review.md): una voce per ogni vulnerabilità candidata.
REVIEW_KEYS = ("title", "category", "area", "location", "severity", "confidence", "outcome", "ref", "reason")
REVIEW_OUTCOMES = ("observation", "duplicate", "discarded")
REVIEW_MIN_CONFIDENCE = 8               # soglia di /security-review: sotto, la candidata è scartata
REVIEW_PREFIX = "Security review:"      # inizio di analysis_summary delle OBS nate dalla security review
MAX_REVIEW_TITLE, MAX_REVIEW_CATEGORY, MAX_REVIEW_REASON = 120, 60, 200


def filled(x):
    return isinstance(x, str) and bool(x.strip())


def path_problem(p):
    if not filled(p):
        return "è vuoto"
    if re.match(r"^[A-Za-z]:", p):
        return "contiene una lettera di unità"
    if p.startswith(("/", "\\")):
        return "è un percorso assoluto"
    if "\\" in p:
        return "usa '\\' invece di '/'"
    if ".." in p.split("/"):
        return "contiene '..'"
    return None


def check_keys(obj, allowed, where, err):
    for k in obj:
        if k not in allowed:
            err.append("{0}: campo non previsto dal contratto: '{1}'.".format(where, k))


def check_location(loc, where, err):
    if not isinstance(loc, dict):
        err.append("{0}: location deve essere un oggetto con file e line.".format(where))
        return
    check_keys(loc, ("file", "line"), where + " location", err)
    problem = path_problem(loc.get("file"))
    if problem:
        err.append("{0}: location.file {1} (servono percorsi relativi ai sorgenti, con '/', senza '..'): {2!r}.".format(
            where, problem, loc.get("file")))
    line = loc.get("line")
    if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
        err.append("{0}: location.line deve essere un numero intero >= 1 oppure null.".format(where))


def check_evidence(ev, where, err):
    """Controlla la forma; restituisce il numero di voci valide."""
    if not isinstance(ev, list):
        err.append("{0}: evidence deve essere un elenco.".format(where))
        return 0
    for i, e in enumerate(ev, 1):
        w = "{0}, evidence #{1}".format(where, i)
        if not isinstance(e, dict):
            err.append("{0}: deve essere un oggetto con file, line e note.".format(w))
            continue
        check_keys(e, ("file", "line", "note"), w, err)
        problem = path_problem(e.get("file"))
        if problem:
            err.append("{0}: il file {1}: {2!r}.".format(w, problem, e.get("file")))
        line = e.get("line")
        if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
            err.append("{0}: line deve essere un numero intero >= 1 oppure null.".format(w))
        if not filled(e.get("note")):
            err.append("{0}: la nota è vuota.".format(w))
    return len(ev)


def check_finding(f, rep, err):
    fid = f["id"]
    verdict = f.get("verdict")
    if verdict not in VERDICTS:
        err.append("Il finding {0} ha un verdict non valido: {1!r}. Valori ammessi: {2}.".format(
            fid, verdict, ", ".join(VERDICTS)))
        return
    # i campi che vengono dal report devono coincidere
    for k, expected in (("title", rep["title"]), ("scanner_severity", rep["scanner_severity"])):
        if k in f and f[k] != expected:
            err.append("Il finding {0} ha {1} {2!r} ma il report indica {3!r}.".format(fid, k, f[k], expected))
    if "location" in f and f["location"] != {"file": rep["file"], "line": rep["line"]}:
        err.append("Il finding {0} ha una location diversa dal report ({1}:{2}).".format(fid, rep["file"], rep["line"]))
    if "defect_present" in f:
        dp = f["defect_present"]
        if verdict == FALSE_POSITIVE and not isinstance(dp, bool):
            err.append("Il finding {0} ha verdict {1}: defect_present deve essere true o false (trovato {2!r}).".format(
                fid, verdict, dp))
        elif verdict != FALSE_POSITIVE and dp is not None:
            err.append("Il finding {0} ha verdict {1}: defect_present deve essere null (vale solo per {2}).".format(
                fid, verdict, FALSE_POSITIVE))
    if not filled(f.get("analysis_summary")):
        err.append("Il finding {0} ha verdict {1} ma analysis_summary è vuoto.".format(fid, verdict))
    n_ev = check_evidence(f.get("evidence"), "Il finding " + fid, err)
    gates = f.get("gates")
    if not isinstance(gates, dict) or set(gates) != set(GATES) or not all(isinstance(v, str) for v in gates.values()):
        err.append("Il finding {0}: gates deve contenere esattamente g1, g2, g3, g4 (testo).".format(fid))
        gates = None
    missing = f.get("missing_evidence")
    if not isinstance(missing, list) or not all(filled(m) for m in missing):
        err.append("Il finding {0}: missing_evidence deve essere un elenco di frasi non vuote.".format(fid))
        missing = None

    if verdict == UNKNOWN:
        if missing is not None and not missing:
            err.append("Il finding {0} ha verdict {1} ma missing_evidence è vuoto: indica cosa impedisce di chiudere.".format(fid, verdict))
        return
    if n_ev == 0 and isinstance(f.get("evidence"), list):
        err.append("Il finding {0} ha verdict {1} ma evidence è vuota.".format(fid, verdict))
    if gates:
        for g in GATES:
            if not filled(gates[g]):
                err.append("Il finding {0} ha verdict {1} ma gates.{2} è vuoto.".format(fid, verdict, g))
    if missing:
        err.append("Il finding {0} ha verdict {1} ma missing_evidence non è vuoto: vale solo per {2}.".format(fid, verdict, UNKNOWN))


def check_observation(o, where, err):
    check_keys(o, OBS_KEYS, where, err)
    for k in OBS_KEYS:
        if k not in o:
            err.append("{0}: manca il campo '{1}'.".format(where, k))
    if o.get("verdict") not in CONFIRMED:
        err.append("{0} ha verdict {1!r}: per le osservazioni aggiuntive sono ammessi solo High, Medium, Low.".format(
            where, o.get("verdict")))
    if not filled(o.get("title")):
        err.append("{0}: title è vuoto.".format(where))
    if not filled(o.get("analysis_summary")):
        err.append("{0}: analysis_summary è vuoto.".format(where))
    if "location" in o:
        check_location(o["location"], where, err)
    if "evidence" in o and check_evidence(o["evidence"], where, err) == 0 and isinstance(o["evidence"], list):
        err.append("{0}: evidence è vuota.".format(where))


def validate(analysis, parsed):
    err = []
    if not isinstance(analysis, dict):
        return ["L'analisi deve essere un oggetto JSON."]
    for k in TOP:
        if k not in analysis:
            err.append("Manca il campo '{0}' al livello principale.".format(k))
    if "metadata" in analysis:
        err.append("L'analisi non deve contenere 'metadata': lo script lo aggiunge da parsed.json e dalla versione del toolkit.")
    check_keys({k: v for k, v in analysis.items() if k != "metadata"}, TOP, "Analisi", err)
    if analysis.get("schema_version") != "1.0":
        err.append("schema_version deve essere \"1.0\" (trovato {0!r}).".format(analysis.get("schema_version")))
    ctx = analysis.get("context")
    if not isinstance(ctx, dict):
        err.append("context deve essere un oggetto.")
    else:
        for k in CTX:
            if k not in ctx:
                err.append("Manca context.{0}.".format(k))
        check_keys(ctx, CTX, "context", err)
        for k in ("stack", "constraints", "assumptions"):
            if k in ctx and not (isinstance(ctx[k], list) and all(isinstance(x, str) for x in ctx[k])):
                err.append("context.{0} deve essere un elenco di testi.".format(k))
        for k in ("exposure_detail", "release_model"):
            if k in ctx and not isinstance(ctx[k], str):
                err.append("context.{0} deve essere un testo.".format(k))
        if "exposure" in ctx and ctx["exposure"] not in EXPOSURES:
            err.append("context.exposure non valido: {0!r}. Valori ammessi: {1}.".format(
                ctx["exposure"], ", ".join(EXPOSURES)))

    findings, observations = analysis.get("findings"), analysis.get("additional_observations")
    if not isinstance(findings, list):
        err.append("findings deve essere un elenco.")
        findings = []
    if not isinstance(observations, list):
        err.append("additional_observations deve essere un elenco.")
        observations = []

    report = {f["id"]: f for f in parsed["findings"]}
    ids = [f.get("id") if isinstance(f, dict) else None for f in findings]
    dup = sorted({i for i, n in Counter(ids).items() if n > 1 and i})
    if dup:
        err.append("Finding duplicati nell'analisi: {0}.".format(", ".join(dup)))
    missing = [i for i in report if i not in ids]
    if missing:
        err.append("Mancano nell'analisi {0} finding del report: {1}.".format(len(missing), ", ".join(missing)))
    extra = sorted({str(i) for i in ids if i not in report})
    if extra:
        err.append("L'analisi contiene finding che non sono nel report: {0}.".format(", ".join(extra)))

    for f in findings:
        if not isinstance(f, dict) or f.get("id") not in report:
            continue
        check_keys(f, FINDING_KEYS, "Il finding " + f["id"], err)
        for k in ("id", "verdict", "defect_present", "analysis_summary", "evidence", "gates", "missing_evidence"):
            if k not in f:
                err.append("Il finding {0}: manca il campo '{1}'.".format(f["id"], k))
        check_finding(f, report[f["id"]], err)

    obs_ids = []
    for n, o in enumerate(observations, 1):
        if not isinstance(o, dict):
            err.append("L'osservazione #{0} deve essere un oggetto.".format(n))
            continue
        oid = o.get("id")
        where = "L'osservazione {0}".format(oid if filled(oid) else "#{0}".format(n))
        if not (isinstance(oid, str) and re.match(r"^OBS-\d{3,}$", oid)):
            err.append("{0}: l'id deve avere la forma OBS-001.".format(where))
        elif oid in report:
            err.append("{0}: l'id coincide con quello di un finding del report.".format(where))
        obs_ids.append(oid)
        check_observation(o, where, err)
    for d in sorted({i for i, n in Counter(obs_ids).items() if n > 1 and i}):
        err.append("Osservazione duplicata: {0}.".format(d))

    if not err:
        for path, text in walk_strings(analysis, ""):
            for _, kind in find_secrets(text):
                err.append("Possibile segreto in chiaro ({0}) in {1}. Il valore non viene mostrato: "
                           "descrivi solo esistenza e posizione.".format(kind, path))
    return err


def check_review_candidate(c, where, finding_ids, observations, checks, err):
    """Una candidata della security review; restituisce l'OBS che ha generato (esito observation) o None."""
    check_keys(c, REVIEW_KEYS, where, err)
    missing = [k for k in REVIEW_KEYS if k not in c]
    for k in missing:
        err.append("{0}: manca il campo '{1}'.".format(where, k))
    if missing:
        return None
    for k, limit in (("title", MAX_REVIEW_TITLE), ("category", MAX_REVIEW_CATEGORY)):
        if not filled(c[k]) or len(c[k]) > limit:
            err.append("{0}: {1} deve essere un testo non vuoto di al massimo {2} caratteri.".format(where, k, limit))
    if c["area"] != "" and c["area"] not in AREAS:
        err.append("{0}: area non valida {1!r}. Valori ammessi: {2} oppure vuoto.".format(where, c["area"], ", ".join(AREAS)))
    check_location(c["location"], where, err)
    if c["severity"] not in CONFIRMED:
        err.append("{0}: severity deve essere High, Medium o Low (trovato {1!r}).".format(where, c["severity"]))
    confidence = c["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, int) or not 1 <= confidence <= 10:
        err.append("{0}: confidence deve essere un intero da 1 a 10.".format(where))
        confidence = None
    if not isinstance(c["reason"], str) or len(c["reason"]) > MAX_REVIEW_REASON:
        err.append("{0}: reason deve essere un testo di al massimo {1} caratteri.".format(where, MAX_REVIEW_REASON))
    outcome, ref = c["outcome"], c["ref"]
    if outcome not in REVIEW_OUTCOMES:
        err.append("{0}: outcome non valido {1!r}. Valori ammessi: {2}.".format(where, outcome, ", ".join(REVIEW_OUTCOMES)))
        return None
    if outcome == "discarded":
        if ref != "":
            err.append("{0}: una candidata scartata ha ref vuoto.".format(where))
        if not filled(c["reason"]):
            err.append("{0}: una candidata scartata dice perché in reason.".format(where))
        return None
    if outcome == "duplicate":
        if ref not in finding_ids and ref not in observations:
            err.append("{0}: ref {1!r} deve essere un finding del report o un'osservazione esistente.".format(where, ref))
        if not filled(c["reason"]):
            err.append("{0}: un duplicato dice in reason perché è lo stesso problema.".format(where))
        return None
    if ref not in observations:
        err.append("{0}: ref {1!r} deve essere un'osservazione di additional_observations.".format(where, ref))
        return None
    if confidence is not None and confidence < REVIEW_MIN_CONFIDENCE:
        err.append("{0}: confidenza {1} sotto la soglia di {2}: la candidata va scartata, non diventa {3}.".format(
            where, confidence, REVIEW_MIN_CONFIDENCE, ref))
    summary = observations[ref].get("analysis_summary")
    if not (isinstance(summary, str) and summary.startswith(REVIEW_PREFIX)):
        err.append("L'osservazione {0} viene dalla security review: analysis_summary deve iniziare con «{1}».".format(
            ref, REVIEW_PREFIX))
    if c["area"] in AREAS and ref not in checks.get(c["area"], {}).get("observation_ids", []):
        err.append("{0}: l'area è {1}, quindi {2} va anche in standard_checks.{1} (confirmed_observation).".format(
            where, c["area"], ref))
    return ref


def validate_security_review(review, analysis, parsed):
    """Terza analisi (references/security-review.md): esiti e riferimenti delle candidate, e provenienza delle OBS.
    Da chiamare con un'analisi già valida."""
    if not isinstance(review, dict) or set(review) != {"candidates"} or not isinstance(review["candidates"], list):
        return ["La security review deve essere un oggetto con il solo campo 'candidates' (un elenco, anche vuoto)."]
    err = []
    finding_ids = {f["id"] for f in parsed["findings"]}
    observations = {o["id"]: o for o in analysis["additional_observations"]}
    checks = {c["area"]: c for c in analysis["standard_checks"] if isinstance(c, dict) and c.get("area") in AREAS}
    from_review = set()
    for n, c in enumerate(review["candidates"], 1):
        where = "Security review, candidata #{0}".format(n)
        if not isinstance(c, dict):
            err.append("{0}: deve essere un oggetto.".format(where))
            continue
        ref = check_review_candidate(c, where, finding_ids, observations, checks, err)
        if ref:
            from_review.add(ref)
    from_checks = {i for c in checks.values() if isinstance(c.get("observation_ids"), list) for i in c["observation_ids"]}
    for oid in observations:
        if oid not in from_checks and oid not in from_review:
            err.append("L'osservazione {0} non viene né da una verifica standard (standard_checks) né dalla security "
                       "review (candidata con outcome observation).".format(oid))
    if not err:
        for path, text in walk_strings(review, "security-review"):
            for _, kind in find_secrets(text):
                err.append("Possibile segreto in chiaro ({0}) in {1}. Il valore non viene mostrato: "
                           "descrivi solo esistenza e posizione.".format(kind, path))
    return err


def walk_strings(obj, path):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, "{0}.{1}".format(path, k) if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, "{0}[{1}]".format(path, i))


def metadata_problems(parsed):
    """I metadati vengono da parsed.json (che li ricava dal report e dal percorso dei sorgenti): niente si inventa."""
    err = []
    if not filled(parsed.get("project_name")):
        err.append("project_name mancante in parsed.json: riesegui parse_appscan.py o parse_sarif.py con --sources.")
    if not filled(parsed.get("report")):
        err.append("Il nome del report manca in parsed.json: riesegui parse_appscan.py o parse_sarif.py.")
    d = parsed.get("report_date")
    if d is not None:
        try:
            ok = isinstance(d, str) and re.match(r"^\d{4}-\d{2}-\d{2}$", d) and datetime.date.fromisoformat(d)
        except ValueError:
            ok = False
        if not ok:
            err.append("report_date in parsed.json non è nella forma AAAA-MM-GG: {0!r}.".format(d))
    return err


def assemble(analysis, parsed):
    """Ordine dei finding come nel report, campi nell'ordine del contratto."""
    by_id = {f["id"]: f for f in analysis["findings"]}
    out = []
    for rep in parsed["findings"]:
        f = by_id[rep["id"]]
        out.append({"id": rep["id"], "title": rep["title"], "scanner_severity": rep["scanner_severity"],
                    "verdict": f["verdict"], "defect_present": f["defect_present"],
                    "location": {"file": rep["file"], "line": rep["line"]},
                    "analysis_summary": f["analysis_summary"], "evidence": f["evidence"],
                    "gates": {g: f["gates"][g] for g in GATES}, "missing_evidence": f["missing_evidence"]})
    obs = [{k: o[k] for k in OBS_KEYS} for o in analysis["additional_observations"]]
    ctx = {k: analysis["context"][k] for k in CTX}
    meta = {"project_name": parsed["project_name"], "scanner_report_name": parsed["report"],
            "scanner_report_date": parsed.get("report_date"), "toolkit_version": TOOLKIT_VERSION}
    return {"schema_version": "1.0", "metadata": meta, "context": ctx, "findings": out,
            "additional_observations": obs, "standard_checks": copy.deepcopy(analysis["standard_checks"])}


def load(path, label):
    try:
        with io.open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except OSError:
        print("Errore: {0} non trovato o non leggibile: {1}".format(label, path), file=sys.stderr)
    except ValueError as e:
        print("Errore: {0} non è un JSON valido ({1}): {2}".format(label, e, path), file=sys.stderr)
    return None


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")   # niente crash su console con codifiche limitate
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--parsed", required=True, help="uscita di parse_appscan.py o di parse_sarif.py")
    ap.add_argument("--analysis", required=True, help="JSON dell'analisi di Claude")
    ap.add_argument("--security-review", required=True, help="esiti della terza analisi (security-review.json)")
    ap.add_argument("-o", "--output", required=True, help="triage.json di uscita")
    args = ap.parse_args(argv)

    parsed, analysis = load(args.parsed, "parsed"), load(args.analysis, "analisi")
    review = load(args.security_review, "security review")
    if parsed is None or analysis is None or review is None:
        return 2
    if not isinstance(parsed, dict) or not isinstance(parsed.get("findings"), list) or not parsed["findings"]:
        print("Errore: il file 'parsed' non è l'uscita di parse_appscan.py o di parse_sarif.py.", file=sys.stderr)
        return 2

    problems = metadata_problems(parsed)
    if problems:
        for p in problems:
            print("Errore: {0}".format(p), file=sys.stderr)
        return 2

    errors = validate(analysis, parsed)
    if errors:
        print("Analisi NON valida ({0} problemi). Nessun file scritto:".format(len(errors)), file=sys.stderr)
        for e in errors:
            print(" - " + e, file=sys.stderr)
        print("Correggi l'analisi e riesegui: lo script non modifica i verdetti.", file=sys.stderr)
        return 1

    final = assemble(analysis, parsed)
    problems = validate_final(final)     # stesse regole che applicano make_report.py e read_triage.py
    if problems:
        print("Analisi NON valida ({0} problemi) per il contratto di triage.json. Nessun file scritto:".format(len(problems)),
              file=sys.stderr)
        for p in problems:
            print(" - " + p, file=sys.stderr)
        print("Correggi l'analisi e riesegui: lo script non modifica i verdetti.", file=sys.stderr)
        return 1
    problems = validate_security_review(review, analysis, parsed)
    if problems:
        print("Security review NON valida ({0} problemi). Nessun file scritto:".format(len(problems)), file=sys.stderr)
        for p in problems:
            print(" - " + p, file=sys.stderr)
        print("Correggi security-review.json o l'analisi e riesegui.", file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with io.open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(final, ensure_ascii=False, indent=2) + "\n")

    counts = Counter(f["verdict"] for f in final["findings"])
    print("Analisi valida: {0} finding ({1}), {2} osservazioni aggiuntive.".format(
        len(final["findings"]), ", ".join("{0} {1}".format(IT_VERDICT[v], counts[v]) for v in VERDICTS if counts[v]),
        len(final["additional_observations"])))
    outcomes = Counter(c["outcome"] for c in review["candidates"])
    print("Security review: {0} candidate ({1} osservazioni, {2} duplicati, {3} scartate).".format(
        len(review["candidates"]), outcomes["observation"], outcomes["duplicate"], outcomes["discarded"]))
    print("Scritto: {0}".format(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
