# -*- coding: utf-8 -*-
"""Contratto di triage.json: costanti e validatore del file FINALE (references/output-contract.md).

Modulo condiviso: la copia in sast-triage e quella in sast-remediation sono identiche.
Non è uno script da lanciare. Lo usano build_triage.py (controllo finale), make_report.py,
make_plan.py e read_triage.py, così le regole sono scritte una volta sola.
"""

import datetime
import re
from collections import Counter

VERDICTS = ("High", "Medium", "Low", "False Positive", "Unknown - Needs Review")
CONFIRMED = ("High", "Medium", "Low")
UNKNOWN = "Unknown - Needs Review"
FALSE_POSITIVE = "False Positive"
GATES = ("g1", "g2", "g3", "g4")
EXPOSURES = ("Internet", "Rete interna", "Solo locale", "Non nota")
TOP = ("schema_version", "metadata", "context", "findings", "additional_observations", "standard_checks")
META = ("project_name", "scanner_report_name", "scanner_report_date", "toolkit_version")
CTX = ("stack", "exposure", "exposure_detail", "release_model", "constraints", "assumptions")
FINDING_KEYS = ("id", "title", "scanner_severity", "verdict", "defect_present", "location",
                "analysis_summary", "evidence", "gates", "missing_evidence")
OBS_KEYS = ("id", "title", "verdict", "location", "analysis_summary", "evidence")

# Le cinque verifiche standard oltre lo scanner: identificatore -> etichetta italiana, in ordine canonico.
AREAS = ("authentication_authorization", "secrets", "transport_cors", "sql_commands", "cryptography")
AREA_LABELS = {
    "authentication_authorization": "Autenticazione e autorizzazione degli endpoint esposti",
    "secrets": "Segreti nel codice e nella configurazione",
    "transport_cors": "Sicurezza del trasporto e CORS",
    "sql_commands": "Esecuzione di SQL o comandi con dati non fidati o di origine esterna",
    "cryptography": "Crittografia, chiavi e IV",
}
CHECK_STATUSES = ("confirmed_observation", "no_observation", "not_verifiable")
CHECK_KEYS = ("area", "status", "observation_ids", "missing_evidence")
MAX_MISSING_CHARS = 200          # una prova mancante è una frase breve


def filled(x):
    return isinstance(x, str) and bool(x.strip())


def id_number(item_id):
    """Numero di un id AS-001 / OBS-001, per l'ordinamento (mai alfabetico, mai dipendente dalla lingua)."""
    return int(item_id.split("-")[1])


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


def check_line(line):
    return line is None or (isinstance(line, int) and not isinstance(line, bool) and line >= 1)


def check_location(loc, where, err):
    if not isinstance(loc, dict) or set(loc) != {"file", "line"}:
        err.append("{0}: location deve avere esattamente file e line.".format(where))
        return
    problem = path_problem(loc["file"])
    if problem:
        err.append("{0}: location.file {1}: {2!r}.".format(where, problem, loc["file"]))
    if not check_line(loc["line"]):
        err.append("{0}: location.line deve essere un intero >= 1 oppure null.".format(where))


def check_evidence(ev, where, err):
    if not isinstance(ev, list):
        err.append("{0}: evidence deve essere un elenco.".format(where))
        return 0
    for i, e in enumerate(ev, 1):
        w = "{0}, evidence #{1}".format(where, i)
        if not isinstance(e, dict) or set(e) != {"file", "line", "note"}:
            err.append("{0}: deve avere esattamente file, line e note.".format(w))
            continue
        problem = path_problem(e["file"])
        if problem:
            err.append("{0}: il file {1}: {2!r}.".format(w, problem, e["file"]))
        if not check_line(e["line"]):
            err.append("{0}: line deve essere un intero >= 1 oppure null.".format(w))
        if not filled(e["note"]):
            err.append("{0}: la nota è vuota.".format(w))
    return len(ev)


def check_finding(f, err):
    fid = f.get("id")
    where = "Il finding {0}".format(fid)
    if not (isinstance(fid, str) and re.match(r"^AS-\d{3,}$", fid)):
        err.append("Un finding ha un id non valido: {0!r} (atteso AS-001).".format(fid))
        return None
    for k in FINDING_KEYS:
        if k not in f:
            err.append("{0}: manca il campo '{1}'.".format(where, k))
    for k in f:
        if k not in FINDING_KEYS:
            err.append("{0}: campo non previsto dal contratto: '{1}'.".format(where, k))
    verdict = f.get("verdict")
    if verdict not in VERDICTS:
        err.append("{0} ha un verdict non valido: {1!r}.".format(where, verdict))
        return None
    if not filled(f.get("title")) or not filled(f.get("scanner_severity")):
        err.append("{0}: title e scanner_severity devono essere non vuoti.".format(where))
    if "defect_present" in f:
        dp = f["defect_present"]
        if verdict == FALSE_POSITIVE and not isinstance(dp, bool):
            err.append("{0} ha verdict {1}: defect_present deve essere true o false (trovato {2!r}).".format(
                where, verdict, dp))
        elif verdict != FALSE_POSITIVE and dp is not None:
            err.append("{0} ha verdict {1}: defect_present deve essere null (vale solo per {2}).".format(
                where, verdict, FALSE_POSITIVE))
    if not filled(f.get("analysis_summary")):
        err.append("{0} ha verdict {1} ma analysis_summary è vuoto.".format(where, verdict))
    if "location" in f:
        check_location(f["location"], where, err)
    n_ev = check_evidence(f.get("evidence", []), where, err)
    gates, missing = f.get("gates"), f.get("missing_evidence")
    if not isinstance(gates, dict) or set(gates) != set(GATES) or not all(isinstance(v, str) for v in gates.values()):
        err.append("{0}: gates deve contenere esattamente g1, g2, g3, g4 (testo).".format(where))
        gates = None
    if not isinstance(missing, list) or not all(filled(m) for m in missing):
        err.append("{0}: missing_evidence deve essere un elenco di frasi non vuote.".format(where))
        missing = None
    if verdict == UNKNOWN:
        if missing is not None and not missing:
            err.append("{0} ha verdict {1} ma missing_evidence è vuoto.".format(where, verdict))
    else:
        if n_ev == 0 and isinstance(f.get("evidence"), list):
            err.append("{0} ha verdict {1} ma evidence è vuota.".format(where, verdict))
        for g in GATES:
            if gates and not filled(gates[g]):
                err.append("{0} ha verdict {1} ma gates.{2} è vuoto.".format(where, verdict, g))
        if missing:
            err.append("{0} ha verdict {1} ma missing_evidence non è vuoto.".format(where, verdict))
    return verdict


def check_observation(o, err):
    oid = o.get("id")
    where = "L'osservazione {0}".format(oid)
    if not (isinstance(oid, str) and re.match(r"^OBS-\d{3,}$", oid)):
        err.append("Un'osservazione ha un id non valido: {0!r} (atteso OBS-001).".format(oid))
        return
    for k in OBS_KEYS:
        if k not in o:
            err.append("{0}: manca il campo '{1}'.".format(where, k))
    for k in o:
        if k not in OBS_KEYS:
            err.append("{0}: campo non previsto dal contratto: '{1}'.".format(where, k))
    if o.get("verdict") not in CONFIRMED:
        err.append("{0} ha verdict {1!r}: sono ammessi solo High, Medium, Low.".format(where, o.get("verdict")))
    if not filled(o.get("title")) or not filled(o.get("analysis_summary")):
        err.append("{0}: title e analysis_summary devono essere non vuoti.".format(where))
    if "location" in o:
        check_location(o["location"], where, err)
    if check_evidence(o.get("evidence", []), where, err) == 0 and isinstance(o.get("evidence"), list):
        err.append("{0}: evidence è vuota.".format(where))


def check_metadata(meta, err):
    if not isinstance(meta, dict) or set(meta) != set(META):
        err.append("metadata deve contenere esattamente: {0}.".format(", ".join(META)))
        return
    for k in ("project_name", "scanner_report_name", "toolkit_version"):
        if not filled(meta[k]):
            err.append("metadata.{0} deve essere un testo non vuoto.".format(k))
    d = meta["scanner_report_date"]
    if d is not None:
        try:
            ok = isinstance(d, str) and re.match(r"^\d{4}-\d{2}-\d{2}$", d) and datetime.date.fromisoformat(d)
        except ValueError:
            ok = False
        if not ok:
            err.append("metadata.scanner_report_date deve essere AAAA-MM-GG oppure null (trovato {0!r}).".format(d))


def check_standard_checks(checks, obs_ids, err):
    """Le cinque verifiche standard: ognuna una volta, in ordine canonico, con stato e riferimenti coerenti."""
    if not isinstance(checks, list):
        err.append("standard_checks deve essere un elenco di {0} voci.".format(len(AREAS)))
        return
    areas = [c.get("area") if isinstance(c, dict) else None for c in checks]
    if areas != list(AREAS):
        err.append("standard_checks deve contenere esattamente le cinque aree, una volta sola e in quest'ordine: {0} "
                   "(trovato: {1}).".format(", ".join(AREAS), ", ".join(str(a) for a in areas) or "nessuna"))
    for c in checks:
        if not isinstance(c, dict):
            err.append("Una voce di standard_checks non è un oggetto.")
            continue
        area = c.get("area")
        where = "standard_checks.{0}".format(area)
        for k in CHECK_KEYS:
            if k not in c:
                err.append("{0}: manca il campo '{1}'.".format(where, k))
        for k in c:
            if k not in CHECK_KEYS:
                err.append("{0}: campo non previsto dal contratto: '{1}'.".format(where, k))
        status, ids, missing = c.get("status"), c.get("observation_ids"), c.get("missing_evidence")
        if status not in CHECK_STATUSES:
            err.append("{0}: status non valido {1!r}. Valori ammessi: {2}.".format(where, status, ", ".join(CHECK_STATUSES)))
        if not (isinstance(ids, list) and all(isinstance(i, str) and re.match(r"^OBS-\d{3,}$", i) for i in ids)):
            err.append("{0}: observation_ids deve essere un elenco di id nella forma OBS-001.".format(where))
            ids = None
        elif len(set(ids)) != len(ids):
            err.append("{0}: observation_ids contiene id ripetuti.".format(where))
        if not (isinstance(missing, list) and all(filled(m) for m in missing)):
            err.append("{0}: missing_evidence deve essere un elenco di frasi non vuote.".format(where))
            missing = None
        elif any(len(m) > MAX_MISSING_CHARS for m in missing):
            err.append("{0}: ogni voce di missing_evidence deve essere breve (al massimo {1} caratteri).".format(
                where, MAX_MISSING_CHARS))
        if ids is not None:
            for i in ids:
                if i not in obs_ids:
                    err.append("{0}: {1} non esiste in additional_observations.".format(where, i))
        if status == "confirmed_observation" and ids is not None and not ids:
            err.append("{0}: confirmed_observation richiede almeno un OBS-xxx in observation_ids.".format(where))
        if status == "no_observation":
            if ids:
                err.append("{0}: no_observation richiede observation_ids vuoto.".format(where))
            if missing:
                err.append("{0}: no_observation richiede missing_evidence vuoto.".format(where))
        if status == "not_verifiable":
            if ids:
                err.append("{0}: not_verifiable non può avere osservazioni (observation_ids deve essere vuoto).".format(where))
            if missing is not None and not missing:
                err.append("{0}: not_verifiable richiede almeno una voce breve in missing_evidence.".format(where))


def validate(data):
    """Errori (in italiano) del triage.json finale; elenco vuoto se è valido."""
    err = []
    if not isinstance(data, dict):
        return ["Il file deve contenere un oggetto JSON."]
    if data.get("schema_version") != "1.0":
        err.append("schema_version non supportata: {0!r} (questa skill legge solo \"1.0\").".format(data.get("schema_version")))
    for k in TOP:
        if k not in data:
            err.append("Manca il campo '{0}' al livello principale.".format(k))
    for k in data:
        if k not in TOP:
            err.append("Campo non previsto al livello principale: '{0}'.".format(k))
    check_metadata(data.get("metadata"), err)
    ctx = data.get("context")
    if not isinstance(ctx, dict) or any(k not in ctx for k in CTX) or any(k not in CTX for k in ctx):
        err.append("context deve contenere esattamente: {0}.".format(", ".join(CTX)))
    else:
        if ctx["exposure"] not in EXPOSURES:
            err.append("context.exposure non valido: {0!r}. Valori ammessi: {1}.".format(ctx["exposure"], ", ".join(EXPOSURES)))
        for k in ("exposure_detail", "release_model"):
            if not isinstance(ctx[k], str):
                err.append("context.{0} deve essere un testo.".format(k))
        for k in ("stack", "constraints", "assumptions"):
            if not (isinstance(ctx[k], list) and all(isinstance(x, str) for x in ctx[k])):
                err.append("context.{0} deve essere un elenco di testi.".format(k))
    if not isinstance(data.get("findings"), list) or not isinstance(data.get("additional_observations"), list):
        err.append("findings e additional_observations devono essere elenchi.")
        return err
    ids = [f.get("id") for f in data["findings"] if isinstance(f, dict)] + \
          [o.get("id") for o in data["additional_observations"] if isinstance(o, dict)]
    for d in sorted({i for i, n in Counter(ids).items() if n > 1 and i}):
        err.append("Id duplicato: {0}.".format(d))
    for f in data["findings"]:
        if isinstance(f, dict):
            check_finding(f, err)
        else:
            err.append("Un finding non è un oggetto.")
    for o in data["additional_observations"]:
        if isinstance(o, dict):
            check_observation(o, err)
        else:
            err.append("Un'osservazione non è un oggetto.")
    obs_ids = {o.get("id") for o in data["additional_observations"] if isinstance(o, dict)}
    if "standard_checks" in data:
        check_standard_checks(data["standard_checks"], obs_ids, err)
    return err
