# -*- coding: utf-8 -*-
"""Genera PIANO_REMEDIATION.md, PIANO_FIX.md e VERIFICA.md da triage.json e da piccoli file di contenuti scritti da Claude.

Uso:
  python make_remediation_plan.py plan   --triage TRIAGE.json --input remediation-input.json -o PIANO_REMEDIATION.md
  python make_remediation_plan.py fix    --triage TRIAGE.json --input fix-input.json -o PIANO_FIX.md
  python make_remediation_plan.py verify --triage TRIAGE.json --input verification-input.json --fix-input fix-input.json
                                         --manifest PROPOSTE.json -o VERIFICA.md

Claude fornisce solo il giudizio (ordine e motivi, causa radice, modifica, verifica). Sezioni, ordine, etichette,
conteggi e formattazione sono dello script. Stessi contenuti => stessi byte: nessuna data o ora corrente, UTF-8
senza BOM, fine riga "\\n", id ordinati per numero. I testi sono controllati per forma e lunghezza e non devono
contenere segreti (il valore non viene mai mostrato).

plan    Candidati e esclusioni li ricava lo script da triage.json. Ogni finding candidato (High/Medium/Low) compare
        in un solo passo dell'ordine; ogni osservazione aggiuntiva compare una sola volta nell'elenco separato.
fix     Un solo finding candidato, un solo piano breve: obiettivo circa 400 parole, MASSIMO 500. Oltre il massimo il piano
        NON viene scritto (nessun taglio automatico): Claude deve accorciare i contenuti. Ogni percorso di compatibilità
        legacy dichiara di essere temporaneo e quando va rimosso.
verify  VERIFICA.md: artefatti reali da PROPOSTE.json (diff, sostituzioni proposte con hash dell'originale, sole
        istruzioni), controlli, formati dei dati, rollback, e ciò che NON è stato compilato né testato.

Esito: 0 scritto | 1 contenuti non validi (nessun file scritto) | 2 uso errato o file illeggibile
"""

import argparse
import io
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_secrets import find_secrets  # noqa: E402
from triage_contract import CONFIRMED, FALSE_POSITIVE, UNKNOWN, filled, id_number, path_problem, validate  # noqa: E402

PLAN_KEYS = ("order", "observations", "open_points")
STEP_KEYS = ("finding_ids", "reason", "depends_on")
OBS_KEYS = ("id", "reason")
FIX_KEYS = ("finding_id", "reason", "root_cause", "proposed_change", "delivery", "compatibility", "legacy_paths",
            "verification", "outside_code", "changes_data_format", "open_points")
DELIVERY_KEYS = ("file", "mode", "reason")
DELIVERY_MODES = ("diff", "proposto", "istruzioni")
DELIVERY_LABELS = {"diff": "diff", "proposto": "sostituzione proposta, non applicata automaticamente",
                   "istruzioni": "solo istruzioni"}
LEGACY_KEYS = ("what", "removal_condition")
VERIFY_KEYS = ("finding_id", "build_checks", "behavior_checks", "data_format", "rollback", "open_points", "executed")
BUILD_KEYS = ("check", "command", "origin")
FORMAT_LISTS = ("writers", "readers", "validators", "compatibility", "migration_rollback")
FORMAT_LABELS = {"writers": "Chi scrive il valore", "readers": "Chi lo legge",
                 "validators": "Chi ne valida lunghezza, formato o prefisso",
                 "compatibility": "Compatibilità con i valori già salvati", "migration_rollback": "Migrazione e rollback"}
MANIFEST_LABELS = {"diff": "Diff", "proposto": "Sostituzione proposta, non applicata automaticamente",
                   "istruzioni": "Solo istruzioni (nessun file generato)"}
LEGACY_WORDS = re.compile(r"legacy|retrocompatibil|compatibilit[àa] (?:con|legacy)", re.I)
MAX_REASON, MAX_ITEM, MAX_CHANGE = 200, 240, 600
TARGET_FIX_WORDS, MAX_FIX_WORDS = 400, 500
LIMITS = {"root_cause": (1, 3), "compatibility": (0, 4), "verification": (1, 5), "outside_code": (0, 4),
          "open_points": (0, 2)}
MAX_PLAN_OPEN = 3
APPROVAL_PLAN = "Approvi il piano di remediation, vuoi modificarlo o annulli?"
APPROVAL_FIX = "Approvi questo piano di fix, vuoi modificarlo o annulli?"


def one_line(text):
    return " ".join(str(text).split())


def cell(text):
    return one_line(text).replace("|", "\\|")


def position(item):
    loc = item["location"]
    return "{0}:{1}".format(loc["file"], loc["line"]) if loc["line"] else loc["file"]


def strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from strings(v)


def secret_errors(data):
    return ["Possibile segreto in chiaro ({0}) nei contenuti: il valore non viene mostrato.".format(kind)
            for s in strings(data) for _, kind in find_secrets(one_line(s))]


def short_list(value, label, err, low, high, limit=MAX_ITEM):
    if not (isinstance(value, list) and all(filled(x) for x in value)):
        err.append("{0} deve essere un elenco di frasi non vuote.".format(label))
        return
    if not low <= len(value) <= high:
        err.append("{0}: servono da {1} a {2} voci (trovate {3}).".format(label, low, high, len(value)))
    if any(len(one_line(x)) > limit for x in value):
        err.append("{0}: una voce supera {1} caratteri: va resa breve.".format(label, limit))


def candidates(triage):
    findings = sorted(triage["findings"], key=lambda f: id_number(f["id"]))
    obs = sorted(triage["additional_observations"], key=lambda o: id_number(o["id"]))
    return [f for f in findings if f["verdict"] in CONFIRMED], obs, findings


# ---------------------------------------------------------------- piano generale

def validate_plan(data, triage):
    err = []
    if not isinstance(data, dict):
        return ["Il file dei contenuti deve essere un oggetto JSON."]
    for k in PLAN_KEYS:
        if k not in data:
            err.append("Manca il campo '{0}'.".format(k))
    for k in data:
        if k not in PLAN_KEYS:
            err.append("Campo non previsto: '{0}'.".format(k))
    cand_f, cand_o, _ = candidates(triage)
    cand_ids, obs_ids = {f["id"] for f in cand_f}, {o["id"] for o in cand_o}
    order, seen_step = data.get("order"), {}
    if not isinstance(order, list):
        err.append("order deve essere un elenco di passi.")
        order = []
    elif not order and cand_ids:
        err.append("order è vuoto ma ci sono finding candidati.")
    for n, step in enumerate(order, 1):
        where = "Il passo #{0}".format(n)
        if not isinstance(step, dict) or set(step) != set(STEP_KEYS):
            err.append("{0} deve contenere esattamente: {1}.".format(where, ", ".join(STEP_KEYS)))
            continue
        if not filled(step["reason"]) or len(one_line(step["reason"])) > MAX_REASON:
            err.append("{0}: reason deve essere una frase non vuota di al massimo {1} caratteri.".format(where, MAX_REASON))
        ids, dep = step["finding_ids"], step["depends_on"]
        if not (isinstance(ids, list) and ids and all(isinstance(i, str) for i in ids)):
            err.append("{0}: finding_ids deve essere un elenco non vuoto di id.".format(where))
            continue
        for i in ids:
            if i not in cand_ids:
                err.append("{0}: {1} non è un finding candidato (High, Medium o Low).".format(where, i))
            elif i in seen_step:
                err.append("{0} compare nei passi #{1} e #{2}: ogni finding sta in un solo passo.".format(i, seen_step[i], n))
            else:
                seen_step[i] = n
        if not (isinstance(dep, list) and all(isinstance(d, str) for d in dep)):
            err.append("{0}: depends_on deve essere un elenco di id (anche vuoto).".format(where))
            continue
        for d in dep:
            if d not in seen_step or seen_step[d] >= n:
                err.append("{0}: depends_on cita {1}, che non sta in un passo precedente.".format(where, d))
    for i in sorted(cand_ids - set(seen_step), key=id_number):
        err.append("Il finding candidato {0} non compare in nessun passo dell'ordine.".format(i))
    obs = data.get("observations")
    seen_obs = set()
    if not isinstance(obs, list):
        err.append("observations deve essere un elenco (anche vuoto).")
        obs = []
    for n, o in enumerate(obs, 1):
        where = "L'osservazione #{0}".format(n)
        if not isinstance(o, dict) or set(o) != set(OBS_KEYS):
            err.append("{0} deve contenere esattamente: {1}.".format(where, ", ".join(OBS_KEYS)))
            continue
        if o["id"] not in obs_ids:
            err.append("{0}: {1} non è un'osservazione del triage.".format(where, o["id"]))
        elif o["id"] in seen_obs:
            err.append("{0} compare più volte in observations.".format(o["id"]))
        seen_obs.add(o["id"])
        if not filled(o["reason"]) or len(one_line(o["reason"])) > MAX_REASON:
            err.append("{0}: reason deve essere una frase non vuota di al massimo {1} caratteri.".format(where, MAX_REASON))
    for i in sorted(obs_ids - seen_obs, key=id_number):
        err.append("L'osservazione {0} non compare in observations.".format(i))
    short_list(data.get("open_points"), "open_points", err, 0, MAX_PLAN_OPEN)
    return err + (secret_errors(data) if not err else [])


def render_plan(data, triage):
    meta, ctx = triage["metadata"], triage["context"]
    cand_f, cand_o, findings = candidates(triage)
    by = Counter(f["verdict"] for f in cand_f)
    by_id = {f["id"]: f for f in cand_f}
    obs_by_id = {o["id"]: o for o in cand_o}
    fps = [f["id"] for f in findings if f["verdict"] == FALSE_POSITIVE]
    unknown = [f for f in findings if f["verdict"] == UNKNOWN]
    L = ["# Piano di remediation", "", "## Triage di origine", ""]
    L.append("- Progetto: `{0}`".format(meta["project_name"]))
    L.append("- Report scanner: `{0}` ({1})".format(meta["scanner_report_name"], meta["scanner_report_date"] or "data non disponibile"))
    L.append("- File: `sast-output/triage/triage.json` (versione toolkit `{0}`)".format(meta["toolkit_version"]))
    detail = " — {0}".format(one_line(ctx["exposure_detail"])) if ctx["exposure_detail"].strip() else ""
    L.append("- Contesto: {0}; esposizione {1}{2}; rilascio {3}".format(
        "; ".join(one_line(s) for s in ctx["stack"]) or "n/d", ctx["exposure"], detail, one_line(ctx["release_model"]) or "n/d"))
    L.append("- Vincoli: {0}".format("; ".join(one_line(c) for c in ctx["constraints"]) or "Nessuno"))
    L += ["", "## Candidati", "",
          "- Finding: High {0} · Medium {1} · Low {2}".format(by["High"], by["Medium"], by["Low"]),
          "- Osservazioni aggiuntive: {0}".format(len(cand_o)), "- Totale: {0}".format(len(cand_f) + len(cand_o))]
    L += ["", "## Esclusioni", "",
          "- Falsi positivi: {0}{1}".format(len(fps), " ({0})".format(", ".join(fps)) if fps else ""),
          "- Da verificare: {0}".format(len(unknown))]
    for f in unknown:
        L.append("  - {0}: {1}".format(f["id"], "; ".join(one_line(m) for m in f["missing_evidence"])))
    L += ["", "## Ordine proposto", ""]
    if data["order"]:
        L += ["| Passo | ID | Verdetto | Titolo | Posizione | Dipende da | Motivo |", "|---|---|---|---|---|---|---|"]
        for n, step in enumerate(data["order"], 1):
            for fid in sorted(step["finding_ids"], key=id_number):
                f = by_id[fid]
                L.append("| {0} | `{1}` | {2} | {3} | `{4}` | {5} | {6} |".format(
                    n, fid, f["verdict"], cell(f["title"]), position(f),
                    ", ".join(sorted(step["depends_on"], key=id_number)) or "—", cell(step["reason"])))
        L.append("")
        L.append("Criteri: rischio, dipendenze, vincoli. Lo sforzo conta solo a parità degli altri.")
    else:
        L.append("Nessun finding candidato.")
    L += ["", "## Osservazioni aggiuntive", ""]
    if data["observations"]:
        L += ["| ID | Verdetto | Titolo | Posizione | Motivo |", "|---|---|---|---|---|"]
        for o in sorted(data["observations"], key=lambda o: id_number(o["id"])):
            item = obs_by_id[o["id"]]
            L.append("| `{0}` | {1} | {2} | `{3}` | {4} |".format(o["id"], item["verdict"], cell(item["title"]), position(item), cell(o["reason"])))
    else:
        L.append("Nessuna.")
    L += ["", "## Punti aperti", ""]
    L += ["- {0}".format(one_line(p)) for p in data["open_points"]] or ["Nessuno."]
    L += ["", "## Approvazione", "", APPROVAL_PLAN]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- piano di fix

def validate_delivery(delivery, err):
    if not isinstance(delivery, list) or not delivery:
        err.append("delivery deve essere un elenco non vuoto: un elemento per file coinvolto.")
        return
    seen = set()
    for n, d in enumerate(delivery, 1):
        where = "delivery #{0}".format(n)
        if not isinstance(d, dict) or set(d) != set(DELIVERY_KEYS):
            err.append("{0} deve contenere esattamente: {1}.".format(where, ", ".join(DELIVERY_KEYS)))
            continue
        problem = path_problem(d["file"]) if isinstance(d["file"], str) else "non è un testo"
        if problem:
            err.append("{0}: file {1!r} {2} (servono percorsi relativi ai sorgenti, con '/').".format(where, d["file"], problem))
        elif d["file"] in seen:
            err.append("{0}: il file {1} compare più volte.".format(where, d["file"]))
        seen.add(d["file"])
        if d["mode"] not in DELIVERY_MODES:
            err.append("{0}: mode non valido {1!r}. Valori ammessi: {2}.".format(where, d["mode"], ", ".join(DELIVERY_MODES)))
        elif d["mode"] == "diff" and isinstance(d["reason"], str) and d["reason"].strip():
            err.append("{0}: con mode diff il motivo deve essere vuoto.".format(where))
        elif d["mode"] != "diff" and not (filled(d["reason"]) and len(one_line(d["reason"])) <= MAX_ITEM):
            err.append("{0}: con mode {1} serve un motivo breve (al massimo {2} caratteri).".format(where, d["mode"], MAX_ITEM))


def validate_legacy(data, err):
    legacy = data.get("legacy_paths")
    if not isinstance(legacy, list) or len(legacy) > 3:
        err.append("legacy_paths deve essere un elenco di al massimo 3 voci (anche vuoto).")
        return
    for n, item in enumerate(legacy, 1):
        where = "legacy_paths #{0}".format(n)
        if not isinstance(item, dict) or set(item) != set(LEGACY_KEYS):
            err.append("{0} deve contenere esattamente: {1}.".format(where, ", ".join(LEGACY_KEYS)))
            continue
        for k in LEGACY_KEYS:
            if not filled(item[k]):
                err.append("{0}: {1} è vuoto: un percorso di compatibilità è temporaneo e dichiara quando va rimosso.".format(where, k))
            elif len(one_line(item[k])) > MAX_ITEM:
                err.append("{0}: {1} supera {2} caratteri.".format(where, k, MAX_ITEM))
    mentions = [x for x in list(data.get("compatibility") or []) + [data.get("proposed_change") or ""] +
                list(data.get("root_cause") or []) if isinstance(x, str) and LEGACY_WORDS.search(x)]
    if mentions and not legacy:
        err.append("Il piano parla di compatibilità legacy: dichiarala in legacy_paths come temporanea, "
                   "con la condizione in cui va rimossa.")


def validate_fix(data, triage):
    err = []
    if not isinstance(data, dict):
        return ["Il file dei contenuti deve essere un oggetto JSON."]
    for k in FIX_KEYS:
        if k not in data:
            err.append("Manca il campo '{0}'.".format(k))
    for k in data:
        if k not in FIX_KEYS:
            err.append("Campo non previsto: '{0}'.".format(k))
    cand_f, cand_o, _ = candidates(triage)
    if data.get("finding_id") not in {x["id"] for x in cand_f + cand_o}:
        err.append("finding_id {0!r} non è un candidato del triage (High, Medium, Low o osservazione).".format(data.get("finding_id")))
    for k, limit in (("reason", MAX_REASON), ("proposed_change", MAX_CHANGE)):
        if not filled(data.get(k)):
            err.append("{0} è vuoto.".format(k))
        elif len(one_line(data[k])) > limit:
            err.append("{0} supera {1} caratteri: va reso breve.".format(k, limit))
    for k, (low, high) in LIMITS.items():
        if k in data:
            short_list(data[k], k, err, low, high)
    if "delivery" in data:
        validate_delivery(data["delivery"], err)
    if "changes_data_format" in data and not isinstance(data["changes_data_format"], bool):
        err.append("changes_data_format deve essere true o false.")
    if "legacy_paths" in data:
        validate_legacy(data, err)
    return err + (secret_errors(data) if not err else [])


def diff_line(delivery):
    n = sum(1 for d in delivery if d["mode"] == "diff")
    if n == len(delivery):
        return "Diff: sì"
    if n:
        return "Diff: sì (parziale: {0} di {1} file)".format(n, len(delivery))
    reasons = []
    for d in delivery:
        r = one_line(d["reason"])
        if r not in reasons:
            reasons.append(r)
    return "Diff: no ({0})".format("; ".join(reasons))


def render_fix(data, triage):
    cand_f, cand_o, _ = candidates(triage)
    item = next(x for x in cand_f + cand_o if x["id"] == data["finding_id"])
    verdict_line = "`{0}` · {1} · `{2}`".format(item["verdict"], one_line(item["title"]), position(item))
    delivery = sorted(data["delivery"], key=lambda d: d["file"])
    L = ["# Piano di fix: `{0}`".format(item["id"]), "", "## Finding", "",
         "- {0}".format(verdict_line), "- Motivo: {0}".format(one_line(data["reason"])),
         "", "## Causa radice", ""]
    L += ["- {0}".format(one_line(x)) for x in data["root_cause"]]
    L += ["", "## Modifica proposta", "", one_line(data["proposed_change"]), "", "## File coinvolti", ""]
    for d in delivery:
        extra = " ({0})".format(one_line(d["reason"])) if d["mode"] != "diff" else ""
        L.append("- `{0}` — {1}{2}".format(d["file"], DELIVERY_LABELS[d["mode"]], extra))
    L += ["", "## Compatibilità ed effetti collaterali", ""]
    L += ["- {0}".format(one_line(x)) for x in data["compatibility"]] or ["Nessuno."]
    L += ["", "## Percorsi temporanei di compatibilità", ""]
    L += ["- {0} — temporaneo; da rimuovere quando: {1}".format(one_line(x["what"]), one_line(x["removal_condition"]))
          for x in data["legacy_paths"]] or ["Nessuno."]
    L += ["", "## Verifica", ""] + ["- {0}".format(one_line(x)) for x in data["verification"]]
    L += ["", "## Passi fuori dal codice", ""]
    L += ["- {0}".format(one_line(x)) for x in data["outside_code"]] or ["Nessuno."]
    L += ["", "## Diff", "", diff_line(delivery)]
    L += ["", "## Punti aperti", ""]
    L += ["- {0}".format(one_line(x)) for x in data["open_points"]] or ["Nessuno."]
    L += ["", "## Approvazione", "", APPROVAL_FIX]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- verifica

def validate_verify(data, triage, fix, manifest):
    err = []
    if not isinstance(data, dict):
        return ["Il file dei contenuti deve essere un oggetto JSON."]
    for k in VERIFY_KEYS:
        if k not in data:
            err.append("Manca il campo '{0}'.".format(k))
    for k in data:
        if k not in VERIFY_KEYS:
            err.append("Campo non previsto: '{0}'.".format(k))
    cand_f, cand_o, _ = candidates(triage)
    if data.get("finding_id") not in {x["id"] for x in cand_f + cand_o}:
        err.append("finding_id {0!r} non è un candidato del triage.".format(data.get("finding_id")))
    if isinstance(fix, dict) and data.get("finding_id") != fix.get("finding_id"):
        err.append("finding_id non coincide con quello del piano di fix ({0}).".format(fix.get("finding_id")))
    build = data.get("build_checks")
    if not isinstance(build, list) or len(build) > 5:
        err.append("build_checks deve essere un elenco di al massimo 5 controlli (anche vuoto).")
    else:
        for n, b in enumerate(build, 1):
            where = "build_checks #{0}".format(n)
            if not isinstance(b, dict) or set(b) != set(BUILD_KEYS):
                err.append("{0} deve contenere esattamente: {1}.".format(where, ", ".join(BUILD_KEYS)))
            elif not filled(b["check"]) or b["origin"] not in ("inferred", "to_define") or not isinstance(b["command"], str):
                err.append("{0}: servono check e origin (inferred oppure to_define) e un comando (testo).".format(where))
            elif b["origin"] == "inferred" and not filled(b["command"]):
                err.append("{0}: un controllo dedotto dal progetto riporta il comando.".format(where))
            elif b["origin"] == "to_define" and b["command"].strip():
                err.append("{0}: un controllo da definire non riporta nessun comando inventato.".format(where))
    short_list(data.get("behavior_checks"), "behavior_checks", err, 1, 6)
    short_list(data.get("rollback"), "rollback", err, 1, 4)
    short_list(data.get("open_points"), "open_points", err, 0, 2)
    executed = data.get("executed")
    if not isinstance(executed, list) or len(executed) > 5 or not all(
            isinstance(e, dict) and set(e) == {"check", "result"} and filled(e["check"]) and filled(e["result"]) for e in executed):
        err.append("executed deve essere un elenco (anche vuoto) di al massimo 5 voci {check, result}: solo controlli davvero eseguiti.")
    dformat = data.get("data_format")
    changes = isinstance(fix, dict) and fix.get("changes_data_format") is True
    if not isinstance(dformat, dict) or set(dformat) != set(("changed",) + FORMAT_LISTS) or not isinstance(dformat.get("changed"), bool):
        err.append("data_format deve contenere: changed, {0}.".format(", ".join(FORMAT_LISTS)))
    else:
        if dformat["changed"] != changes:
            err.append("data_format.changed ({0}) non coincide con changes_data_format del piano di fix ({1}).".format(
                str(dformat["changed"]).lower(), str(changes).lower()))
        for k in FORMAT_LISTS:
            if dformat["changed"]:
                short_list(dformat[k], "data_format." + k, err, 1, 3)
            elif dformat[k]:
                err.append("data_format.{0} deve essere vuoto se il formato non cambia.".format(k))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list) or not manifest["files"]:
        err.append("PROPOSTE.json non è valido o non contiene file: esegui prima make_diff.py (e make_proposto.py).")
    else:
        for e in manifest["files"]:
            if e.get("mode") == "segreto_nel_diff":
                err.append("{0} è ancora «segreto_nel_diff»: trattalo con make_proposto.py prima di scrivere la verifica.".format(e.get("path")))
            elif e.get("mode") not in DELIVERY_MODES:
                err.append("PROPOSTE.json: modo non valido per {0}.".format(e.get("path")))
    return err + (secret_errors(data) if not err else [])


def render_verify(data, triage, manifest):
    cand_f, cand_o, _ = candidates(triage)
    fid = data["finding_id"]
    files = sorted(manifest["files"], key=lambda e: e["path"])
    L = ["# Verifica: `{0}`".format(fid), "", "## Artefatti prodotti", "",
         "| File | Consegna | Proposta | SHA-256 dell'originale |", "|---|---|---|---|"]
    for e in files:
        if e["mode"] == "diff":
            delivery, proposal, sha = "Diff (`{0}.diff`)".format(fid), "—", "—"
        elif e["mode"] == "proposto":
            delivery, proposal, sha = MANIFEST_LABELS["proposto"], "`{0}`".format(e["proposal"]), \
                "`{0}`".format(e["original_sha256"]) if e.get("original_sha256") else "file nuovo"
        else:
            delivery, proposal, sha = MANIFEST_LABELS["istruzioni"], "—", "—"
        L.append("| `{0}` | {1} | {2} | {3} |".format(e["path"], delivery, proposal, sha))
    L += ["", "## File che devono cambiare", ""] + ["- `{0}`".format(e["path"]) for e in files]
    modes = {e["mode"] for e in files}
    if "proposto" in modes:
        L += ["", "## Controllo dell'hash prima di sostituire", "",
              "Prima di sostituire un file con la sua proposta, verifica che l'SHA-256 del file originale coincida ancora con "
              "quello in tabella (PowerShell: `Get-FileHash <file> -Algorithm SHA256`; altrove `sha256sum <file>`). "
              "Se è diverso, il sorgente è cambiato e la proposta va rigenerata."]
    L += ["", "## Come applicare", ""]
    if "diff" in modes:
        L.append("- Diff: dalla radice dei sorgenti `git apply {0}.diff` (anche fuori da un repository) oppure `patch -p1 < {0}.diff`.".format(fid))
    if "proposto" in modes:
        L.append("- Sostituzione proposta: rivedi il file `.proposto` e sostituisci a mano l'originale. Non viene mai applicata in automatico.")
    if "istruzioni" in modes:
        L.append("- Solo istruzioni: segui «Modifica proposta» e «Passi fuori dal codice» del piano di fix.")
    L += ["", "## Controlli di compilazione e analisi statica", ""]
    for b in data["build_checks"]:
        if b["origin"] == "inferred":
            L.append("- [ ] {0}: `{1}` (comando dedotto dal progetto)".format(one_line(b["check"]), one_line(b["command"])))
        else:
            L.append("- [ ] {0} (comando da definire)".format(one_line(b["check"])))
    if not data["build_checks"]:
        L.append("Nessuno.")
    L += ["", "## Controlli di comportamento e sicurezza", ""]
    L += ["- [ ] {0}".format(one_line(x)) for x in data["behavior_checks"]]
    L += ["", "## Compatibilità e formati dei dati", ""]
    dformat = data["data_format"]
    if dformat["changed"]:
        L.append("Il formato di un valore cifrato o codificato cambia. Verifica:")
        for k in FORMAT_LISTS:
            L += ["- [ ] {0}: {1}".format(FORMAT_LABELS[k], "; ".join(one_line(x) for x in dformat[k]))]
    else:
        L.append("Nessun formato di dati cambia.")
    L += ["", "## Rollback", ""] + ["- {0}".format(one_line(x)) for x in data["rollback"]]
    L += ["", "## Punti aperti", ""]
    L += ["- {0}".format(one_line(x)) for x in data["open_points"]] or ["Nessuno."]
    L += ["", "## Stato dei controlli", ""]
    if data["executed"]:
        L += ["Eseguito da Claude:"] + ["- {0}: {1}".format(one_line(e["check"]), one_line(e["result"])) for e in data["executed"]]
        L.append("Non compilato né testato da Claude: tutto ciò che non è elencato sopra.")
    else:
        L += ["Eseguito da Claude: nessun controllo.", "Non compilato né testato da Claude."]
    L += ["", "## Dopo", "",
          "Dì a Claude quando la modifica è stata **applicata** e quando la verifica è **riuscita**: lo stato in `REMEDIATION.md` "
          "cambia solo su tua conferma. Un `.diff` o un `.proposto` non significa che la modifica sia stata applicata."]
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
    ap.add_argument("kind", choices=("plan", "fix", "verify"),
                    help="plan = PIANO_REMEDIATION.md, fix = PIANO_FIX.md, verify = VERIFICA.md")
    ap.add_argument("--triage", required=True, help="triage.json")
    ap.add_argument("--input", required=True, help="contenuti scritti da Claude (JSON)")
    ap.add_argument("--fix-input", help="verify: fix-input.json dello stesso fix")
    ap.add_argument("--manifest", help="verify: PROPOSTE.json prodotto da make_diff.py / make_proposto.py")
    ap.add_argument("-o", "--output", required=True, help="file Markdown di uscita")
    args = ap.parse_args(argv)
    triage, data = load(args.triage, "triage.json"), load(args.input, "contenuti")
    if triage is None or data is None:
        return 2
    fix = manifest = None
    if args.kind == "verify":
        if not args.fix_input or not args.manifest:
            print("Errore: verify richiede --fix-input e --manifest.", file=sys.stderr)
            return 2
        fix, manifest = load(args.fix_input, "fix-input.json"), load(args.manifest, "PROPOSTE.json")
        if fix is None or manifest is None:
            return 2
    problems = validate(triage)
    if problems:
        print("triage.json NON valido ({0} problemi). Nessun file scritto.".format(len(problems)), file=sys.stderr)
        for p in problems:
            print(" - " + p, file=sys.stderr)
        return 1
    if args.kind == "plan":
        errors = validate_plan(data, triage)
    elif args.kind == "fix":
        errors = validate_fix(data, triage)
    else:
        errors = validate_verify(data, triage, fix, manifest)
    if errors:
        print("Contenuti NON validi ({0} problemi). Nessun file scritto:".format(len(errors)), file=sys.stderr)
        for e in errors:
            print(" - " + e, file=sys.stderr)
        return 1
    text = {"plan": lambda: render_plan(data, triage), "fix": lambda: render_fix(data, triage),
            "verify": lambda: render_verify(data, triage, manifest)}[args.kind]()
    words = len(text.split())
    if args.kind == "fix" and words > MAX_FIX_WORDS:
        print("Il piano di fix ha {0} parole: il massimo è {1} (obiettivo circa {2}). Nessun file scritto: "
              "accorcia i contenuti, senza tagli automatici.".format(words, MAX_FIX_WORDS, TARGET_FIX_WORDS), file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "wb") as fh:
        fh.write(text.encode("utf-8"))
    note = ""
    if args.kind == "fix" and words > TARGET_FIX_WORDS:
        note = " Sopra l'obiettivo di {0} parole: se puoi, accorcia.".format(TARGET_FIX_WORDS)
    print("Scritto: {0} ({1} parole).{2}".format(args.output, words, note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
