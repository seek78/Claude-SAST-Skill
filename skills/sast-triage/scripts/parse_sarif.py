# -*- coding: utf-8 -*-
"""Legge uno o più report SAST in formato SARIF 2.1.0 (di AppScan o di altri strumenti) e scrive la stessa
rappresentazione normalizzata in JSON di parse_appscan.py. È l'alternativa alla coppia CSV + XML di AppScan.

Non assegna verdetti e non trae conclusioni di sicurezza: è la base su cui Claude lavora.

Uso:
  python parse_sarif.py REPORT.sarif [ALTRO.sarif ...] -o parsed.json [--sources CARTELLA] [--sca REPORT.html]
                        [--include-suppressed]

  REPORT.sarif          uno o più report SARIF 2.1.0: elenco AUTOREVOLE dei finding (obbligatorio)
  --sources             cartella dei sorgenti: i percorsi del report diventano relativi a essa
  --sca                 report SCA (HTML): ne ricava solo un breve riepilogo
  --include-suppressed  tiene anche i risultati soppressi nello strumento (di norma esclusi)
  -o                    file JSON di uscita (scritto solo se tutti i controlli passano)

Esito: 0 ok | 1 input non utilizzabile (messaggio in italiano) | 2 uso errato

L'uscita ha il formato di parse_appscan.py (intermedio, NON è il contratto del triage), così make_plan.py e
build_triage.py non cambiano. Differenze: "xml" è sempre null (le tracce vengono dai codeFlows del SARIF, nel campo
"trace" del finding), file_match può valere anche "class", e c'è un riepilogo in più:
  "sarif": {"tools": ["nome versione"], "results": N,
            "files": [{"name": "nome.sarif", "results": n, "findings": n}],
            "excluded": {"suppressed": n, "absent": n, "not_a_problem": n, "duplicate": n},
            "severity_from": {"tool": n, "security-severity": n, "level": n}}

Quali risultati diventano finding (uno per risultato, nell'ordine dei file indicati e, in ciascuno, delle run):
  - kind "fail" (il valore predefinito), "open" o "review"; esclusi "pass", "notApplicable", "informational";
  - esclusi i risultati con baselineState "absent" (non più presenti nella scansione);
  - esclusi i risultati soppressi: almeno una soppressione "accepted" (anche senza status) e nessuna "underReview" o
    "rejected"; con --include-suppressed restano;
  - con più file, esclusi i duplicati: un risultato già letto da un file precedente (stesso strumento, regola, file,
    riga e scanner_issue_id dato dallo strumento) conta una volta sola. Strumenti diversi sullo stesso punto restano
    finding distinti.
Gli id AS-001, AS-002... seguono quest'ordine, con una sola numerazione per tutti i file, e valgono solo per questo
ciclo di triage/remediation, anche se il SARIF non viene da AppScan: il formato di triage.json non cambia.

Campi:
  scanner_severity  scala Critical · High · Medium · Low · Informational, presa nell'ordine da:
                    1) campo di gravità dello strumento: proprietà "severity" o "issue_severity" del risultato o della
                       regola (es. AppScan properties.Severity), se il valore è riconosciuto;
                    2) "security-severity", punteggio 0-10 sulla scala CVSS: >= 9.0 Critical, >= 7.0 High,
                       >= 4.0 Medium, >= 0.1 Low, 0 Informational;
                    3) level: error High, warning Medium, note Low, none Informational, con i valori predefiniti
                       della specifica (level della regola, altrimenti "warning"; "none" se kind non è "fail").
  title             descrizione breve della regola, altrimenti il suo nome, altrimenti il messaggio, altrimenti ruleId
  scanner_issue_id  guid, correlationGuid o la prima impronta (fingerprints, partialFingerprints) del risultato;
                    se mancano, la posizione nel file (run1/result5; con più file file2/run1/result5)
  cwe               proprietà o tag CWE di risultato e regola, relazioni e taxa verso la tassonomia CWE
  threat_class      proprietà "threatClass" o "IssueType" (AppScan), se presenti
  cause             messaggio del risultato (se diverso dal titolo) e posizione logica (es. il metodo sink di AppScan)
  file, line        prima posizione fisica: artifactLocation risolto con artifacts e originalUriBaseIds, region.startLine.
                    Con --sources il percorso diventa relativo ai sorgenti come per il CSV; in più un nome di classe
                    qualificato (es. 'Azienda.Modulo.OrderRepository.cs' di AppScan) si risolve nel file della classe.

Metadati (finiscono in triage.json, mai ricavati da date del file system né dall'orologio):
  report        nome del file SARIF, senza cartelle; con più file i nomi uniti da " + " nell'ordine indicato
                (se due file hanno lo stesso nome, preceduti dalla cartella che li contiene)
  report_date   data (UTC) più recente dichiarata negli invocations di tutti i file (endTimeUtc, altrimenti
                startTimeUtc), AAAA-MM-GG; null se manca (l'export SARIF di AppScan non la riporta)
  project_name  nome dell'ultima cartella del percorso passato a --sources; null senza --sources
I testi liberi sono accorciati e passano da una redazione dei segreti evidenti.
"""

import argparse
import datetime
import io
import json
import os
import re
import sys
from collections import Counter
from urllib.parse import unquote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_appscan import (SEVERITIES, InputError, make_resolver, norm_path, project_name_of,  # noqa: E402
                           read_sca, short)

SARIF_VERSION = "2.1.0"
PROBLEM_KINDS = ("fail", "open", "review")
LEVELS = {"error": "High", "warning": "Medium", "note": "Low", "none": "Informational"}
SEVERITY_WORDS = dict(LEVELS, critical="Critical", critico="Critical", high="High", alto="High", alta="High",
                      medium="Medium", medio="Medium", media="Medium", moderate="Medium", low="Low", basso="Low",
                      bassa="Low", informational="Informational", informativa="Informational", info="Informational",
                      information="Informational")
CVSS_LIMITS = ((9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"))
TRACE_STEPS = 5
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]+):")      # due o più caratteri: 'C:' è un'unità, non uno schema
_DRIVE = re.compile(r"^[A-Za-z]:")
_CWE = re.compile(r"(?i)\bcwe[-_:/ ]*0*(\d{1,5})\b")
_NUMBER = re.compile(r"^\s*0*(\d{1,5})\s*$")
_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$", re.I)


def as_dict(value):
    return value if isinstance(value, dict) else {}


def as_list(value):
    return value if isinstance(value, list) else []


def norm_key(key):
    return re.sub(r"[-_\s]", "", key).lower() if isinstance(key, str) else ""


def prop(bags, keys):
    """Primo valore (testo o numero) con una delle chiavi, confrontate senza '-', '_' e maiuscole."""
    for bag in bags:
        for k, v in as_dict(bag).items():
            if norm_key(k) in keys and isinstance(v, (str, int, float)) and not isinstance(v, bool):
                return v
    return None


def text_of(message):
    """Testo di un message o di un multiformatMessageString."""
    text = as_dict(message).get("text")
    return text if isinstance(text, str) else ""


# ---------------------------------------------------------------- regole e testi

def find_rule(run, result):
    """reportingDescriptor della regola: per indice (ruleIndex o rule.index), altrimenti per id (anche gerarchico)."""
    tool = as_dict(run.get("tool"))
    driver = as_dict(tool.get("driver"))
    extensions = [e for e in as_list(tool.get("extensions")) if isinstance(e, dict)]
    ref = as_dict(result.get("rule"))
    component = driver
    tc = as_dict(ref.get("toolComponent"))
    if isinstance(tc.get("index"), int) and 0 <= tc["index"] < len(extensions):
        component = extensions[tc["index"]]
    elif isinstance(tc.get("name"), str):
        component = next((e for e in extensions if e.get("name") == tc["name"]), driver)
    rules = as_list(component.get("rules"))
    index = ref.get("index", result.get("ruleIndex"))
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules) and isinstance(rules[index], dict):
        return rules[index]
    rule_id = result.get("ruleId") or ref.get("id")
    if isinstance(rule_id, str) and rule_id:
        parts = rule_id.split("/")
        for candidate in ["/".join(parts[:k]) for k in range(len(parts), 0, -1)]:
            for comp in [component, driver] + extensions:
                for rule in as_list(comp.get("rules")):
                    if isinstance(rule, dict) and rule.get("id") == candidate:
                        return rule
    return {}


def message_text(message, rule, driver):
    """Testo del messaggio: testo diretto o da messageStrings, segnaposto {n} sostituiti, link [testo](id) ridotti."""
    message = as_dict(message)
    text = message.get("text")
    if not isinstance(text, str):
        text, mid = "", message.get("id")
        for table in (rule.get("messageStrings"), driver.get("globalMessageStrings")):
            if isinstance(mid, str) and isinstance(as_dict(table).get(mid), dict):
                text = text_of(table[mid])
                if text:
                    break
    args = as_list(message.get("arguments"))

    def fill(m):
        if m.group(1) is None:
            return m.group(0)[0]
        i = int(m.group(1))
        return str(args[i]) if i < len(args) else m.group(0)

    text = re.sub(r"\{\{|\}\}|\{(\d+)\}", fill, text)
    return re.sub(r"\[([^\]]*)\]\([^)\s]*\)", r"\1", text)


def title_of(rule, rule_id, message):
    name = rule.get("name")
    for candidate in (text_of(rule.get("shortDescription")),
                      name if isinstance(name, str) and name != rule.get("id") else "",
                      message, rule_id):
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    return "Risultato SARIF senza titolo"


def level_of(result, rule):
    level = result.get("level")
    if level in LEVELS:
        return level
    if result.get("kind", "fail") != "fail":
        return "none"
    default = as_dict(rule.get("defaultConfiguration")).get("level")
    return default if default in LEVELS else "warning"


def cvss_label(value):
    if isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not 0 <= score <= 10:
        return None
    return next((label for limit, label in CVSS_LIMITS if score >= limit), "Informational")


def severity_of(result, rule):
    """(gravità, fonte, valore dello strumento non riconosciuto o None)."""
    bags = (result.get("properties"), rule.get("properties"))
    raw = prop(bags, ("severity", "issueseverity"))
    unknown = None
    if isinstance(raw, str) and raw.strip().lower() in SEVERITY_WORDS:
        return SEVERITY_WORDS[raw.strip().lower()], "tool", None
    if raw is not None:
        unknown = str(raw).strip()[:40]
    label = cvss_label(prop(bags, ("securityseverity",)))
    if label:
        return label, "security-severity", unknown
    return LEVELS[level_of(result, rule)], "level", unknown


def cwe_of(result, rule, run):
    found = []

    def add(value, bare_number):
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return
        text = str(value)
        m = _NUMBER.match(text) if bare_number else None
        for number in ([m.group(1)] if m else [x.group(1) for x in _CWE.finditer(text)]):
            if number not in found:
                found.append(number)

    for bag in (result.get("properties"), rule.get("properties")):
        for k, v in as_dict(bag).items():
            if norm_key(k) in ("cwe", "cweid", "cwes", "cweids"):
                for item in (v if isinstance(v, list) else [v]):
                    add(item, True)
            elif norm_key(k) == "tags":
                for item in as_list(v):
                    add(item, False)
    taxonomies = as_list(run.get("taxonomies"))

    def is_cwe(ref):
        tc = as_dict(as_dict(ref).get("toolComponent"))
        name, index = tc.get("name"), tc.get("index")
        if not isinstance(name, str) and isinstance(index, int) and 0 <= index < len(taxonomies):
            name = as_dict(taxonomies[index]).get("name")
        return isinstance(name, str) and name.strip().upper() == "CWE"

    refs = [as_dict(r).get("target") for r in as_list(rule.get("relationships"))] + as_list(result.get("taxa"))
    for ref in refs:
        if is_cwe(ref):
            add(ref.get("id"), True)
    return ", ".join(found)


# ---------------------------------------------------------------- posizioni

def uri_to_path(uri):
    """Percorso con '/' da un URI SARIF: file:///..., percorso relativo o percorso Windows (anche con '\\')."""
    if _SCHEME.match(uri):
        parts = urlsplit(uri)
        path = parts.path
        if parts.scheme.lower() == "file" and parts.netloc and parts.netloc.lower() != "localhost":
            path = parts.netloc + "/" + path
        uri = path
    return norm_path(unquote(uri))


def is_absolute(uri):
    return bool(_SCHEME.match(uri) or _DRIVE.match(uri) or uri.startswith(("/", "\\")))


def base_prefix(base_id, bases, depth=0):
    """Prefisso relativo aggiunto da un uriBaseId, risalendo originalUriBaseIds fino a una radice assoluta o non
    definita: i percorsi restano relativi alla radice della scansione, come nel CSV."""
    entry = as_dict(bases).get(base_id) if isinstance(base_id, str) else None
    if depth > 10 or not isinstance(entry, dict):
        return ""
    uri = entry.get("uri")
    if not isinstance(uri, str) or not uri.strip() or is_absolute(uri):
        return ""
    prefix = uri_to_path(uri)
    return base_prefix(entry.get("uriBaseId"), bases, depth + 1) + (prefix + "/" if prefix else "")


def artifact_path(location, run):
    """Percorso di un artifactLocation (uri diretto o tramite run.artifacts[index]); '' se non indica un file."""
    location = as_dict(location)
    uri, base = location.get("uri"), location.get("uriBaseId")
    artifacts = as_list(run.get("artifacts"))
    index = location.get("index")
    if (not isinstance(uri, str) or not uri.strip()) and isinstance(index, int) and not isinstance(index, bool) \
            and 0 <= index < len(artifacts):
        art = as_dict(as_dict(artifacts[index]).get("location"))
        uri, base = art.get("uri"), art.get("uriBaseId", base)
    if not isinstance(uri, str) or not uri.strip():
        return ""
    if is_absolute(uri):
        return uri_to_path(uri)
    return norm_path(base_prefix(base, run.get("originalUriBaseIds")) + uri_to_path(uri))


def start_line(region):
    line = as_dict(region).get("startLine")
    return line if isinstance(line, int) and not isinstance(line, bool) and line >= 1 else None


def logical_name(location):
    for logical in as_list(as_dict(location).get("logicalLocations")):
        for key in ("fullyQualifiedName", "decoratedName", "name"):
            value = as_dict(logical).get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def primary_location(result, run):
    """(percorso, riga, location) della prima posizione fisica; ripiega su analysisTarget."""
    for location in as_list(result.get("locations")):
        physical = as_dict(as_dict(location).get("physicalLocation"))
        path = artifact_path(physical.get("artifactLocation"), run)
        if path:
            return path, start_line(physical.get("region")), location
    return artifact_path(result.get("analysisTarget"), run), None, {}


def trace_of(result, run, resolve):
    """Passi del primo codeFlow (ruolo e metodo @ file:riga @ codice o stato): al massimo 5, tenendo inizio e fine."""
    for flow in as_list(result.get("codeFlows")):
        for thread in as_list(as_dict(flow).get("threadFlows")):
            steps = []
            for step in as_list(as_dict(thread).get("locations")):
                location = as_dict(as_dict(step).get("location"))
                physical = as_dict(location.get("physicalLocation"))
                path = artifact_path(physical.get("artifactLocation"), run)
                if path and resolve:
                    path = resolve(path)[0]
                line = start_line(physical.get("region"))
                where = "{0}:{1}".format(path, line) if path and line else path
                state = ", ".join(t for t in (text_of(v) for v in as_dict(as_dict(step).get("state")).values()) if t)
                code = text_of(as_dict(physical.get("region")).get("snippet")) or state
                role, name = text_of(location.get("message")).strip(), logical_name(location)
                if role.lower() in ("none", "null"):      # AppScan scrive "None" per i passi senza ruolo
                    role = ""
                head = "{0}: {1}".format(role, name) if role and name else (name or role)
                text = " @ ".join(x for x in (head, where, code.strip()) if x)
                if text:
                    steps.append(short(text, 200))
            if steps:
                return steps if len(steps) <= TRACE_STEPS else steps[:2] + ["…"] + steps[-2:]
    return None


# ---------------------------------------------------------------- risultati

def suppressed(result):
    statuses = [as_dict(s).get("status", "accepted") for s in as_list(result.get("suppressions"))]
    return "accepted" in statuses and not any(s in ("underReview", "rejected") for s in statuses)


def stable_id(result):
    """Identificativo dato dallo strumento: guid, correlationGuid o la prima impronta; None se manca."""
    for key in ("guid", "correlationGuid"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key in ("fingerprints", "partialFingerprints"):
        prints = as_dict(result.get(key))
        for k in sorted(prints):
            if isinstance(prints[k], str) and prints[k].strip():
                return prints[k].strip()
    return None


def utc_date(value):
    """Data UTC (AAAA-MM-GG) da un timestamp ISO 8601 del SARIF; None se non valido."""
    m = _DATE.match(value.strip()) if isinstance(value, str) else None
    if not m:
        return None
    y, mo, d, h, mi, s, zone = m.groups()
    try:
        moment = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0))
    except ValueError:
        return None
    if zone and zone.upper() != "Z":
        sign = 1 if zone[0] == "+" else -1
        moment -= sign * datetime.timedelta(hours=int(zone[1:3]), minutes=int(zone[-2:]))
    return moment.date()


def read_report_date(runs):
    dates = []
    for run in runs:
        for invocation in as_list(run.get("invocations")):
            invocation = as_dict(invocation)
            moment = utc_date(invocation.get("endTimeUtc")) or utc_date(invocation.get("startTimeUtc"))
            if moment:
                dates.append(moment)
    return max(dates).isoformat() if dates else None


def tool_name(run):
    driver = as_dict(as_dict(run.get("tool")).get("driver"))
    name = driver.get("name") if isinstance(driver.get("name"), str) else "(strumento senza nome)"
    version = next((driver[k] for k in ("semanticVersion", "version") if isinstance(driver.get(k), str) and driver[k]), "")
    return " ".join(x for x in (name.strip(), version.strip()) if x)


def load_sarif(path):
    try:
        with io.open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except ValueError as e:
        raise InputError("SARIF non leggibile ({0}): non è un JSON valido ({1}).".format(os.path.basename(path), e))
    except OSError as e:
        raise InputError("SARIF non leggibile ({0}): {1}".format(os.path.basename(path), e))
    name = os.path.basename(path)
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        raise InputError("Il file {0} non sembra un SARIF: manca l'elenco 'runs'.".format(name))
    if data.get("version") != SARIF_VERSION:
        raise InputError("Versione SARIF non supportata in {0}: {1!r}. Serve SARIF {2}.".format(
            name, data.get("version"), SARIF_VERSION))
    if not all(isinstance(run, dict) for run in data["runs"]):
        raise InputError("Il SARIF {0} contiene una run che non è un oggetto.".format(name))
    return data


def report_names(paths):
    """Nome di ogni report per i metadati: il nome del file, con la cartella se due file hanno lo stesso nome."""
    real = [os.path.normcase(os.path.realpath(p)) for p in paths]
    for p, r in zip(paths, real):
        if real.count(r) > 1:
            raise InputError("Lo stesso file SARIF è indicato più volte: {0}".format(p))
    names = [os.path.basename(p) for p in paths]
    lower = [n.lower() for n in names]
    names = ["{0}/{1}".format(os.path.basename(os.path.dirname(os.path.abspath(p))), n) if lower.count(n.lower()) > 1
             else n for p, n in zip(paths, names)]
    lower = [n.lower() for n in names]
    for n in names:
        if lower.count(n.lower()) > 1:
            raise InputError("Più file SARIF hanno lo stesso nome anche con la cartella ({0}): rinominali per "
                             "distinguerli nel report.".format(n))
    return names


def read_findings(files, include_suppressed, resolve):
    """Finding nello stesso formato di parse_appscan.py, più il riepilogo 'sarif'.
    files: [(nome, runs)] nell'ordine indicato. Un risultato già letto da un file precedente (stesso strumento,
    regola, file, riga e identificativo dello strumento) è un duplicato: conta una volta sola."""
    findings, seen, first_file = [], Counter(), {}
    excluded, sources_of_severity, unknown = Counter(), Counter(), Counter()
    total, per_file = 0, []
    many = len(files) > 1
    for file_no, (name, runs) in enumerate(files, 1):
        where = "{0}: ".format(name) if many else ""
        read = kept = 0
        for run_no, run in enumerate(runs, 1):
            driver = as_dict(as_dict(run.get("tool")).get("driver"))
            tool = driver.get("name") if isinstance(driver.get("name"), str) else ""
            if "results" in run and not isinstance(run["results"], list):
                raise InputError("{0}Run #{1}: 'results' deve essere un elenco.".format(where, run_no))
            for result_no, result in enumerate(as_list(run.get("results")), 1):
                total += 1
                read += 1
                if not isinstance(result, dict):
                    raise InputError("{0}Run #{1}, risultato #{2}: non è un oggetto.".format(where, run_no, result_no))
                if result.get("kind", "fail") not in PROBLEM_KINDS:
                    excluded["not_a_problem"] += 1
                    continue
                if result.get("baselineState") == "absent":
                    excluded["absent"] += 1
                    continue
                if suppressed(result) and not include_suppressed:
                    excluded["suppressed"] += 1
                    continue
                rule = find_rule(run, result)
                rule_id = result.get("ruleId") or as_dict(result.get("rule")).get("id") or rule.get("id") or ""
                path, line, location = primary_location(result, run)
                if not path:
                    raise InputError("{0}Run #{1}, risultato #{2} ({3}): nessuna posizione fisica con un file "
                                     "(physicalLocation): formato non supportato.".format(
                                         where, run_no, result_no, rule_id or "senza regola"))
                file, match = resolve(path) if resolve else (path, None)
                stable = stable_id(result)
                if stable and first_file.setdefault((tool, str(rule_id), file, line, stable), file_no) < file_no:
                    excluded["duplicate"] += 1
                    continue
                message = message_text(result.get("message"), rule, driver)
                title = title_of(rule, rule_id, message)
                severity, source, raw = severity_of(result, rule)
                sources_of_severity[source] += 1
                if raw:
                    unknown[raw] += 1
                ident = stable or "{0}run{1}/result{2}".format("file{0}/".format(file_no) if many else "",
                                                             run_no, result_no)
                seen[ident] += 1
                if seen[ident] > 1:
                    ident = "{0}#{1}".format(ident, seen[ident])
                logical = logical_name(location)
                cause = [m for m in (message if message.strip() != title.strip() else "",
                                     logical if logical and norm_path(logical) != path else "") if m]
                threat = prop((result.get("properties"), rule.get("properties")), ("threatclass", "issuetype"))
                finding = {
                    "id": "AS-{0:03d}".format(len(findings) + 1),
                    "scanner_issue_id": ident,
                    "title": short(title, 120),
                    "scanner_severity": severity,
                    "cwe": cwe_of(result, rule, run),
                    "threat_class": short(str(threat), 80) if threat is not None else "",
                    "cause": short(" — ".join(cause)),
                    "file": file,
                    "line": line,
                }
                if resolve:
                    finding["file_match"] = match
                trace = trace_of(result, run, resolve)
                if trace:
                    finding["trace"] = trace
                findings.append(finding)
                kept += 1
        per_file.append({"name": name, "results": read, "findings": kept})
    summary = {"tools": [], "results": total, "files": per_file,
               "excluded": {k: excluded[k] for k in ("suppressed", "absent", "not_a_problem", "duplicate")},
               "severity_from": {k: sources_of_severity[k] for k in ("tool", "security-severity", "level")}}
    for _, runs in files:
        for run in runs:
            name = tool_name(run)
            if name not in summary["tools"]:
                summary["tools"].append(name)
    repeated = sum(n - 1 for n in seen.values() if n > 1)
    return findings, summary, unknown, repeated


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")   # niente crash su console con codifiche limitate
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report", nargs="+", help="uno o più report SARIF 2.1.0 (obbligatorio)")
    ap.add_argument("-o", "--output", required=True, help="file JSON di uscita")
    ap.add_argument("--sources", help="cartella dei sorgenti")
    ap.add_argument("--sca", help="report SCA in HTML (facoltativo)")
    ap.add_argument("--include-suppressed", action="store_true",
                    help="tiene anche i risultati soppressi nello strumento (di norma esclusi)")
    args = ap.parse_intermixed_args(argv)
    many = len(args.report) > 1
    the_sarif = "i SARIF" if many else "il SARIF"

    warnings = []
    try:
        for label, p in [("Report SARIF", r) for r in args.report] + [("SCA", args.sca)]:
            if p and not os.path.isfile(p):
                raise InputError("{0} non trovato: {1}".format(label, p))
        if args.sources and not os.path.isdir(args.sources):
            raise InputError("Cartella dei sorgenti non trovata: {0}".format(args.sources))
        names = report_names(args.report)
        files = [(name, load_sarif(p)["runs"]) for name, p in zip(names, args.report)]
        resolver = make_resolver(args.sources, class_names=True) if args.sources else None
        cache = {}

        def resolve(path):
            if path not in cache:
                cache[path] = resolver(path)
            return cache[path]

        findings, summary, unknown, repeated = read_findings(files, args.include_suppressed, resolve if resolver else None)
        if not findings:
            raise InputError("{0} non {1} finding da valutare ({2} risultati letti, {3} esclusi).".format(
                "I SARIF" if many else "Il SARIF", "contengono" if many else "contiene", summary["results"],
                sum(summary["excluded"].values())))
        warnings.append("{0} non {1} il totale dei finding: controllo dei conteggi non possibile.".format(
            the_sarif, "dichiarano" if many else "dichiara"))
        report_date = read_report_date([run for _, runs in files for run in runs])
        if report_date is None:
            warnings.append("{0} non {1} una data del report affidabile (invocations): scanner_report_date sarà "
                            "null.".format(the_sarif, "contengono" if many else "contiene"))
        sources = None
        if resolver:
            found = sum(1 for f in findings if f["file_match"] in ("path", "basename", "class"))
            sources = {"checked": True, "found": found, "not_found": len(findings) - found}
        sca = read_sca(args.sca) if args.sca else None
    except InputError as e:
        print("Errore: {0}".format(e), file=sys.stderr)
        return 1
    for value, n in sorted(unknown.items()):
        warnings.append("gravità dello strumento non riconosciuta {0!r} in {1} risultati: usati security-severity "
                        "o level.".format(value, n))
    if repeated:
        warnings.append("{0} risultati con identificativo ripetuto: distinti con #2, #3...".format(repeated))
    if summary["excluded"]["suppressed"]:
        warnings.append("{0} risultati soppressi nello strumento esclusi: per includerli riesegui con "
                        "--include-suppressed.".format(summary["excluded"]["suppressed"]))
    if summary["excluded"]["duplicate"]:
        warnings.append("{0} risultati già letti da un file precedente (stesso strumento, regola, file, riga e "
                        "identificativo) contati una volta sola.".format(summary["excluded"]["duplicate"]))
    for f in summary["files"]:
        if many and not f["findings"]:
            warnings.append("{0}: nessun finding da valutare ({1} risultati letti).".format(f["name"], f["results"]))

    by_sev = Counter(f["scanner_severity"] for f in findings)
    out = {"report": " + ".join(names),
           "report_date": report_date,
           "project_name": project_name_of(args.sources),
           "counts": {"total": len(findings), "by_scanner_severity": dict(by_sev)},
           "sources": sources, "xml": None, "sca_summary": sca, "sarif": summary, "findings": findings}
    folder = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(folder, exist_ok=True)
    with io.open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")

    print("Strumento: {0}".format("; ".join(summary["tools"])))
    if many:
        print("File SARIF: {0}".format("; ".join("{name} {findings} finding su {results} risultati".format(**f)
                                                 for f in summary["files"])))
    print("Finding letti: {0} ({1})".format(len(findings), ", ".join(
        "{0} {1}".format(s, by_sev[s]) for s in SEVERITIES if by_sev.get(s))))
    print("Gravità ricavata da: campo dello strumento {tool}, security-severity {security-severity}, "
          "level {level}".format(**summary["severity_from"]))
    ex = summary["excluded"]
    if any(ex.values()):
        print("Risultati esclusi: {0} soppressi, {1} non più presenti (absent), {2} che non sono problemi "
              "(pass, notApplicable, informational){3}".format(
                  ex["suppressed"], ex["absent"], ex["not_a_problem"],
                  ", {0} duplicati di un file precedente".format(ex["duplicate"]) if many else ""))
    if sources:
        print("File trovati nei sorgenti: {0} su {1}".format(sources["found"], len(findings)))
    print("Tracce (codeFlows): {0} finding".format(sum(1 for f in findings if f.get("trace"))))
    if sca:
        print("SCA: {0} problemi su {1} librerie".format(sca["total"], len(sca["libraries"])))
    for w in warnings:
        print("Avviso: {0}".format(w))
    print("Scritto: {0}".format(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
