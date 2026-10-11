# -*- coding: utf-8 -*-
"""Legge un report HCL AppScan e scrive una rappresentazione normalizzata in JSON.

Non assegna verdetti e non trae conclusioni di sicurezza: è la base su cui Claude lavora.

Uso:
  python parse_appscan.py REPORT.csv -o parsed.json [--sources CARTELLA] [--xml REPORT.xml] [--sca REPORT.html]

  REPORT.csv  export CSV di AppScan: elenco AUTOREVOLE dei finding (obbligatorio)
  --sources   cartella dei sorgenti: i percorsi del report diventano relativi a essa
  --xml       export XML della stessa scansione: aggiunge la traccia ai finding che corrispondono
  --sca       report SCA (HTML): ne ricava solo un breve riepilogo
  -o          file JSON di uscita (scritto solo se tutti i controlli passano)

Esito: 0 ok | 1 input non utilizzabile (messaggio in italiano) | 2 uso errato

Formato dell'uscita (intermedio, NON è il contratto del triage):
  {"report": "nome.csv",
   "report_date": "AAAA-MM-GG" | null,
   "project_name": "nome-cartella-sorgenti" | null,
   "counts": {"total": N, "by_scanner_severity": {"High": n, ...}},
   "sources": {"checked": bool, "found": n, "not_found": n} | null,
   "xml": {"matched": n, "not_found": n, "ambiguous": n, "xml_only": n} | null,
   "sca_summary": {...} | null,
   "findings": [{"id": "AS-001", "scanner_issue_id": "...", "title": "...",
                 "scanner_severity": "High", "cwe": "89", "threat_class": "...",
                 "cause": "...", "file": "app/File.ext", "line": 42,
                 "file_match": "path|basename|ambiguous|not_found" (con --sources),
                 "xml": "matched|not_found|ambiguous", "trace": ["..."] (con --xml)}]}

Gli id AS-001, AS-002... seguono l'ordine del CSV e valgono solo per questo ciclo di
triage/remediation: non sono stabili tra scansioni diverse.

Metadati (finiscono in triage.json, mai ricavati da date del file system né dall'orologio):
  report        nome del file CSV, senza cartelle
  report_date   data (UTC) dichiarata dallo scanner nella sezione 'Report Attributes' del CSV
                ('Report Date U T C'), normalizzata AAAA-MM-GG; null se assente o non valida
  project_name  nome dell'ultima cartella del percorso passato a --sources; null senza --sources
I testi liberi sono accorciati e passano da una redazione dei segreti evidenti.
"""

import argparse
import csv
import datetime
import html
import io
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_secrets import redact  # noqa: E402

REQUIRED = ["Issue Id", "Severity", "Issue Type Name", "Source File", "Line"]
NON_EMPTY = ["Issue Id", "Severity", "Issue Type Name", "Source File"]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
MAX_TEXT = 300
_SKIP_DIRS = {".git", "node_modules", "bin", "obj", "__pycache__"}


class InputError(Exception):
    pass


def short(text, limit=MAX_TEXT):
    text = redact(re.sub(r"\s+", " ", text or "").strip())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def read_text(path):
    for enc in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            with io.open(path, encoding=enc, newline="") as fh:
                return fh.read()
        except UnicodeDecodeError:
            continue
    raise InputError("Impossibile leggere il file: {0}".format(path))


# ---------------------------------------------------------------- CSV

def read_sections(text):
    """Il CSV contiene più tabelle: 'Nome sezione:' / intestazione / righe / riga vuota."""
    rows = list(csv.reader(io.StringIO(text)))
    sections, i = {}, 0
    while i < len(rows):
        filled = [c for c in rows[i] if c.strip()]
        if len(filled) == 1 and filled[0].strip().endswith(":") and i + 1 < len(rows):
            header = [c.strip() for c in rows[i + 1]]
            data, j = [], i + 2
            while j < len(rows) and any(c.strip() for c in rows[j]):
                data.append(rows[j])
                j += 1
            sections[filled[0].strip()[:-1].strip()] = (header, data)
            i = j
        else:
            i += 1
    return sections


def to_line(value, n):
    value = (value or "").strip()
    if not value:
        return None
    if not value.isdigit():
        raise InputError("Riga {0} di 'Issue Attributes': il campo 'Line' non è un numero ('{1}').".format(n, value[:20]))
    return int(value) or None


def norm_path(p):
    p = p.strip().replace("\\", "/")
    while "//" in p:
        p = p.replace("//", "/")
    return p.lstrip("/")


def read_findings(sections):
    if "Issue Attributes" not in sections:
        raise InputError("Sezione 'Issue Attributes' non trovata: il file non sembra un export CSV di AppScan.")
    header, rows = sections["Issue Attributes"]
    missing = [c for c in REQUIRED if c not in header]
    if missing:
        raise InputError("Colonne obbligatorie mancanti in 'Issue Attributes': {0}.".format(", ".join(missing)))
    if not rows:
        raise InputError("La sezione 'Issue Attributes' non contiene finding.")
    findings, seen = [], set()
    for n, row in enumerate(rows, 1):
        if len(row) != len(header):
            raise InputError("Riga {0} di 'Issue Attributes': {1} colonne invece di {2}.".format(n, len(row), len(header)))
        rec = dict(zip(header, row))
        for col in NON_EMPTY:
            if not rec[col].strip():
                raise InputError("Riga {0} di 'Issue Attributes': il campo '{1}' è vuoto.".format(n, col))
        ident = rec["Issue Id"].strip()
        if ident in seen:
            raise InputError("Issue Id duplicato nel CSV: {0}.".format(ident))
        seen.add(ident)
        findings.append({
            "id": "AS-{0:03d}".format(n),
            "scanner_issue_id": ident,
            "title": short(rec["Issue Type Name"], 120),
            "scanner_severity": rec["Severity"].strip(),
            "cwe": rec.get("Cwe", "").strip(),
            "threat_class": short(rec.get("Threat Class", ""), 80),
            "cause": short(rec.get("Cause", "")),
            "file": norm_path(rec["Source File"]),
            "line": to_line(rec["Line"], n),
        })
    return findings


def read_report_date(sections):
    """Data del report dichiarata dallo scanner (UTC), come AAAA-MM-GG; None se non affidabile.
    Non si usano mai date dei file né l'orologio."""
    if "Report Attributes" not in sections:
        return None
    header, rows = sections["Report Attributes"]
    if not rows or "Report Date U T C" not in header:
        return None
    value = rows[0][header.index("Report Date U T C")].strip() if len(rows[0]) == len(header) else ""
    m = re.match(r"^(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}", value)
    if not m:
        return None
    try:
        return datetime.date.fromisoformat(m.group(1)).isoformat()
    except ValueError:
        return None


def project_name_of(sources):
    """Nome dell'ultima cartella del percorso dei sorgenti; None se non c'è un nome (es. radice del disco)."""
    if not sources:
        return None
    name = os.path.basename(os.path.abspath(sources).rstrip("\\/"))
    return None if not name or name.endswith(":") else name


def check_declared_counts(sections, findings, warnings):
    errors = []
    total = None
    if "Report Attributes" in sections:
        h, d = sections["Report Attributes"]
        if d and "Total Issues In The Report" in h:
            total = d[0][h.index("Total Issues In The Report")].strip()
    if total and total.isdigit():
        if int(total) != len(findings):
            errors.append("totale: letti {0} finding, il report ne dichiara {1}".format(len(findings), total))
    else:
        warnings.append("il report non dichiara il totale dei finding: controllo non possibile.")
    if "Issue Counters" in sections:
        h, d = sections["Issue Counters"]
        got = Counter(f["scanner_severity"] for f in findings)
        for sev in SEVERITIES:
            col = sev + " Issues"
            if d and col in h and d[0][h.index(col)].strip().isdigit():
                if int(d[0][h.index(col)]) != got.get(sev, 0):
                    errors.append("gravità {0}: letti {1}, dichiarati {2}".format(
                        sev, got.get(sev, 0), d[0][h.index(col)].strip()))
    if errors:
        raise InputError("Il CSV non è coerente con i conteggi che dichiara: " + "; ".join(errors) + ".")


# ---------------------------------------------------------------- sorgenti

_CLASS_NAME = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")


def by_class_name(path, index):
    """Nome di classe qualificato usato al posto del file (es. 'Azienda.Modulo.Repositories.OrderRepository.cs',
    come nel SARIF di AppScan per il codice compilato): cerca 'OrderRepository.cs' e, se più file hanno quel nome,
    sceglie quello le cui cartelle finali corrispondono al namespace. Restituisce (percorso, esito)."""
    stem, _, ext = path.rpartition(".")
    if "/" in path or not ext or not _CLASS_NAME.match(stem):
        return path, "not_found"
    names = stem.split(".")
    for k in range(len(names) - 1, 0, -1):
        same = index.get((".".join(names[k:]) + "." + ext).lower(), [])
        if not same:
            continue
        namespace = [n.lower() for n in names[:k]]

        def score(rel):
            folders = ".".join(rel.split("/")[:-1]).lower().split(".")
            s = 0
            while s < min(len(namespace), len(folders)) and folders[-1 - s] == namespace[-1 - s]:
                s += 1
            return s

        scores = {rel: score(rel) for rel in same}
        best = max(scores.values())
        top = [rel for rel in same if scores[rel] == best]
        return (top[0], "class") if len(top) == 1 else (path, "ambiguous")
    return path, "not_found"


def make_resolver(sources, class_names=False):
    """Restituisce resolve(percorso) -> (percorso, esito), con esito path | basename | class | ambiguous | not_found.
    Rende il percorso relativo ai sorgenti: toglie i segmenti iniziali (radice di scansione) finché il file esiste;
    in alternativa cerca un file con lo stesso nome, se unico. Con class_names prova anche i nomi di classe
    qualificati (by_class_name)."""
    index = {}

    def build_index():
        for root, dirs, names in os.walk(sources):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for n in names:
                rel = os.path.relpath(os.path.join(root, n), sources).replace("\\", "/")
                index.setdefault(n.lower(), []).append(rel)

    def resolve(path):
        parts = path.split("/")
        for k in range(len(parts)):
            if os.path.isfile(os.path.join(sources, *parts[k:])):
                return "/".join(parts[k:]), "path"
        if not index:
            build_index()
        same = index.get(parts[-1].lower(), [])
        if len(same) == 1:
            return same[0], "basename"
        if len(same) > 1:
            return path, "ambiguous"
        return by_class_name(path, index) if class_names else (path, "not_found")

    return resolve


def resolve_files(findings, sources):
    """Rende i percorsi dei finding relativi ai sorgenti (make_resolver) e registra l'esito in file_match."""
    resolve = make_resolver(sources)
    counts = Counter()
    for f in findings:
        f["file"], match = resolve(f["file"])
        f["file_match"] = match
        counts["found" if match in ("path", "basename") else "not_found"] += 1
    return {"checked": True, "found": counts["found"], "not_found": counts["not_found"]}


# ---------------------------------------------------------------- XML

def read_xml(path, findings):
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as e:
        raise InputError("XML non leggibile ({0}): {1}".format(os.path.basename(path), e))
    group = root.find("issue-group")
    if group is None:
        raise InputError("XML non riconosciuto: manca l'elemento 'issue-group' di un export AppScan.")
    by_id = {}
    for item in group.findall("item"):
        ident = (item.findtext("asoc-issue-id") or "").strip()
        if ident:
            by_id.setdefault(ident, []).append(item)
    counts = Counter()
    for f in findings:
        items = by_id.get(f["scanner_issue_id"], [])
        if not items:
            f["xml"] = "not_found"
        elif len(items) > 1:
            f["xml"] = "ambiguous"   # non si indovina: si registra
        else:
            f["xml"] = "matched"
            steps = []
            for inv in items[0].iter("call-invocation"):
                code = " ".join((h.text or "").strip() for h in inv.iter("highlight")).strip()
                steps.append(short(" @ ".join(x for x in ((inv.get("signature") or "").strip(), code) if x), 200))
            f["trace"] = [s for s in steps if s][:5]
        counts[f["xml"]] += 1
    only = len(set(by_id) - {f["scanner_issue_id"] for f in findings})
    return {"matched": counts["matched"], "not_found": counts["not_found"],
            "ambiguous": counts["ambiguous"], "xml_only": only}


# ---------------------------------------------------------------- SCA

_SCA_LABELS = [  # le etichette inglesi non sono state verificate su un report reale
    {"id": "ID problema:", "sev": "Gravità:", "tot": "Problemi di sicurezza totali:",
     "lib": "Nome libreria:", "ver": "Versione libreria:"},
    {"id": "Issue ID:", "sev": "Severity:", "tot": "Total security issues:",
     "lib": "Library name:", "ver": "Library version:"},
]
_SEV_MAP = {"critico": "Critical", "alto": "High", "medio": "Medium", "basso": "Low",
            "informativa": "Informational", "critical": "Critical", "high": "High",
            "medium": "Medium", "low": "Low", "informational": "Informational"}


def read_sca(path):
    raw = read_text(path)
    raw = re.sub(r"(?is)<(script|style).*?</\1>", " ", raw)
    text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", raw)))
    lab = next((l for l in _SCA_LABELS if l["id"] in text), None)
    if lab is None:
        raise InputError("Report SCA non riconosciuto: nessuna etichetta 'ID problema' / 'Issue ID'. "
                         "Formato non supportato, il riepilogo SCA non è stato prodotto.")
    anchors = [m.start() for m in re.finditer(re.escape(lab["id"]), text)]
    declared = re.search(re.escape(lab["tot"]) + r"\s*(\d+)", text)
    if not declared or int(declared.group(1)) != len(anchors):
        raise InputError("Report SCA incoerente: letti {0} problemi, dichiarati {1}.".format(
            len(anchors), declared.group(1) if declared else "non trovato"))
    heads = [(m.start(), m.group(1).strip(), m.group(2)) for m in re.finditer(
        re.escape(lab["lib"]) + r"\s*(.+?)\s+" + re.escape(lab["ver"]) + r"\s*(\S+)", text)]
    libs, by_sev = {}, Counter()
    for i, a in enumerate(anchors):
        block = text[a:anchors[i + 1] if i + 1 < len(anchors) else len(text)]
        name, ver = next(((n, v) for p, n, v in reversed(heads) if p < a), ("(sconosciuta)", ""))
        sev = re.search(re.escape(lab["sev"]) + r"\s*(\w+)", block)
        sev = _SEV_MAP.get(sev.group(1).lower(), sev.group(1)) if sev else "?"
        cvss = re.search(r"CVSS\s+([\d.]+)", block)
        cve = re.search(r"(CVE-\d{4}-\d+)", block)
        by_sev[sev] += 1
        d = libs.setdefault((name, ver), {"name": name, "version": ver, "issues": 0,
                                          "max_severity": "?", "max_cvss": 0.0, "cves": []})
        d["issues"] += 1
        if sev in SEVERITIES and (d["max_severity"] not in SEVERITIES or SEVERITIES.index(sev) < SEVERITIES.index(d["max_severity"])):
            d["max_severity"] = sev
        d["max_cvss"] = max(d["max_cvss"], float(cvss.group(1)) if cvss else 0.0)
        if cve and cve.group(1) not in d["cves"]:
            d["cves"].append(cve.group(1))
    ordered = sorted(libs.values(), key=lambda d: (SEVERITIES.index(d["max_severity"]) if d["max_severity"] in SEVERITIES else 9, -d["max_cvss"], d["name"].lower()))
    return {"total": len(anchors), "by_severity": dict(by_sev), "libraries": ordered[:15]}


# ---------------------------------------------------------------- main

def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")   # niente crash su console con codifiche limitate
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report", help="export CSV di AppScan (obbligatorio)")
    ap.add_argument("-o", "--output", required=True, help="file JSON di uscita")
    ap.add_argument("--sources", help="cartella dei sorgenti")
    ap.add_argument("--xml", help="export XML della stessa scansione (facoltativo)")
    ap.add_argument("--sca", help="report SCA in HTML (facoltativo)")
    args = ap.parse_args(argv)

    warnings = []
    try:
        for label, p in (("Report CSV", args.report), ("XML", args.xml), ("SCA", args.sca)):
            if p and not os.path.isfile(p):
                raise InputError("{0} non trovato: {1}".format(label, p))
        if args.sources and not os.path.isdir(args.sources):
            raise InputError("Cartella dei sorgenti non trovata: {0}".format(args.sources))
        sections = read_sections(read_text(args.report))
        findings = read_findings(sections)
        check_declared_counts(sections, findings, warnings)
        report_date = read_report_date(sections)
        if report_date is None:
            warnings.append("il CSV non contiene una data del report affidabile: scanner_report_date sarà null.")
        sources = resolve_files(findings, args.sources) if args.sources else None
        xml = read_xml(args.xml, findings) if args.xml else None
        sca = read_sca(args.sca) if args.sca else None
    except InputError as e:
        print("Errore: {0}".format(e), file=sys.stderr)
        return 1

    by_sev = Counter(f["scanner_severity"] for f in findings)
    out = {"report": os.path.basename(args.report),
           "report_date": report_date,
           "project_name": project_name_of(args.sources),
           "counts": {"total": len(findings), "by_scanner_severity": dict(by_sev)},
           "sources": sources, "xml": xml, "sca_summary": sca, "findings": findings}
    folder = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(folder, exist_ok=True)
    with io.open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")

    print("Finding letti: {0} ({1})".format(len(findings), ", ".join(
        "{0} {1}".format(s, by_sev[s]) for s in SEVERITIES + sorted(set(by_sev) - set(SEVERITIES)) if by_sev.get(s))))
    if sources:
        print("File trovati nei sorgenti: {0} su {1}".format(sources["found"], len(findings)))
    if xml:
        print("XML: {matched} corrispondenze, {not_found} senza riscontro, {ambiguous} ambigui, "
              "{xml_only} solo nell'XML (ignorati)".format(**xml))
    if sca:
        print("SCA: {0} problemi su {1} librerie".format(sca["total"], len(sca["libraries"])))
    for w in warnings:
        print("Avviso: {0}".format(w))
    print("Scritto: {0}".format(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
