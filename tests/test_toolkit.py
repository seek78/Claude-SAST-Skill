# -*- coding: utf-8 -*-
"""Test di non regressione del toolkit (solo libreria standard).

Esecuzione, dalla cartella del toolkit:
  python -m unittest discover -s tests

- L'output con CSV + XML resta quello della versione 1.0.0 (fixtures/expected_v1, prodotti con gli script
  originali): cambiano solo la riga della security review nel piano e la versione del toolkit.
- Un SARIF equivalente al CSV produce lo stesso report: cambiano solo nome e data del report scanner.
- parse_sarif.py: gravità, esclusioni, percorsi, regole, date ed errori su SARIF costruiti nei test.
- build_triage.py: validazione della terza analisi (security-review.json).
"""

import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")
TRIAGE = os.path.join(ROOT, "skills", "sast-triage", "scripts")
REMEDIATION = os.path.join(ROOT, "skills", "sast-remediation", "scripts")
DEMO = os.path.join(FIX, "demo")
PLAN_LINE = ("Terza analisi, dopo le verifiche standard: security review di tutta la cartella dei sorgenti con il "
             "metodo di `/security-review` di Claude Code. Solo le vulnerabilità confermate diventano `OBS`, senza "
             "duplicare finding o altre `OBS`.\n\n")


def run(script, *args):
    """Esegue uno script del toolkit come da riga di comando: (esito, stdout, stderr)."""
    p = subprocess.run([sys.executable, "-I", script] + [str(a) for a in args],
                       capture_output=True, text=True, encoding="utf-8")
    return p.returncode, p.stdout, p.stderr


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def read_json(path):
    with io.open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def write_json(path, data, bom=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with io.open(path, "w", encoding="utf-8-sig" if bom else "utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)


class Workspace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sast-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)

    def pipeline(self, name, report, xml=None, review=None, analysis=None):
        """parse → piano → triage.json → report, nella cartella <tmp>/<name>/sast-output/triage."""
        triage = self.path(name, "sast-output", "triage")
        parsed = os.path.join(triage, "_work", "parsed.json")
        if report.endswith(".sarif"):
            code, out, err = run(os.path.join(TRIAGE, "parse_sarif.py"), report, "--sources", DEMO, "-o", parsed)
        else:
            extra = ["--xml", xml] if xml else []
            code, out, err = run(os.path.join(TRIAGE, "parse_appscan.py"), report, "--sources", DEMO, "-o", parsed, *extra)
        self.assertEqual(code, 0, err)
        code, out, err = run(os.path.join(TRIAGE, "make_plan.py"), "--parsed", parsed,
                             "--input", os.path.join(FIX, "plan-input.json"), "-o", os.path.join(triage, "PIANO_TRIAGE.md"))
        self.assertEqual(code, 0, err)
        code, out, err = run(os.path.join(TRIAGE, "build_triage.py"), "--parsed", parsed,
                             "--analysis", analysis or os.path.join(FIX, "analysis.json"),
                             "--security-review", review or os.path.join(FIX, "security-review.json"),
                             "-o", os.path.join(triage, "triage.json"))
        self.assertEqual(code, 0, err)
        code, out, err = run(os.path.join(TRIAGE, "make_report.py"), os.path.join(triage, "triage.json"))
        self.assertEqual(code, 0, err)
        return triage


# ---------------------------------------------------------------- output invariato

class TestOutputInvariato(Workspace):
    def test_parsed_csv_identico_alla_v1(self):
        out = self.path("parsed.json")
        code, _, err = run(os.path.join(TRIAGE, "parse_appscan.py"), os.path.join(FIX, "appscan", "report.csv"),
                           "--sources", DEMO, "-o", out, "--xml", os.path.join(FIX, "appscan", "report.xml"))
        self.assertEqual(code, 0, err)
        self.assertEqual(read_bytes(out), read_bytes(os.path.join(FIX, "expected_v1", "parsed.json")))

    def test_output_csv_come_la_v1(self):
        triage = self.pipeline("csv", os.path.join(FIX, "appscan", "report.csv"), xml=os.path.join(FIX, "appscan", "report.xml"))
        expected = os.path.join(FIX, "expected_v1")
        self.assertEqual(read_bytes(os.path.join(triage, "TRIAGE_REPORT.csv")),
                         read_bytes(os.path.join(expected, "TRIAGE_REPORT.csv")))
        plan = read_bytes(os.path.join(triage, "PIANO_TRIAGE.md")).decode("utf-8")
        self.assertIn(PLAN_LINE, plan)
        self.assertEqual(plan.replace(PLAN_LINE, "", 1), read_bytes(os.path.join(expected, "PIANO_TRIAGE.md")).decode("utf-8"))
        for name, old, new in (("triage.json", '"toolkit_version": "1.0.0"', '"toolkit_version": "1.1.0"'),
                               ("TRIAGE_REPORT.md", "Versione toolkit: `1.0.0`", "Versione toolkit: `1.1.0`")):
            got = read_bytes(os.path.join(triage, name)).decode("utf-8")
            want = read_bytes(os.path.join(expected, name)).decode("utf-8")
            self.assertIn(new, got)
            self.assertEqual(got, want.replace(old, new), name)

    def test_sarif_stessi_finding_del_csv(self):
        out = self.path("parsed.json")
        code, stdout, err = run(os.path.join(TRIAGE, "parse_sarif.py"), os.path.join(FIX, "appscan", "report.sarif"),
                                "--sources", DEMO, "-o", out)
        self.assertEqual(code, 0, err)
        sarif, csv = read_json(out), read_json(os.path.join(FIX, "expected_v1", "parsed.json"))
        keys = ("id", "scanner_issue_id", "title", "scanner_severity", "cwe", "file", "line")
        self.assertEqual([{k: f[k] for k in keys} for f in sarif["findings"]], [{k: f[k] for k in keys} for f in csv["findings"]])
        self.assertEqual(sarif["counts"], csv["counts"])
        self.assertEqual(sarif["sources"], {"checked": True, "found": 5, "not_found": 0})
        self.assertEqual([f["file_match"] for f in sarif["findings"]], ["class", "class", "path", "path", "path"])
        self.assertIsNone(sarif["xml"])
        self.assertIsNone(sarif["report_date"])           # l'export SARIF di AppScan non ha una data
        self.assertEqual(sarif["sarif"]["tools"], ["HCL AppScan Static Analyzer"])
        self.assertEqual(sarif["findings"][0]["trace"][-1].split(" @ ")[1], "Src/Demo.Shop/Persistence/OrderRepository.cs:17")
        self.assertIn("Strumento: HCL AppScan Static Analyzer", stdout)

    def test_output_sarif_come_csv(self):
        csv = self.pipeline("csv", os.path.join(FIX, "appscan", "report.csv"), xml=os.path.join(FIX, "appscan", "report.xml"))
        sarif = self.pipeline("sarif", os.path.join(FIX, "appscan", "report.sarif"))
        self.assertEqual(read_bytes(os.path.join(csv, "TRIAGE_REPORT.csv")), read_bytes(os.path.join(sarif, "TRIAGE_REPORT.csv")))
        a, b = read_json(os.path.join(csv, "triage.json")), read_json(os.path.join(sarif, "triage.json"))
        self.assertEqual((b["metadata"]["scanner_report_name"], b["metadata"]["scanner_report_date"]), ("report.sarif", None))
        for data in (a, b):
            del data["metadata"]["scanner_report_name"], data["metadata"]["scanner_report_date"]
        self.assertEqual(a, b)
        report_line = {"csv": "- Report scanner: `report.csv` (2026-01-15)",
                       "sarif": "- Report scanner: `report.sarif` (data non disponibile)"}
        for name, extra in (("TRIAGE_REPORT.md", {}),
                            ("PIANO_TRIAGE.md", {"csv": "- XML: 5 finding abbinati su 5",
                                                 "sarif": "- XML: non previsto con il SARIF (tracce dai codeFlows: 2 finding su 5)"})):
            got_csv = read_bytes(os.path.join(csv, name)).decode("utf-8").replace(report_line["csv"], "<report>")
            got_sarif = read_bytes(os.path.join(sarif, name)).decode("utf-8").replace(report_line["sarif"], "<report>")
            if extra:
                got_csv = got_csv.replace(extra["csv"], "<xml>")
                got_sarif = got_sarif.replace(extra["sarif"], "<xml>")
            self.assertEqual(got_csv, got_sarif, name)

    def test_nomi_di_classe_risolti_solo_dal_sarif(self):
        """Scelta esplicita: il CSV resta identico alla v1, quindi un Source File con il nome di classe (export di
        AppScan on Cloud per il codice compilato) non viene risolto; il SARIF della stessa scansione sì."""
        rows = io.open(os.path.join(FIX, "appscan", "report.csv"), encoding="utf-8-sig", newline="").read()
        report = self.path("classi.csv")
        with io.open(report, "w", encoding="utf-8-sig", newline="") as fh:
            fh.write(rows.replace("C:\\build\\demo\\Src\\Demo.Shop\\Persistence\\OrderRepository.cs",
                                  "Demo.Shop.Persistence.OrderRepository.cs"))
        out = self.path("parsed.json")
        code, stdout, err = run(os.path.join(TRIAGE, "parse_appscan.py"), report, "--sources", DEMO, "-o", out)
        self.assertEqual(code, 0, err)
        csv = read_json(out)
        self.assertEqual([(f["file"], f["file_match"]) for f in csv["findings"][:2]],
                         [("Demo.Shop.Persistence.OrderRepository.cs", "not_found")] * 2)
        self.assertEqual(csv["sources"], {"checked": True, "found": 3, "not_found": 2})
        code, _, err = run(os.path.join(TRIAGE, "parse_sarif.py"), os.path.join(FIX, "appscan", "report.sarif"),
                           "--sources", DEMO, "-o", out)
        self.assertEqual(code, 0, err)
        self.assertEqual([(f["file"], f["file_match"]) for f in read_json(out)["findings"][:2]],
                         [("Src/Demo.Shop/Persistence/OrderRepository.cs", "class")] * 2)

    def test_remediation_legge_il_triage(self):
        for name, report, xml in (("csv", "report.csv", "report.xml"), ("sarif", "report.sarif", None)):
            triage = self.pipeline(name, os.path.join(FIX, "appscan", report), xml=os.path.join(FIX, "appscan", xml) if xml else None)
            code, out, err = run(os.path.join(REMEDIATION, "read_triage.py"), os.path.join(triage, "triage.json"), "--sources", DEMO)
            self.assertEqual(code, 0, err)
            self.assertIn("Candidati alla remediation (4)", out)

    def test_file_condivisi_identici(self):
        for rel in (("scripts", "check_secrets.py"), ("scripts", "triage_contract.py"), ("references", "output-contract.md")):
            self.assertEqual(read_bytes(os.path.join(ROOT, "skills", "sast-triage", *rel)),
                             read_bytes(os.path.join(ROOT, "skills", "sast-remediation", *rel)), "/".join(rel))


# ---------------------------------------------------------------- parse_sarif.py

def sarif_doc(results, rules=None, **run_extra):
    driver = {"name": "Strumento", "version": "1.0"}
    if rules is not None:
        driver["rules"] = rules
    run_obj = {"tool": {"driver": driver}, "results": results}
    run_obj.update(run_extra)
    return {"version": "2.1.0", "runs": [run_obj]}


def result(uri="src/App/Data/OrderRepository.cs", line=10, **extra):
    r = {"ruleId": "R1", "message": {"text": "Messaggio"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}]}
    r.update(extra)
    return r


class TestParseSarif(Workspace):
    def setUp(self):
        super().setUp()
        self.sources = self.path("progetto")
        for rel in ("src/App/Data/OrderRepository.cs", "src/Legacy/OrderRepository.cs", "src/App/Web/Home Page.cs",
                    "src/App/Data/Customer.cs"):
            p = os.path.join(self.sources, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").close()

    def parse(self, doc, *extra, sources=True):
        report = self.path("in", "report.sarif")
        write_json(report, doc, bom=True)
        out = self.path("out", "parsed.json")
        if os.path.exists(out):
            os.remove(out)
        args = [report, "-o", out] + (["--sources", self.sources] if sources else []) + list(extra)
        code, stdout, stderr = run(os.path.join(TRIAGE, "parse_sarif.py"), *args)
        return code, stdout, stderr, read_json(out) if code == 0 else None

    def test_gravita_campo_strumento_poi_security_severity_poi_level(self):
        rules = [{"id": "R1", "properties": {"security-severity": "9.1"}},
                 {"id": "R2", "defaultConfiguration": {"level": "error"}},
                 {"id": "R3", "properties": {"security-severity": "0.0"}}]
        results = [result(properties={"Severity": "Low"}),                 # campo dello strumento prevale
                   result(),                                                 # security-severity 9.1 -> Critical
                   result(ruleId="R2"),                                      # level della regola -> High
                   result(ruleId="R2", level="note"),                        # level del risultato -> Low
                   result(ruleId="R9"),                                      # nessuna regola: warning -> Medium
                   result(ruleId="R9", kind="review"),                       # kind non fail: none -> Informational
                   result(ruleId="R3"),                                      # 0.0 -> Informational
                   result(ruleId="R9", properties={"issue_severity": "Critico"}),
                   result(ruleId="R9", properties={"severity": "Blocker"})]  # non riconosciuta: ripiega su level
        code, out, err, parsed = self.parse(sarif_doc(results, rules))
        self.assertEqual(code, 0, err)
        self.assertEqual([f["scanner_severity"] for f in parsed["findings"]],
                         ["Low", "Critical", "High", "Low", "Medium", "Informational", "Informational", "Critical", "Medium"])
        self.assertEqual(parsed["sarif"]["severity_from"], {"tool": 2, "security-severity": 2, "level": 5})
        self.assertIn("gravità dello strumento non riconosciuta 'Blocker'", out)

    def test_esclusioni(self):
        results = [result(),
                   result(suppressions=[{"kind": "inSource"}]),                                   # accettata (predefinito)
                   result(suppressions=[{"kind": "external", "status": "accepted"}]),
                   result(suppressions=[{"kind": "external", "status": "underReview"}]),          # resta
                   result(suppressions=[{"kind": "external", "status": "rejected"}]),             # resta
                   result(baselineState="absent"),
                   result(kind="pass"), result(kind="notApplicable"), result(kind="informational"),
                   result(kind="open")]
        code, out, err, parsed = self.parse(sarif_doc(results))
        self.assertEqual(code, 0, err)
        self.assertEqual(parsed["counts"]["total"], 4)
        self.assertEqual(parsed["sarif"]["excluded"], {"suppressed": 2, "absent": 1, "not_a_problem": 3})
        self.assertIn("--include-suppressed", out)
        code, out, err, parsed = self.parse(sarif_doc(results), "--include-suppressed")
        self.assertEqual(parsed["counts"]["total"], 6)

    def test_percorsi(self):
        bases = {"SRCROOT": {"uri": "file:///C:/build/progetto/"}, "SRC": {"uri": "src/", "uriBaseId": "SRCROOT"}}
        artifacts = [{"location": {"uri": "App/Data/OrderRepository.cs", "uriBaseId": "SRC"}}]
        results = [result(uri="App/Web/Home%20Page.cs", line=3),                               # uriBaseId + percent-encoding
                   result(locations=[{"physicalLocation": {"artifactLocation": {"index": 0}}}]),  # artifacts + uriBaseId
                   result(uri="file:///C:/build/progetto/src/App/Data/Customer.cs"),             # URI assoluto
                   result(uri="file:///src\\App\\Data\\Customer.cs"),                             # backslash (AppScan)
                   result(uri="file:///App.Data.OrderRepository.cs"),                             # nome di classe
                   result(uri="file:///Other.OrderRepository.cs"),                                # classe ambigua
                   result(uri="file:///Nothing.Here.Missing.cs")]
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "SRC"
        code, out, err, parsed = self.parse(sarif_doc(results, originalUriBaseIds=bases, artifacts=artifacts))
        self.assertEqual(code, 0, err)
        got = [(f["file"], f["file_match"], f["line"]) for f in parsed["findings"]]
        self.assertEqual(got, [("src/App/Web/Home Page.cs", "path", 3),
                               ("src/App/Data/OrderRepository.cs", "path", None),
                               ("src/App/Data/Customer.cs", "path", 10),
                               ("src/App/Data/Customer.cs", "path", 10),
                               ("src/App/Data/OrderRepository.cs", "class", 10),
                               ("Other.OrderRepository.cs", "ambiguous", 10),
                               ("Nothing.Here.Missing.cs", "not_found", 10)])
        self.assertEqual(parsed["sources"], {"checked": True, "found": 5, "not_found": 2})

    def test_regole_titoli_cwe_messaggi(self):
        rules = [{"id": "cs/sql-injection", "name": "cs/sql-injection",
                  "shortDescription": {"text": "SQL costruito da input dell'utente"},
                  "properties": {"tags": ["security", "external/cwe/cwe-089", "external/cwe/cwe-564"]}},
                 {"id": "B608", "name": "hardcoded_sql_expressions",
                  "relationships": [{"target": {"id": "89", "toolComponent": {"name": "CWE"}}}]},
                 {"id": "TPL", "messageStrings": {"m": {"text": "Valore {0} usato in {1}"}}}]
        ext = [{"name": "Estensione", "rules": [{"id": "EXT1", "shortDescription": {"text": "Regola di estensione"}}]}]
        results = [result(ruleId="cs/sql-injection/variant"),                                    # id gerarchico
                   result(ruleId="B608", ruleIndex=1),
                   result(ruleId="TPL", message={"id": "m", "arguments": ["x", "[query](1)"]}),
                   result(ruleId="EXT1", rule={"id": "EXT1", "index": 0, "toolComponent": {"index": 0}}),
                   result(ruleId="NOPE", message={"text": "Vedi [qui](2) {{nota}}"},
                          taxa=[{"id": "79", "toolComponent": {"name": "CWE"}}], properties={"CWE_ID": "CWE-80"})]
        doc = sarif_doc(results, rules)
        doc["runs"][0]["tool"]["extensions"] = ext
        code, out, err, parsed = self.parse(doc)
        self.assertEqual(code, 0, err)
        f = parsed["findings"]
        self.assertEqual([x["title"] for x in f], ["SQL costruito da input dell'utente", "hardcoded_sql_expressions",
                                                   "Valore x usato in query", "Regola di estensione", "Vedi qui {nota}"])
        self.assertEqual([x["cwe"] for x in f], ["89, 564", "89", "", "", "80, 79"])
        self.assertEqual(f[0]["cause"], "Messaggio")

    def test_id_e_date(self):
        results = [result(guid="g-1"), result(guid="g-1"), result(fingerprints={"b": "fp-b", "a": "fp-a"}),
                   result(partialFingerprints={"primaryLocationLineHash": "plh"}), result()]
        invocations = [{"startTimeUtc": "2026-02-01T10:00:00Z", "endTimeUtc": "2026-02-01T23:30:00-02:00"},
                       {"endTimeUtc": "non è una data"}]
        code, out, err, parsed = self.parse(sarif_doc(results, invocations=invocations))
        self.assertEqual(code, 0, err)
        self.assertEqual([x["scanner_issue_id"] for x in parsed["findings"]], ["g-1", "g-1#2", "fp-a", "plh", "run1/result5"])
        self.assertEqual(parsed["report_date"], "2026-02-02")            # 23:30 a UTC-2 è il giorno dopo in UTC
        self.assertIn("1 risultati con identificativo ripetuto", out)

    def test_tracce(self):
        steps = [{"location": {"physicalLocation": {"artifactLocation": {"uri": "file:///App.Data.OrderRepository.cs"},
                                                    "region": {"startLine": n}},
                               "logicalLocations": [{"fullyQualifiedName": "M{0}".format(n)}],
                               "message": {"text": "Source" if n == 1 else "None"}},
                  "state": {"taint": {"text": "v{0}".format(n)}}} for n in range(1, 8)]
        code, out, err, parsed = self.parse(sarif_doc([result(codeFlows=[{"threadFlows": [{"locations": steps}]}])]))
        self.assertEqual(code, 0, err)
        trace = parsed["findings"][0]["trace"]
        self.assertEqual(trace, ["Source: M1 @ src/App/Data/OrderRepository.cs:1 @ v1",
                                 "M2 @ src/App/Data/OrderRepository.cs:2 @ v2", "…",
                                 "M6 @ src/App/Data/OrderRepository.cs:6 @ v6",
                                 "M7 @ src/App/Data/OrderRepository.cs:7 @ v7"])

    def test_errori(self):
        report = self.path("in", "rotto.sarif")
        os.makedirs(os.path.dirname(report), exist_ok=True)
        with open(report, "w", encoding="utf-8") as fh:
            fh.write("{ non è json")
        code, _, err = run(os.path.join(TRIAGE, "parse_sarif.py"), report, "-o", self.path("x.json"))
        self.assertEqual(code, 1)
        self.assertIn("non è un JSON valido", err)
        for doc, message in (({"version": "2.0.0", "runs": []}, "Versione SARIF non supportata"),
                             ({"version": "2.1.0"}, "manca l'elenco 'runs'"),
                             (sarif_doc([{"ruleId": "R1", "message": {"text": "x"}}]), "nessuna posizione fisica"),
                             (sarif_doc([result(kind="pass")]), "non contiene finding da valutare")):
            code, _, err, _ = self.parse(doc)
            self.assertEqual(code, 1, message)
            self.assertIn(message, err)
            self.assertFalse(os.path.exists(self.path("out", "parsed.json")))

    def test_senza_sorgenti(self):
        code, out, err, parsed = self.parse(sarif_doc([result(uri="file:///App.Data.OrderRepository.cs")]), sources=False)
        self.assertEqual(code, 0, err)
        self.assertIsNone(parsed["sources"])
        self.assertIsNone(parsed["project_name"])
        self.assertNotIn("file_match", parsed["findings"][0])
        self.assertEqual(parsed["findings"][0]["file"], "App.Data.OrderRepository.cs")


# ---------------------------------------------------------------- security review in build_triage.py

class TestSecurityReview(Workspace):
    def setUp(self):
        super().setUp()
        self.parsed = self.path("parsed.json")
        code, _, err = run(os.path.join(TRIAGE, "parse_appscan.py"), os.path.join(FIX, "appscan", "report.csv"),
                           "--sources", DEMO, "-o", self.parsed)
        self.assertEqual(code, 0, err)
        self.analysis = read_json(os.path.join(FIX, "analysis.json"))
        self.review = read_json(os.path.join(FIX, "security-review.json"))

    def build(self, analysis=None, review=None):
        a, r = self.path("analysis.json"), self.path("review.json")
        write_json(a, analysis if analysis is not None else self.analysis)
        write_json(r, review if review is not None else self.review)
        out = self.path("triage.json")
        if os.path.exists(out):
            os.remove(out)
        code, stdout, stderr = run(os.path.join(TRIAGE, "build_triage.py"), "--parsed", self.parsed,
                                   "--analysis", a, "--security-review", r, "-o", out)
        if code != 0:
            self.assertFalse(os.path.exists(out))
        return code, stdout, stderr

    def broken(self, change):
        review = copy.deepcopy(self.review)
        change(review)
        return self.build(review=review)

    def test_valida(self):
        code, out, err = self.build()
        self.assertEqual(code, 0, err)
        self.assertIn("Security review: 3 candidate (1 osservazioni, 1 duplicati, 1 scartate).", out)

    def test_obbligatoria(self):
        code, _, err = run(os.path.join(TRIAGE, "build_triage.py"), "--parsed", self.parsed,
                           "--analysis", os.path.join(FIX, "analysis.json"), "-o", self.path("triage.json"))
        self.assertEqual(code, 2)
        self.assertIn("--security-review", err)

    def test_osservazione_senza_provenienza(self):
        code, _, err = self.build(review={"candidates": []})
        self.assertEqual(code, 1)
        self.assertIn("L'osservazione OBS-002 non viene né da una verifica standard", err)

    def test_vuota_con_osservazioni_solo_standard(self):
        analysis = copy.deepcopy(self.analysis)
        analysis["additional_observations"] = analysis["additional_observations"][:1]
        code, out, err = self.build(analysis=analysis, review={"candidates": []})
        self.assertEqual(code, 0, err)

    def test_errori_delle_candidate(self):
        cases = [
            (lambda r: r["candidates"][0].update(confidence=7), "confidenza 7 sotto la soglia di 8"),
            (lambda r: r["candidates"][0].update(area="sql_commands"), "quindi OBS-002 va anche in standard_checks.sql_commands"),
            (lambda r: r["candidates"][0].update(ref="OBS-009"), "deve essere un'osservazione di additional_observations"),
            (lambda r: r["candidates"][1].update(ref="AS-099"), "deve essere un finding del report o un'osservazione esistente"),
            (lambda r: r["candidates"][1].update(reason=""), "un duplicato dice in reason"),
            (lambda r: r["candidates"][2].update(ref="AS-001"), "una candidata scartata ha ref vuoto"),
            (lambda r: r["candidates"][2].update(reason=" "), "una candidata scartata dice perché"),
            (lambda r: r["candidates"][2].update(outcome="forse"), "outcome non valido"),
            (lambda r: r["candidates"][2].update(confidence=11), "confidence deve essere un intero da 1 a 10"),
            (lambda r: r["candidates"][2].update(severity="Critical"), "severity deve essere High, Medium o Low"),
            (lambda r: r["candidates"][2].update(area="xss"), "area non valida"),
            (lambda r: r["candidates"][2].update(extra=1), "campo non previsto dal contratto: 'extra'"),
            (lambda r: r["candidates"][2].pop("title"), "manca il campo 'title'"),
            (lambda r: r["candidates"][2]["location"].update(file="C:/x.cs"), "contiene una lettera di unità"),
            (lambda r: r["candidates"][2].update(reason='password = "Sup3rS3gr3t0!"'), "Possibile segreto in chiaro"),
            (lambda r: r.update(altro=[]), "il solo campo 'candidates'"),
        ]
        for change, message in cases:
            code, _, err = self.broken(change)
            self.assertEqual(code, 1, message)
            self.assertIn(message, err)

    def test_prefisso_obbligatorio(self):
        analysis = copy.deepcopy(self.analysis)
        analysis["additional_observations"][1]["analysis_summary"] = "Il nome del file arriva dalla richiesta."
        code, _, err = self.build(analysis=analysis)
        self.assertEqual(code, 1)
        self.assertIn("analysis_summary deve iniziare con «Security review:»", err)


if __name__ == "__main__":
    unittest.main()
