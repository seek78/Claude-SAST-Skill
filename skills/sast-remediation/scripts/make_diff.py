# -*- coding: utf-8 -*-
"""Crea un diff unificato tra i sorgenti originali e le copie proposte, file per file. Non richiede Git.

Uso:
  python make_diff.py --sources CARTELLA_SORGENTI --proposed CARTELLA_PROPOSTE -o FILE.diff [--manifest PROPOSTE.json]

  --proposed  contiene SOLO i file proposti, con lo stesso percorso relativo dei sorgenti
              (es. <proposed>/app/orders/search.py). Un file che non esiste nei sorgenti
              diventa un file nuovo. Le cancellazioni non sono supportate.
  -o          diff di uscita, FUORI dai sorgenti e mai nella cartella del triage. I percorsi nel diff sono
              relativi (a/... e b/...), i file in ordine alfabetico di percorso.
  --manifest  scrive l'esito per file (PROPOSTE.json): "diff" oppure "segreto_nel_diff" (da trattare con
              make_proposto.py), con l'SHA-256 dell'originale. Mai valori segreti.

Sicurezza, valutata FILE PER FILE: il diff di un file riporta anche le righe di contesto dell'originale. Se contiene
un segreto probabile, quel file NON entra nel diff (il valore non viene mai mostrato). Un segreto in un file non
impedisce di emettere i diff degli altri file della stessa correzione.
Applicazione, dalla radice dei sorgenti: git apply FILE.diff   oppure   patch -p1 < FILE.diff

Esito: 0 tutti i file nel diff | 1 errore o nessuna differenza | 2 uso errato
       3 almeno un file escluso dal diff per un segreto (il diff degli altri file è scritto, se ce ne sono)
"""

import argparse
import difflib
import hashlib
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_secrets import find_secrets  # noqa: E402

_LINE = re.compile(r"[^\r\n]*(?:\r\n|\n|\r)|[^\r\n]+")


def inside(path, root):
    p, r = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(root))
    return p == r or p.startswith(r + os.sep)


def inside_triage_folder(path):
    """True se il percorso sta in una cartella 'triage' che contiene triage.json: la remediation non vi scrive mai."""
    d = os.path.dirname(os.path.realpath(path))
    while True:
        if os.path.basename(d).lower() == "triage" and os.path.isfile(os.path.join(d, "triage.json")):
            return True
        parent = os.path.dirname(d)
        if parent == d:
            return False
        d = parent


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def sha256_of(path):
    return hashlib.sha256(read_bytes(path)).hexdigest() if os.path.isfile(path) else None


def file_diff(rel, old_path, new_path):
    """Originale e proposta si decodificano con lo stesso codec (utf-8, altrimenti latin-1,
    che conserva i byte intatti)."""
    new_bytes = read_bytes(new_path)
    old_bytes = read_bytes(old_path) if os.path.isfile(old_path) else b""
    old_name = "a/" + rel if os.path.isfile(old_path) else "/dev/null"
    try:
        old_text, new_text, codec = old_bytes.decode("utf-8"), new_bytes.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        old_text, new_text, codec = old_bytes.decode("latin-1"), new_bytes.decode("latin-1"), "latin-1"
    a, b = _LINE.findall(old_text), _LINE.findall(new_text)
    lines = list(difflib.unified_diff(a, b, old_name, "b/" + rel, n=3))
    out = []
    for ln in lines:
        out.append(ln if ln.endswith("\n") else ln + "\n\\ No newline at end of file\n")
    return out, codec


def secret_kinds(text):
    """Tipi di segreto nel diff (contesto compreso), togliendo il prefisso +/-/spazio. Mai i valori."""
    kinds = []
    for ln in text.splitlines():
        body = ln[1:] if ln[:1] in "+- " and not ln.startswith(("+++", "---")) else ln
        kinds += [kind for _, kind in find_secrets(body)]
    return sorted(set(kinds))


def proposed_files(proposed):
    rels = []
    for base, _, names in os.walk(proposed):
        for n in names:
            rels.append(os.path.relpath(os.path.join(base, n), proposed).replace("\\", "/"))
    return sorted(rels)


def write_manifest(path, entries, fix_id=None):
    data = {"files": sorted(entries, key=lambda e: e["path"])}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sources", required=True, help="cartella dei sorgenti (sola lettura)")
    ap.add_argument("--proposed", required=True, help="cartella con i soli file proposti")
    ap.add_argument("-o", "--output", required=True, help="file .diff di uscita")
    ap.add_argument("--manifest", help="PROPOSTE.json: esito per file (diff / segreto_nel_diff)")
    args = ap.parse_args(argv)

    for label, p in (("sorgenti", args.sources), ("proposte", args.proposed)):
        if not os.path.isdir(p):
            print("Errore: cartella {0} non trovata: {1}".format(label, p), file=sys.stderr)
            return 1
    if inside(args.proposed, args.sources) or inside(args.output, args.sources):
        print("Errore: le copie proposte e il diff devono stare FUORI dalla cartella dei sorgenti.", file=sys.stderr)
        return 1
    if inside_triage_folder(args.output) or inside_triage_folder(os.path.join(args.proposed, "x")) \
            or (args.manifest and inside_triage_folder(args.manifest)):
        print("Errore: la remediation non scrive mai nella cartella del triage (quella con triage.json).", file=sys.stderr)
        return 1

    safe, excluded, unchanged, entries = [], [], [], []
    for rel in proposed_files(args.proposed):
        if rel.startswith("../") or ".." in rel.split("/"):
            print("Errore: percorso non ammesso: {0}".format(rel), file=sys.stderr)
            return 1
        old_path = os.path.join(args.sources, *rel.split("/"))
        lines, codec = file_diff(rel, old_path, os.path.join(args.proposed, *rel.split("/")))
        if not lines:
            unchanged.append(rel)
            continue
        text = "".join(lines)
        plus = sum(1 for l in lines if l.startswith("+") and not l.startswith("+++"))
        minus = sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))
        kinds = secret_kinds(text)
        if kinds:
            excluded.append((rel, kinds))
            entries.append({"path": rel, "mode": "segreto_nel_diff", "proposal": None, "original_sha256": sha256_of(old_path)})
        else:
            safe.append((rel, text, codec, plus, minus))
            entries.append({"path": rel, "mode": "diff", "proposal": None, "original_sha256": sha256_of(old_path)})
    if not entries:
        print("Errore: nessuna differenza tra sorgenti e proposte: il diff sarebbe vuoto.", file=sys.stderr)
        return 1

    if safe:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "wb") as fh:
            for _, text, codec, _, _ in safe:
                fh.write(text.encode(codec))
        print("Diff scritto: {0}".format(args.output))
        for rel, _, _, plus, minus in safe:
            print("  nel diff: {0}: +{1} -{2}".format(rel, plus, minus))
    else:
        print("Nessun diff scritto: tutti i file modificati contengono un possibile segreto.")
    for rel in unchanged:
        print("  invariato: {0}".format(rel))
    if args.manifest:
        write_manifest(args.manifest, entries)
    for rel, kinds in excluded:
        print("  ESCLUSO dal diff (segreto: {0}; valore non mostrato): {1}".format(", ".join(kinds), rel))
    if excluded:
        print("I file esclusi si trattano con make_proposto.py (sostituzione proposta) o con sole istruzioni, senza riportare il valore.")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
