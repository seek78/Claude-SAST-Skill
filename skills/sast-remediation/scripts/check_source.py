# -*- coding: utf-8 -*-
"""Verifica che la cartella dei sorgenti non sia stata modificata durante la remediation.

Uso:
  python check_source.py snapshot CARTELLA_SORGENTI -o snapshot.json
  python check_source.py verify CARTELLA_SORGENTI --snapshot snapshot.json

snapshot  registra percorso relativo e hash SHA-256 di ogni file (mai il contenuto, mai percorsi assoluti).
          Il file di snapshot deve stare FUORI dai sorgenti.
verify    ricalcola e confronta: elenca file modificati, aggiunti e rimossi.

Ignora solo cartelle di metadati ovvie: .git .svn .hg .vs .idea __pycache__ node_modules.
Esito: 0 identico | 1 differenze o errore | 2 uso errato
"""

import argparse
import hashlib
import io
import json
import os
import sys

SKIP_DIRS = {".git", ".svn", ".hg", ".vs", ".idea", "__pycache__", "node_modules"}


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


def hash_tree(root):
    out = {}
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for n in names:
            p = os.path.join(base, n)
            h = hashlib.sha256()
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            out[os.path.relpath(p, root).replace("\\", "/")] = h.hexdigest()
    return out


def show(label, items):
    for rel in sorted(items)[:20]:
        print("  {0}: {1}".format(label, rel))
    if len(items) > 20:
        print("  ... e altri {0} ({1})".format(len(items) - 20, label))


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sn = sub.add_parser("snapshot", help="registra lo stato dei sorgenti")
    sn.add_argument("sorgenti")
    sn.add_argument("-o", "--output", required=True, help="file di snapshot (fuori dai sorgenti)")
    ve = sub.add_parser("verify", help="confronta i sorgenti con lo snapshot")
    ve.add_argument("sorgenti")
    ve.add_argument("--snapshot", required=True)
    args = ap.parse_args(argv)

    if not os.path.isdir(args.sorgenti):
        print("Errore: cartella dei sorgenti non trovata: {0}".format(args.sorgenti), file=sys.stderr)
        return 1
    try:
        if args.cmd == "snapshot":
            if inside(args.output, args.sorgenti):
                print("Errore: lo snapshot deve stare fuori dalla cartella dei sorgenti.", file=sys.stderr)
                return 1
            if inside_triage_folder(args.output):
                print("Errore: la remediation non scrive mai nella cartella del triage (quella con triage.json).", file=sys.stderr)
                return 1
            files = hash_tree(args.sorgenti)
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with io.open(args.output, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps({"files": files}, indent=1, sort_keys=True) + "\n")
            print("Snapshot: {0} file registrati.".format(len(files)))
            return 0

        with io.open(args.snapshot, encoding="utf-8") as fh:
            before = json.load(fh)["files"]
        after = hash_tree(args.sorgenti)
    except (OSError, ValueError, KeyError) as e:
        print("Errore: {0}".format(e), file=sys.stderr)
        return 1
    changed = [r for r in before if r in after and before[r] != after[r]]
    removed = [r for r in before if r not in after]
    added = [r for r in after if r not in before]
    print("File confrontati: {0}".format(len(before)))
    if not (changed or removed or added):
        print("OK: i sorgenti sono identici allo snapshot.")
        return 0
    print("ATTENZIONE: i sorgenti sono cambiati. Non considerare sicura questa sessione di remediation.")
    show("modificato", changed)
    show("rimosso", removed)
    show("aggiunto", added)
    return 1


if __name__ == "__main__":
    sys.exit(main())
