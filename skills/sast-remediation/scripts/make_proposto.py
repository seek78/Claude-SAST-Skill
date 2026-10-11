# -*- coding: utf-8 -*-
"""Crea i file <nome-originale>.proposto per i file che non si possono emettere come diff perché conterrebbero un segreto.

Uso:
  python make_proposto.py --sources CARTELLA_SORGENTI --proposed CARTELLA_PROPOSTE --fix-dir CARTELLA_DEL_FIX

  --fix-dir   cartella del fix (sast-output/remediation/fixes/<ID>): contiene PROPOSTE.json, scritto da make_diff.py.
              Qui nascono i file .proposto. Mai nei sorgenti e mai nella cartella del triage.

Per ogni file marcato "segreto_nel_diff" in PROPOSTE.json:
  - la versione proposta viene controllata riga per riga; se contiene ancora un segreto probabile NON viene scritta
    (il file passa a "istruzioni": solo istruzioni a parole, senza il valore);
  - altrimenti viene scritta, byte per byte, come <nome-originale>.proposto nella cartella del fix. Se due file hanno lo
    stesso nome, il file .proposto riproduce il percorso relativo (es. Src/A/Web.config.proposto);
  - in PROPOSTE.json si registrano percorso relativo dell'originale, SHA-256 dell'originale e la dicitura
    «Sostituzione proposta, non applicata automaticamente». Il valore del segreto non compare mai in nomi, metadati
    o messaggi.
Prima di sostituire un file con la proposta, lo sviluppatore controlla che l'hash dell'originale sia ancora quello registrato.

Esito: 0 tutte le proposte scritte | 1 errore | 2 uso errato | 3 almeno una proposta bloccata da un segreto (solo istruzioni)
"""

import argparse
import io
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_secrets import find_secrets  # noqa: E402
from make_diff import inside, inside_triage_folder, read_bytes, sha256_of  # noqa: E402

LABEL = "Sostituzione proposta, non applicata automaticamente"
PENDING = "segreto_nel_diff"


def decode(data):
    for enc in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def proposal_names(paths):
    """<nome>.proposto; se due file hanno lo stesso nome, il percorso relativo completo."""
    counts = Counter(p.rsplit("/", 1)[-1] for p in paths)
    return {p: (p if counts[p.rsplit("/", 1)[-1]] > 1 else p.rsplit("/", 1)[-1]) + ".proposto" for p in paths}


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sources", required=True, help="cartella dei sorgenti (sola lettura)")
    ap.add_argument("--proposed", required=True, help="cartella con i soli file proposti")
    ap.add_argument("--fix-dir", required=True, help="cartella del fix, con PROPOSTE.json")
    args = ap.parse_args(argv)

    manifest_path = os.path.join(args.fix_dir, "PROPOSTE.json")
    for label, p in (("sorgenti", args.sources), ("proposte", args.proposed), ("del fix", args.fix_dir)):
        if not os.path.isdir(p):
            print("Errore: cartella {0} non trovata: {1}".format(label, p), file=sys.stderr)
            return 1
    if inside(args.fix_dir, args.sources) or inside(args.proposed, args.sources):
        print("Errore: le proposte devono stare FUORI dalla cartella dei sorgenti.", file=sys.stderr)
        return 1
    if inside_triage_folder(os.path.join(args.fix_dir, "x")):
        print("Errore: la remediation non scrive mai nella cartella del triage (quella con triage.json).", file=sys.stderr)
        return 1
    try:
        with io.open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        entries = manifest["files"]
    except (OSError, ValueError, KeyError):
        print("Errore: PROPOSTE.json non trovato o non valido: esegui prima make_diff.py con --manifest.", file=sys.stderr)
        return 1

    pending = [e for e in entries if e["mode"] == PENDING]
    if not pending:
        print("Nessun file da trattare: nessuno è marcato come «{0}».".format(PENDING))
        return 0
    names = proposal_names([e["path"] for e in pending])
    blocked = 0
    for e in sorted(pending, key=lambda e: e["path"]):
        rel = e["path"]
        src_path = os.path.join(args.proposed, *rel.split("/"))
        if not os.path.isfile(src_path):
            print("Errore: la versione proposta non esiste: {0}".format(rel), file=sys.stderr)
            return 1
        data = read_bytes(src_path)
        kinds = sorted({kind for _, kind in find_secrets(decode(data))})
        e["original_sha256"] = sha256_of(os.path.join(args.sources, *rel.split("/")))
        if kinds:
            e["mode"], e["proposal"] = "istruzioni", None
            blocked += 1
            print("  SOLO ISTRUZIONI (la proposta contiene ancora un segreto: {0}; valore non mostrato): {1}".format(
                ", ".join(kinds), rel))
            continue
        target = os.path.join(args.fix_dir, *names[rel].split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(data)
        e["mode"], e["proposal"] = "proposto", names[rel]
        print("  proposta scritta: {0} -> {1}".format(rel, names[rel]))
    manifest["label"] = LABEL
    with io.open(manifest_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps({"label": LABEL, "files": sorted(entries, key=lambda e: e["path"])},
                            ensure_ascii=False, indent=2) + "\n")
    print(LABEL + ".")
    return 3 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
