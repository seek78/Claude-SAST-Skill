# -*- coding: utf-8 -*-
"""Tiene lo stato della remediation e genera REMEDIATION.md con colonne fisse. Mai un finding non candidato.

Uso:
  python remediation_status.py init --triage TRIAGE.json --input remediation-input.json --dir CARTELLA_REMEDIATION
  python remediation_status.py set  --dir CARTELLA_REMEDIATION --id AS-001 --status "Piano fix pronto" [--open TESTO] [--note TESTO]
                                    [--confirmed-by-developer]
  python remediation_status.py next --dir CARTELLA_REMEDIATION     (raggruppamenti per scegliere il finding)
  python remediation_status.py show --dir CARTELLA_REMEDIATION

Lo stato sta in <dir>/_work/status.json; REMEDIATION.md si rigenera da lì, sempre con le stesse colonne:
ID · Verdetto · Stato · Aperto · Note. «Aperto» riporta decisioni o dipendenze non risolte («—» se non ce ne sono).

Stati, in quest'ordine, senza salti e senza tornare indietro:
  Da fare · Piano fix pronto · Piano fix approvato · Fix proposto · Applicato dallo sviluppatore · Verificato
Gli ultimi due richiedono --confirmed-by-developer, cioè una conferma esplicita dello sviluppatore. Generare un
.diff o un .proposto NON cambia lo stato: lo stato lo cambia solo questo comando.
«Piano fix pronto» e «Piano fix approvato» richiedono fixes/<ID>/PIANO_FIX.md; «Fix proposto» richiede anche
fixes/<ID>/VERIFICA.md e fixes/<ID>/PROPOSTE.json.

Candidati: solo finding High/Medium/Low e osservazioni confermate. I falsi positivi e i «Da verificare» non entrano mai.

Esito: 0 ok | 1 richiesta non valida (nulla modificato) | 2 uso errato o file illeggibile
"""

import argparse
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_secrets import find_secrets  # noqa: E402
from triage_contract import CONFIRMED, filled, id_number, validate  # noqa: E402

STATUSES = ("Da fare", "Piano fix pronto", "Piano fix approvato", "Fix proposto", "Applicato dallo sviluppatore", "Verificato")
CONFIRM_REQUIRED = ("Applicato dallo sviluppatore", "Verificato")
NEEDS_FILES = {"Piano fix pronto": ("PIANO_FIX.md",), "Piano fix approvato": ("PIANO_FIX.md",),
               "Fix proposto": ("PIANO_FIX.md", "VERIFICA.md", "PROPOSTE.json")}
MAX_TEXT = 200


def one_line(text):
    return " ".join(str(text).split())


def cell(text):
    return one_line(text).replace("|", "\\|")


def status_path(folder):
    return os.path.join(folder, "_work", "status.json")


def load_json(path, label):
    try:
        with io.open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except OSError:
        print("Errore: {0} non trovato o non leggibile: {1}".format(label, path), file=sys.stderr)
    except ValueError as e:
        print("Errore: {0} non è un JSON valido ({1}).".format(label, e), file=sys.stderr)
    return None


def write_text(path, text):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def render(items):
    L = ["# Stato della remediation", "", "| ID | Verdetto | Stato | Aperto | Note |", "|---|---|---|---|---|"]
    for it in items:
        L.append("| `{0}` | {1} | {2} | {3} | {4} |".format(it["id"], it["verdict"], it["status"],
                                                          cell(it["open"]) or "—", cell(it["note"])))
    L += ["", "Stati: " + " · ".join(STATUSES), "",
          "«Applicato dallo sviluppatore» e «Verificato» si impostano solo su conferma esplicita dello sviluppatore. "
          "Un `.diff` o un `.proposto` non significa che la modifica sia stata applicata."]
    return "\n".join(L) + "\n"


def save(folder, items):
    write_text(status_path(folder), json.dumps({"items": items}, ensure_ascii=False, indent=2) + "\n")
    write_text(os.path.join(folder, "REMEDIATION.md"), render(items))


def load_items(folder):
    data = load_json(status_path(folder), "stato della remediation (esegui prima init)")
    return None if data is None else data["items"]


def cmd_init(args):
    triage, plan = load_json(args.triage, "triage.json"), load_json(args.input, "remediation-input.json")
    if triage is None or plan is None:
        return 2
    problems = validate(triage)
    if problems:
        print("triage.json NON valido ({0} problemi). Nessun file scritto.".format(len(problems)), file=sys.stderr)
        return 1
    cand = {f["id"]: f for f in triage["findings"] if f["verdict"] in CONFIRMED}
    cand.update({o["id"]: o for o in triage["additional_observations"]})
    items, seen = [], set()
    for n, step in enumerate(plan.get("order", []), 1):
        for fid in sorted(step.get("finding_ids", []), key=id_number):
            if fid not in cand or fid in seen:
                print("Errore: {0} non è un candidato valido o compare due volte nell'ordine.".format(fid), file=sys.stderr)
                return 1
            seen.add(fid)
            dep = sorted(step.get("depends_on", []), key=id_number)
            items.append({"id": fid, "verdict": cand[fid]["verdict"], "title": cand[fid]["title"], "step": n,
                          "status": STATUSES[0], "open": "Dopo {0}".format(", ".join(dep)) if dep else "", "note": ""})
    for o in sorted(plan.get("observations", []), key=lambda o: id_number(o["id"])):
        if o["id"] not in cand or o["id"] in seen:
            print("Errore: {0} non è un'osservazione valida o compare due volte.".format(o["id"]), file=sys.stderr)
            return 1
        seen.add(o["id"])
        items.append({"id": o["id"], "verdict": cand[o["id"]]["verdict"], "title": cand[o["id"]]["title"], "step": 0,
                      "status": STATUSES[0], "open": "", "note": ""})
    if set(cand) - seen:
        print("Errore: candidati non presenti nel piano: {0}.".format(", ".join(sorted(set(cand) - seen, key=id_number))),
              file=sys.stderr)
        return 1
    save(args.dir, items)
    print("Stato creato: {0} voci in {1}.".format(len(items), os.path.join(args.dir, "REMEDIATION.md").replace("\\", "/")))
    return 0


def cmd_set(args):
    items = load_items(args.dir)
    if items is None:
        return 2
    item = next((i for i in items if i["id"] == args.id), None)
    if item is None:
        print("Errore: {0} non è un candidato della remediation.".format(args.id), file=sys.stderr)
        return 1
    if args.status not in STATUSES:
        print("Errore: stato non valido {0!r}. Stati ammessi: {1}.".format(args.status, " · ".join(STATUSES)), file=sys.stderr)
        return 1
    cur, new = STATUSES.index(item["status"]), STATUSES.index(args.status)
    if new < cur:
        print("Errore: lo stato non torna indietro ({0} → {1}).".format(item["status"], args.status), file=sys.stderr)
        return 1
    if new > cur + 1:
        print("Errore: gli stati non si saltano: dopo «{0}» viene «{1}».".format(item["status"], STATUSES[cur + 1]), file=sys.stderr)
        return 1
    if args.status in CONFIRM_REQUIRED and not args.confirmed_by_developer:
        print("Errore: «{0}» richiede una conferma esplicita dello sviluppatore (--confirmed-by-developer). "
              "Generare un diff o una sostituzione proposta non vale come conferma.".format(args.status), file=sys.stderr)
        return 1
    for name in NEEDS_FILES.get(args.status, ()):
        if not os.path.isfile(os.path.join(args.dir, "fixes", args.id, name)):
            print("Errore: per «{0}» manca fixes/{1}/{2}.".format(args.status, args.id, name), file=sys.stderr)
            return 1
    for label, value in (("open", args.open), ("note", args.note)):
        if value is not None:
            if len(one_line(value)) > MAX_TEXT:
                print("Errore: {0} supera {1} caratteri.".format(label, MAX_TEXT), file=sys.stderr)
                return 1
            if find_secrets(one_line(value)):
                print("Errore: possibile segreto in chiaro in {0}: il valore non viene mostrato.".format(label), file=sys.stderr)
                return 1
    item["status"] = args.status
    if args.open is not None:
        item["open"] = one_line(args.open)
    if args.note is not None:
        item["note"] = one_line(args.note)
    save(args.dir, items)
    print("{0}: {1}.".format(args.id, args.status))
    return 0


def cmd_next(args):
    items = load_items(args.dir)
    if items is None:
        return 2
    todo = [i for i in items if i["status"] == STATUSES[0]]
    if not todo:
        print("Nessun candidato con stato «Da fare».")
        return 0
    print("Candidati ancora da fare: {0}".format(len(todo)))
    print("Per gravità:")
    for v in CONFIRMED:
        ids = [i["id"] for i in todo if i["verdict"] == v]
        if ids:
            print("  {0} ({1}): {2}".format(v, len(ids), ", ".join(ids)))
    print("Per passo del piano:")
    for n in sorted({i["step"] for i in todo if i["step"]}):
        ids = [i["id"] for i in todo if i["step"] == n]
        print("  passo {0} ({1}): {2}".format(n, len(ids), ", ".join(ids)))
    obs = [i["id"] for i in todo if not i["step"]]
    if obs:
        print("  osservazioni aggiuntive ({0}): {1}".format(len(obs), ", ".join(obs)))
    print("Singoli:")
    for i in todo:
        print("  {0} [{1}] {2}{3}".format(i["id"], i["verdict"], one_line(i["title"]),
                                           " (aperto: {0})".format(i["open"]) if i["open"] else ""))
    return 0


def cmd_show(args):
    items = load_items(args.dir)
    if items is None:
        return 2
    sys.stdout.write(render(items))
    return 0


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("init", help="crea lo stato dai candidati del triage e dal piano approvato")
    a.add_argument("--triage", required=True)
    a.add_argument("--input", required=True, help="remediation-input.json del piano approvato")
    a.add_argument("--dir", required=True, help="cartella sast-output/remediation")
    b = sub.add_parser("set", help="cambia lo stato di un candidato")
    b.add_argument("--dir", required=True)
    b.add_argument("--id", required=True)
    b.add_argument("--status", required=True)
    b.add_argument("--open", help="decisioni o dipendenze non risolte (testo vuoto per azzerare)")
    b.add_argument("--note", help="nota breve")
    b.add_argument("--confirmed-by-developer", action="store_true",
                   help="obbligatorio per «Applicato dallo sviluppatore» e «Verificato»")
    c = sub.add_parser("next", help="raggruppamenti dei candidati ancora da fare")
    c.add_argument("--dir", required=True)
    d = sub.add_parser("show", help="stampa REMEDIATION.md")
    d.add_argument("--dir", required=True)
    args = ap.parse_args(argv)
    return {"init": cmd_init, "set": cmd_set, "next": cmd_next, "show": cmd_show}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
