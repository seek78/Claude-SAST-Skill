# -*- coding: utf-8 -*-
"""Installa le skill sast-triage e sast-remediation in un progetto (o per l'utente). Si esegue da terminale (Python 3).

Dalla cartella del progetto (installa in <cartella corrente>/.claude/skills):
  python <percorso-del-toolkit>/install.py

Dalla cartella del toolkit:
  python install.py                    chiede «Cartella del progetto >»: incolla o trascina il percorso (anche tra
                                       virgolette o con spazi), oppure scrivi «personale»; Invio a vuoto annulla

Con un percorso esplicito:
  python install.py "<cartella-del-progetto>"

Opzioni:
  --personale      installa per tutti i progetti: ~/.claude/skills
  --controlla      mostra cosa farebbe, senza scrivere nulla
  --sovrascrivi    sostituisce una skill già presente ma diversa

Regole: non sovrascrive mai nulla senza --sovrascrivi; le altre skill e le impostazioni di Claude non si toccano;
alla fine confronta i file copiati con l'originale. Se qualcosa va storto non lascia installazioni a metà.
Solo libreria standard, nessuna rete. In alternativa si possono copiare a mano le due cartelle di skills/ in .claude/skills/.

Esito: 0 installato o già a posto | 1 errore | 2 uso errato | 3 una skill diversa è stata lasciata invariata
"""

import argparse
import hashlib
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SKILLS = ("sast-triage", "sast-remediation")
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc")


class InstallError(Exception):
    pass


def tree(path):
    """{percorso relativo: hash}; ignora __pycache__ e .pyc (Python li crea eseguendo gli script)."""
    out = {}
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            if f.endswith(".pyc"):
                continue
            p = os.path.join(root, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, path).replace("\\", "/")] = hashlib.sha256(fh.read()).hexdigest()
    return out


def move(src, dst, tries=15):
    """Rinomina una cartella riprovando: su Windows antivirus o indicizzazione possono tenere aperti per un
    istante i file appena copiati e il rinomino dà «Accesso negato»."""
    for i in range(tries):
        try:
            os.rename(src, dst)
            return
        except PermissionError:
            if i == tries - 1:
                raise
            time.sleep(0.3)


def remove(path, tries=10):
    """Elimina una cartella riprovando; restituisce False se non ci riesce."""
    for _ in range(tries):
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.lexists(path):
            return True
        time.sleep(0.3)
    return False


def inside(path, root):
    p, r = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(root))
    return p == r or p.startswith(r + os.sep)


def describe_difference(src, dest):
    a, b = tree(src), tree(dest)
    diff = sum(1 for k in a if k in b and a[k] != b[k])
    missing = sum(1 for k in a if k not in b)
    extra = sum(1 for k in b if k not in a)
    return "{0} file diversi, {1} mancanti, {2} in più".format(diff, missing, extra)


def plan_for(base, overwrite):
    """[(nome, origine, destinazione, stato)] con stato: da installare | identica | diversa | da sostituire."""
    plan = []
    for name in SKILLS:
        src = os.path.join(HERE, "skills", name)
        if not os.path.isfile(os.path.join(src, "SKILL.md")):
            raise InstallError("Pacchetto incompleto: manca skills/{0}/SKILL.md accanto a install.py.".format(name))
        dest = os.path.join(base, name)
        if not os.path.lexists(dest):
            state = "da installare"
        elif not os.path.isdir(dest):
            raise InstallError("In {0} esiste un file chiamato «{1}»: non è una cartella. "
                               "Rimuovilo o rinominalo e riprova.".format(base, name))
        elif tree(src) == tree(dest):
            state = "identica"
        else:
            state = "da sostituire" if overwrite else "diversa"
        plan.append((name, src, dest, state))
    return plan


def make_dirs(base):
    """Crea le cartelle mancanti fino a base; restituisce quelle create (per annullare in caso di errore)."""
    created, path = [], base
    while not os.path.isdir(path):
        created.append(path)
        path = os.path.dirname(path)
        if os.path.lexists(path) and not os.path.isdir(path):
            raise InstallError("«{0}» esiste ma non è una cartella: non posso installare in {1}.".format(path, base))
    for p in reversed(created):
        os.mkdir(p)
    return list(reversed(created))


def apply(plan, base):
    """Prepara tutte le copie in cartelle temporanee, le verifica, poi le sposta al loro posto."""
    todo = [p for p in plan if p[3] in ("da installare", "da sostituire")]
    tmp, old, placed = {}, {}, []
    try:
        for name, src, dest, state in todo:
            t = os.path.join(base, ".install-nuova-" + name)
            if os.path.lexists(t):
                shutil.rmtree(t)
            shutil.copytree(src, t, ignore=IGNORE)
            tmp[name] = t
            if tree(src) != tree(t):
                raise InstallError("Verifica fallita: la copia di {0} non è identica all'originale.".format(name))
        for name, src, dest, state in todo:
            if os.path.lexists(dest):
                old[name] = os.path.join(base, ".install-vecchia-" + name)
                if os.path.lexists(old[name]):
                    shutil.rmtree(old[name])
                move(dest, old[name])
            move(tmp[name], dest)
            placed.append(name)
    except BaseException:
        for name in placed:
            remove(os.path.join(base, name))
        for name, o in old.items():
            if os.path.lexists(o) and not os.path.lexists(os.path.join(base, name)):
                move(o, os.path.join(base, name))
        raise
    finally:
        for t in tmp.values():
            if os.path.lexists(t):
                remove(t)
    for o in old.values():
        if not remove(o):
            print("Avviso: non riesco a eliminare la cartella temporanea {0}: cancellala a mano.".format(o))


# ---------------------------------------------------------------- modo interattivo da terminale

def clean_path(text):
    """Ripulisce il percorso incollato o trascinato nel terminale: virgolette, spazi finali, «& '...'» di PowerShell."""
    t = text.strip()
    if t.startswith("& "):
        t = t[2:].strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
        t = t[1:-1]
    return os.path.expandvars(os.path.expanduser(t.strip()))


def ask_destination():
    """Restituisce 'personale', il percorso di un progetto, oppure None se l'utente annulla."""
    print("Installazione delle skill SAST per Claude Code")
    print()
    print("Trascina qui dentro la cartella del tuo progetto (oppure scrivi il percorso) e premi Invio.")
    print("Per installare in tutti i progetti scrivi: personale")
    print("Per annullare premi solo Invio.")
    for _ in range(4):
        print()
        answer = input("Cartella del progetto > ").strip()
        if not answer:
            return None
        if answer.lower() == "personale":
            return "personale"
        path = clean_path(answer)
        if not os.path.isdir(path):
            print("Non trovo questa cartella: {0}\nRiprova.".format(path))
        elif inside(path, HERE):
            print("Questa è la cartella del toolkit, non il tuo progetto. Indica la cartella del TUO progetto.")
        else:
            return os.path.abspath(path)
    print("Troppi tentativi senza una cartella valida.")
    return None


def stdin_is_console():
    """True solo se l'input è un vero terminale con cui l'utente può interagire.
    Su Windows il dispositivo NUL (stdin chiuso) risulta «tty» a isatty(): lo si esclude con GetConsoleMode."""
    if sys.stdin is None or not sys.stdin.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            kernel = ctypes.windll.kernel32
            mode = ctypes.c_uint()
            return bool(kernel.GetConsoleMode(kernel.GetStdHandle(-10), ctypes.byref(mode)))
        except Exception:
            return True
    return True


# ---------------------------------------------------------------- installazione

def execute(args):
    created = []
    try:
        if args.personale:
            project = None
            base = os.path.join(os.path.expanduser("~"), ".claude", "skills")
        else:
            project = os.path.abspath(args.cartella or os.getcwd())
            if not os.path.isdir(project):
                raise InstallError("La cartella del progetto non esiste: {0}".format(project))
            if inside(project, HERE):
                raise InstallError("Stai installando dentro la cartella del toolkit. Esegui lo script dalla cartella "
                                   "del TUO progetto, oppure indica la cartella del progetto: python install.py CARTELLA")
            base = os.path.join(project, ".claude", "skills")
        claude_dir = os.path.dirname(base)
        for p in (claude_dir, base):
            if os.path.lexists(p) and not os.path.isdir(p):
                raise InstallError("«{0}» esiste ma è un file, non una cartella: non posso installare in {1}.".format(p, base))

        print("Destinazione: {0}".format(base))
        plan = plan_for(base, args.sovrascrivi) if os.path.isdir(base) else \
            [(n, os.path.join(HERE, "skills", n), os.path.join(base, n), "da installare") for n in SKILLS]
        for n, s, _, _ in plan:
            if not os.path.isfile(os.path.join(s, "SKILL.md")):
                raise InstallError("Pacchetto incompleto: manca skills/{0}/SKILL.md accanto a install.py.".format(n))

        labels = {"da installare": "da installare", "identica": "già installata (identica)",
                  "da sostituire": "diversa: verrà sostituita", "diversa": "DIVERSA dalla versione del toolkit"}
        for name, src, dest, state in plan:
            extra = " ({0})".format(describe_difference(src, dest)) if state in ("diversa", "da sostituire") else ""
            print("- {0}: {1}{2}".format(name, labels[state], extra))

        if args.controlla:
            print("\nModalità controllo: non è stato scritto nulla.")
            return 3 if any(p[3] == "diversa" for p in plan) else 0

        if any(p[3] in ("da installare", "da sostituire") for p in plan):
            created = make_dirs(base)
            apply(plan, base)
            for name, _, _, state in plan:
                if state in ("da installare", "da sostituire"):
                    print("  {0}: installata".format(name))
    except (InstallError, OSError) as e:
        for p in reversed(created):
            try:
                os.rmdir(p)
            except OSError:
                pass
        print("\nErrore: {0}\nNon è stato lasciato nulla a metà.".format(e), file=sys.stderr)
        return 1

    different = [p for p in plan if p[3] == "diversa"]
    for name, src, dest, _ in different:
        print("\n{0} è già presente ma diversa: la lascio invariata. Per aggiornarla: python install.py --sovrascrivi".format(name))
    installed = [p for p in plan if p[3] in ("da installare", "da sostituire")]
    if installed:
        print("\nSkill installate in {0}.".format(base))
    elif not different:
        print("\nLe skill sono già installate e identiche in {0}: nulla da fare.".format(base))
    if installed or not different:
        if args.personale:
            print("Sono disponibili in tutti i progetti. Apri Claude Code con una sessione nuova e scrivi /sast-triage.")
        else:
            print("Apri Claude Code in questa cartella con una sessione nuova e scrivi /sast-triage.")
    return 3 if different else 0


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cartella", nargs="?", help="cartella del progetto (default: la cartella corrente)")
    ap.add_argument("--personale", action="store_true", help="installa per tutti i progetti (~/.claude/skills)")
    ap.add_argument("--controlla", action="store_true", help="mostra cosa farebbe, senza scrivere nulla")
    ap.add_argument("--sovrascrivi", action="store_true", help="sostituisce una skill già presente ma diversa")
    args = ap.parse_args(argv)
    if args.personale and args.cartella:
        ap.error("con --personale non si indica una cartella di progetto")

    # Modo interattivo: nessun argomento, terminale vero e cartella corrente = quella del toolkit.
    interactive = (not args.personale and not args.cartella and inside(os.getcwd(), HERE) and stdin_is_console())
    if interactive:
        try:
            choice = ask_destination()
        except EOFError:
            choice = None
        if choice is None:
            print("\nAnnullato: non è stato scritto nulla.")
            return 0
        if choice == "personale":
            args.personale = True
        else:
            args.cartella = choice
        print()
    return execute(args)


if __name__ == "__main__":
    sys.exit(main())
