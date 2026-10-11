# -*- coding: utf-8 -*-
"""Cerca segreti in chiaro evidenti nei file di testo prodotti dal triage.

Controllo prudente, non uno scanner completo: segnala solo schemi ad alta
affidabilità e ignora i segnaposto (<password>, REDACTED, ***, xxxx...).
Non stampa mai il valore sospetto: solo file, riga e tipo.

Uso:  python check_secrets.py PERCORSO [PERCORSO ...]
Esito: 0 nessun segreto probabile | 1 segreto probabile trovato | 2 uso errato

Anche usato dagli altri script (find_secrets, redact).
"""

import argparse
import io
import os
import re
import sys

_NOMI = (r"(?:password|passwd|pwd|passphrase|secret|credential|api[_-]?key|access[_-]?key"
         r"|(?:signing|encryption|private|master|session|auth|jwt|hmac)[_-]?key|token)")

# (tipo, espressione, gruppo con il valore; 0 = tutta la corrispondenza)
PATTERNS = [
    ("chiave privata", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"), 0),
    ("chiave API o token riconoscibile", re.compile(
        r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9-]{10,}"
        r"|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35})\b"), 0),
    ("token JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), 0),
    ("credenziali in un URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@\"']+:([^/\s@\"']{3,})@"), 1),
    ("assegnazione di password o segreto", re.compile(
        r"(?i)" + _NOMI + r"\w*[\"']?\s*[:=]\s*[\"']([^\"'\r\n]{6,})[\"']"), 1),
    ("password in una stringa di connessione", re.compile(
        r"(?i)(?:^|[;\s,])(?:password|pwd)\s*=\s*([^;\s\"'<>,]{6,})"), 1),
]

# Un identificatore che finisce così contiene il NOME di una variabile o di una chiave di configurazione, non un
# valore segreto (es. EncryptionKeyVariableName = "APP_ENCRYPTION_KEY", PASSWORD_ENV = "DB_PASSWORD").
_NAME_SUFFIX = re.compile(r"(?i)(?:names?|variables?|vars?|env|envvars?|configkeys?)$")
_IDENTIFIER_VALUE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:\-]{3,}$")

_EXCLUDED_DIRS = {".git", "__pycache__", "node_modules"}
_MAX_BYTES = 2 * 1024 * 1024


def is_placeholder(value):
    v = value.strip()
    low = v.lower()
    if not v or v[0] in "<{$%[" or "redact" in low or "redatt" in low:
        return True
    if set(v) <= set("*xX.-_#"):
        return True
    return low in {"password", "secret", "token", "changeme", "example", "esempio",
                   "null", "none", "true", "false"} or low.startswith(("your", "il_tuo"))


def _is_secret_value(value):
    # niente spazi (frase) e niente "(" (chiamata di funzione, non un valore letterale)
    return not is_placeholder(value) and not re.search(r"\s|\(", value)


def _names_a_variable(match_text, value):
    """True se l'assegnazione riguarda il nome di una variabile o di una chiave di configurazione
    (identificatore che finisce per Name, Variable, Var, Env... e valore che è solo un identificatore)."""
    ident = re.match(r"\w+", match_text)
    return bool(ident and _NAME_SUFFIX.search(ident.group(0)) and _IDENTIFIER_VALUE.match(value.strip()))


def _is_hit(m, grp):
    return grp == 0 or (_is_secret_value(m.group(grp)) and not _names_a_variable(m.group(0), m.group(grp)))


def find_secrets(text):
    """Restituisce [(numero_riga, tipo)] senza mai includere il valore."""
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        for kind, rx, grp in PATTERNS:
            for m in rx.finditer(line):
                if _is_hit(m, grp):
                    found.append((n, kind))
    return found


def redact(text):
    """Sostituisce con <redatto> i valori che sembrano segreti."""
    def make(grp):
        def sub(m):
            if grp == 0:
                return "<redatto>"
            if not _is_hit(m, grp):
                return m.group(0)
            s, e = m.start(grp) - m.start(0), m.end(grp) - m.start(0)
            return m.group(0)[:s] + "<redatto>" + m.group(0)[e:]
        return sub
    for _, rx, grp in PATTERNS:
        text = rx.sub(make(grp), text)
    return text


def _read_text(path):
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None  # binario: ignorato
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def _files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
                for n in sorted(names):
                    yield os.path.join(root, n)
        else:
            print("Percorso non trovato: {0}".format(p), file=sys.stderr)


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="replace")   # niente crash su console con codifiche limitate
    ap = argparse.ArgumentParser(
        description="Cerca segreti in chiaro evidenti nei file di testo. Non stampa mai i valori.")
    ap.add_argument("percorsi", nargs="+", help="file o cartelle da controllare")
    args = ap.parse_args(argv)

    scanned, hits = 0, 0
    for path in _files(args.percorsi):
        text = _read_text(path)
        if text is None:
            continue
        scanned += 1
        for line, kind in find_secrets(text):
            hits += 1
            print("{0}:{1}: possibile segreto in chiaro ({2}) - valore non mostrato".format(path, line, kind))
    print("File di testo controllati: {0} | segnalazioni: {1}".format(scanned, hits))
    if hits:
        print("Rimuovi o oscura i valori prima di condividere i file: descrivi solo esistenza e posizione.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
