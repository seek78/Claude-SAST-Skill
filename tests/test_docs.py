# -*- coding: utf-8 -*-
"""La documentazione esiste in italiano e in inglese: le due versioni restano allineate (solo libreria standard).

Esecuzione, dalla cartella del toolkit:
  python -m unittest discover -s tests

Per ogni coppia (italiano, inglese) controlla che:
- ciascun documento rimandi all'altro (riga della lingua in alto);
- i titoli abbiano gli stessi livelli e la stessa numerazione;
- i blocchi di codice abbiano le stesse righe: uguali, salvo i segnaposto tra < > e le righe di flusso con →,
  che si traducono;
- il codice in linea sia lo stesso (comandi, percorsi, opzioni, valori letterali), salvo i segnaposto;
- i link puntino agli stessi documenti, ciascuno nella sua lingua.
Il testo si traduce; ciò che lo strumento mostra o accetta resta identico. La regola è anche in CLAUDE.md.
"""

import io
import os
import re
import unittest
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAIRS = (("README.md", "README.en.md"), ("docs/GUIDA_SVILUPPATORE.md", "docs/DEVELOPER_GUIDE.md"))
NAMES = ((re.compile(r"(?<![\w.])README\.md\b"), "README.en.md"),          # documento italiano -> inglese
         (re.compile(r"\bGUIDA_SVILUPPATORE\.md\b"), "DEVELOPER_GUIDE.md"))
_PLACEHOLDER = re.compile(r"<[^<>\s][^<>]*>")
_HEADING = re.compile(r"^(#{1,6})\s+(?:(\d+(?:\.\d+)*)\.\s)?")
_INLINE = re.compile(r"`([^`]+)`")
_LINK = re.compile(r"\]\(([^)\s]+)\)")


def read(rel):
    with io.open(os.path.join(ROOT, *rel.split("/")), encoding="utf-8") as fh:
        return fh.read()


def shape(text):
    """Titoli (livello, numero), blocchi di codice, codice in linea e link di un documento Markdown."""
    headings, blocks, inline, links = [], [], [], []
    block = None
    for line in text.splitlines():
        if line.startswith("```"):
            if block is None:
                block = []
            else:
                blocks.append(block)
                block = None
            continue
        if block is not None:
            block.append(line)
            continue
        m = _HEADING.match(line)
        if m:
            headings.append((len(m.group(1)), m.group(2)))
        inline += _INLINE.findall(line)
        links += _LINK.findall(line)
    return headings, blocks, inline, links


def neutral(text, italian):
    """Forma confrontabile: segnaposto anonimi e, nella versione italiana, i nomi dei documenti in inglese."""
    text = _PLACEHOLDER.sub("<>", text)
    if italian:
        for name, english in NAMES:
            text = name.sub(english, text)
    return text


class TestDocumentazioneBilingue(unittest.TestCase):
    def check_pair(self, it_rel, en_rel):
        it_shape, en_shape = shape(read(it_rel)), shape(read(en_rel))
        where = "{0} / {1}".format(it_rel, en_rel)

        self.assertEqual(it_shape[0], en_shape[0], "{0}: titoli con livelli o numerazione diversi".format(where))

        it_blocks, en_blocks = it_shape[1], en_shape[1]
        self.assertEqual(len(it_blocks), len(en_blocks), "{0}: numero di blocchi di codice diverso".format(where))
        for n, (a, b) in enumerate(zip(it_blocks, en_blocks), 1):
            self.assertEqual([None if "→" in x else neutral(x, True) for x in a],
                             [None if "→" in x else neutral(x, False) for x in b],
                             "{0}: blocco di codice #{1} diverso".format(where, n))

        it_code = Counter(neutral(x, True) for x in it_shape[2])
        en_code = Counter(neutral(x, False) for x in en_shape[2])
        self.assertEqual(it_code, en_code, "{0}: codice in linea diverso. Solo in italiano: {1}. Solo in inglese: {2}".format(
            where, sorted((it_code - en_code).elements()), sorted((en_code - it_code).elements())))

        to_en = os.path.basename(en_rel)          # riga della lingua: i due documenti stanno nella stessa cartella
        to_it = os.path.basename(it_rel)
        self.assertIn(to_en, it_shape[3], "{0}: manca il link alla versione inglese".format(it_rel))
        self.assertIn(to_it, en_shape[3], "{0}: manca il link alla versione italiana".format(en_rel))
        it_links = Counter(neutral(x, True) for x in it_shape[3] if x != to_en)
        en_links = Counter(neutral(x, False) for x in en_shape[3] if x != to_it)
        self.assertEqual(it_links, en_links, "{0}: link diversi".format(where))

    def test_versioni_allineate(self):
        for it_rel, en_rel in PAIRS:
            with self.subTest(documento=it_rel):
                self.check_pair(it_rel, en_rel)

    def test_regola_in_claude_md(self):
        rules = read("CLAUDE.md")
        for it_rel, en_rel in PAIRS:
            self.assertIn(it_rel, rules)
            self.assertIn(en_rel, rules)


if __name__ == "__main__":
    unittest.main()
