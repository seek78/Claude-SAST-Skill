# SAST Claude Toolkit: note per chi sviluppa il toolkit

## Documentazione in due lingue

La documentazione per le persone esiste in italiano e in inglese. Ogni modifica si fa in entrambe le versioni, nello stesso commit:

| Italiano | English |
|---|---|
| `README.md` | `README.en.md` |
| `docs/GUIDA_SVILUPPATORE.md` | `docs/DEVELOPER_GUIDE.md` |

- Traduci il testo mantenendo lo stesso significato, gli stessi titoli (con la stessa numerazione) e la stessa struttura.
- Lascia identico tutto ciò che lo strumento mostra o accetta: comandi, percorsi, nomi di file, opzioni e valori letterali (per esempio `--sovrascrivi`, `Rete interna`, `Piano fix pronto`). Nella versione inglese la traduzione va tra parentesi, fuori dal codice. Nei blocchi di codice si traducono solo i segnaposto tra `< >` e le righe di flusso con `→`.
- `tests/test_docs.py` fallisce se le due versioni divergono: titoli, blocchi di codice, codice in linea o link.

Restano solo in italiano le skill (`SKILL.md`, `references/`, `templates/`), i messaggi degli script, i piani e i report generati: sono l'output del toolkit, che non cambia.

## Test

```
python -m unittest discover -s tests
```
