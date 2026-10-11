# SAST Claude Toolkit

Strumento per rivalutare con Claude Code i risultati di una scansione SAST **HCL AppScan** (o di un altro strumento che esporta **SARIF**) e per preparare le correzioni, con un'approvazione esplicita dello sviluppatore a ogni passaggio importante.

- Parte dai finding dello scanner e li **rivaluta sul codice sorgente**: la gravità dello scanner non è il verdetto.
- Accetta il report AppScan in **CSV** (con XML facoltativo) oppure un file **SARIF 2.1.0**: l'output è lo stesso.
- Aggiunge una **security review di tutti i sorgenti** con il metodo del comando `/security-review` di Claude Code: le vulnerabilità confermate diventano osservazioni `OBS`, nello stesso report.
- Produce un triage controllato: verdetto, prove, report leggibile, file CSV e un file JSON per la fase successiva.
- Prepara **proposte** di correzione (diff, sostituzioni proposte, verifiche). Non applica mai nulla da solo.
- Ogni sviluppatore, su ogni software, ottiene piani e report con la stessa struttura.

## Componenti

- **`sast-triage`**: per ogni finding stabilisce se il problema è reale e quanto è grave (`High`, `Medium`, `Low`, `False Positive`, `Unknown - Needs Review`), poi esegue le cinque verifiche standard e la security review di tutti i sorgenti. Parte da un piano che devi approvare.
- **`sast-remediation`**: legge il risultato del triage e, un finding alla volta, prepara un piano di fix, la modifica proposta e le istruzioni di verifica. Ha due approvazioni: piano generale e piano del singolo fix.

## Requisiti

- Claude Code.
- Python 3, disponibile come `python` o `python3`. Nessun pacchetto Python esterno.
- Il codice sorgente analizzato.
- Il report dello scanner (obbligatorio): AppScan in **CSV**, con il report XML facoltativo, **oppure** un file **SARIF 2.1.0** di AppScan o di un altro strumento SAST. Il report SCA è facoltativo.

## Installazione rapida

Dalla cartella del progetto (consigliato):

```
python <percorso-toolkit>/install.py
```

oppure indicando la cartella del progetto:

```
python install.py "<cartella-progetto>"
```

In alternativa si possono copiare a mano `skills/sast-triage` e `skills/sast-remediation` in `<progetto>/.claude/skills/`.

Opzioni: `--controlla` (mostra cosa farebbe, senza scrivere), `--personale` (installa per tutti i tuoi progetti), `--sovrascrivi` (sostituisce una versione diversa già installata).

Dopo l'installazione apri una **sessione nuova** di Claude Code nel progetto, scrivi `/` e controlla che `sast-triage` e `sast-remediation` siano elencate.

## Flusso rapido

```
/sast-triage
  → indica o fai cercare i file (sorgenti, report CSV o SARIF)
  → leggi PIANO_TRIAGE.md e approva
  → triage dei finding, verifiche standard, security review
  → leggi TRIAGE_REPORT.md, TRIAGE_REPORT.csv e triage.json

/sast-remediation
  → scegli triage.json e la cartella dei sorgenti
  → leggi il piano di remediation e approva
  → scegli un finding
  → leggi il piano di fix e approva
  → rivedi diff, sostituzioni proposte e verifica
```

**Il toolkit non applica mai le correzioni ai sorgenti.** Si ferma alla proposta: la rivedi e la applichi tu.

## Cosa il toolkit non fa

- Non sostituisce lo scanner: non si fida ciecamente della sua gravità, e la security review aggiunge solo osservazioni confermate da prove.
- Non modifica i sorgenti e non applica fix automaticamente.
- Non esegue triage né fix senza la tua approvazione esplicita.
- Non scrive valori segreti in nessun file prodotto.

## Documentazione

- [`docs/GUIDA_SVILUPPATORE.md`](docs/GUIDA_SVILUPPATORE.md): guida tecnica completa per sviluppatori: installazione, triage, report SARIF, metodo di valutazione, security review, remediation, file prodotti, come applicare un fix, segreti e buone pratiche.
- Test di non regressione: `python -m unittest discover -s tests` dalla cartella del toolkit (solo libreria standard).
