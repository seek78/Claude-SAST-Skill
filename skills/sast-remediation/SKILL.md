---
name: sast-remediation
description: Aiuta lo sviluppatore a preparare in sicurezza le correzioni dei finding confermati da sast-triage (triage.json). Propone un piano di remediation da approvare, poi lavora un finding alla volta - analisi tecnica, piano di fix da approvare, patch in formato diff o sostituzioni proposte e istruzioni di verifica - senza mai modificare i sorgenti. Usala per correggere o sistemare i problemi emersi dal triage SAST.
---

# sast-remediation

Prepara le correzioni dei finding **già confermati** da `/sast-triage`, leggendo `triage.json`. Non rifà il triage e non modifica i sorgenti: **propone** piani, diff, sostituzioni proposte e istruzioni di verifica. Parla sempre in italiano con lo sviluppatore.

I percorsi `scripts/`, `references/` e `templates/` sono relativi alla cartella che contiene questo `SKILL.md`: non chiedere allo sviluppatore dove è installata la skill. Nei comandi usa il percorso completo di quella cartella. Usa `python` (o `python3` se `python` non esiste).

## Dove trovare le cose

| Cosa | File |
|---|---|
| Formato di `triage.json` | `references/output-contract.md` |
| Principi per preparare un fix | `references/fix-guidance.md` |
| Contenuti che scrivi tu (piano generale, piano del fix, verifica) | `templates/remediation-input.json`, `templates/fix-input.json`, `templates/verification-input.json` |
| Script | `scripts/read_triage.py`, `check_source.py`, `make_diff.py`, `make_proposto.py`, `make_remediation_plan.py`, `remediation_status.py`, `check_secrets.py` (`triage_contract.py` è un modulo interno) |

## Regole ferme

- **Sorgenti in sola lettura.** Mai scrivere nella cartella dei sorgenti. Ciò che produci sta in `<rem>` = `sast-output/remediation`, accanto alla cartella `sast-output/triage` che contiene `triage.json`, mai dentro i sorgenti. `read_triage.py` stampa il percorso da usare. Gli artefatti di un fix stanno **solo** in `<rem>/fixes/<ID>/`.
- **Mai scrivere nella cartella del triage** (`sast-output/triage/`): il triage si legge e basta.
- Nei file che produci scrivi i percorsi relativi sempre con `/`.
- **Due approvazioni obbligatorie**: il piano generale e, per ogni finding, il piano di fix. **Nessun diff né file proposto prima della seconda.** Nessun piano di fix prima della prima.
- Un finding alla volta, scelto dallo sviluppatore.
- Non rifare il triage e non cambiare un verdetto. Se il triage sembra sostanzialmente sbagliato: ferma quel finding, riporta l'incoerenza e consiglia `/sast-triage`: non cambiare il verdetto in silenzio.
- **Mai il valore di un segreto** in `.diff`, `.proposto`, Markdown, JSON, nomi di file, metadati, chat o console. Non inventare credenziali sostitutive. `check_secrets.py` è una rete di sicurezza, non una garanzia.
- Generare un `.diff` o un `.proposto` **non significa** che la modifica sia stata applicata.
- I piani e la verifica **non li scrivi tu**: li generano gli script dai tuoi contenuti brevi. Non modificare i file generati a mano: correggi il contenuto e rigenera.

**Approvazione** in linguaggio naturale, sempre valida: «Approvo», «Va bene, procedi», «Approvo il piano» o un'approvazione esplicita equivalente. Facoltativi, in aggiunta e mai al posto dell'approvazione scritta: i pulsanti «Approvo» · «Voglio modifiche» · «Annulla». **Non sono approvazione**: domande, commenti, richieste di spiegazione, silenzio, risposte ambigue («ok, ma…», «forse»): rispondi e rimani fermo al cancello. Se chiede modifiche, aggiorna il file dei contenuti, rigenera, mostra **di nuovo il piano completo** e attendi di nuovo.

## 1. Input guidato

All'avvio **non cercare in modo ricorsivo sul disco**: niente Glob o scansioni per indovinare i percorsi. Usa lo strumento di domande interattive di Claude Code (AskUserQuestion) quando è disponibile; se non lo è, scrivi le stesse domande in chat con le risposte numerate.

**1. Il file `triage.json`.** Leggi **solo** il percorso canonico `sast-output/triage/triage.json` per sapere se esiste; non cercare altri `triage.json`. Se esiste, proponilo come **prima** opzione:

> **Quale file di triage uso?**
> 1. `sast-output/triage/triage.json`
> 2. Altro percorso
> 3. Non l'ho ancora prodotto

Se non esiste, proponi solo «Altro percorso» e «Non l'ho ancora prodotto». Se sceglie «Non l'ho ancora prodotto»: spiega in breve che prima va completato `/sast-triage` e **fermati**.

**2. La cartella dei sorgenti.** Dopo aver letto `triage.json`, ispeziona **solo le cartelle di primo livello** della cartella di lavoro:

```
python "scripts/read_triage.py" "<triage.json>" --suggest-sources "<cartella di lavoro>"
```

Proponi come scelte le cartelle che contengono file citati dal triage, più «Altro percorso». Non fare ricerche ricorsive solo per indovinare la radice dei sorgenti. Servono sempre entrambi i percorsi: se manca uno, chiedilo e non fare altro.

## 2. Validazione e istantanea

```
python "scripts/read_triage.py" "<triage.json>" --sources "<sorgenti>"
python "scripts/check_source.py" snapshot "<sorgenti>" -o "<rem>/_work/snapshot.json"
```

- Il percorso `<rem>` è la riga «Output remediation» di `read_triage.py`. Il file di triage di norma è `sast-output/triage/triage.json`.
- Esito 1 (contratto non valido): fermati e spiega in italiano. Non riparare il file.
- Esito 3 (file non trovati nei sorgenti): chiedi la cartella corretta.
- **Candidati**: `High`, `Medium`, `Low` e osservazioni aggiuntive confermate. **Mai** `False Positive` né `Unknown - Needs Review` (di questi ultimi mostra la prova mancante solo se serve, senza proporli).

## 3. Piano generale (primo cancello)

Il piano **non lo scrivi tu**: lo genera uno script con sezioni fisse (Triage di origine · Candidati · Esclusioni · Ordine proposto · Osservazioni aggiuntive · Punti aperti · Approvazione). Tu fornisci l'ordine e i motivi.

1. Scrivi `<rem>/_work/remediation-input.json` da `templates/remediation-input.json`: ordine per rischio, dipendenze reali e vincoli (lo sforzo solo a parità); ogni finding candidato in un solo passo; le osservazioni aggiuntive restano separate.
2. `python "scripts/make_remediation_plan.py" plan --triage "<triage.json>" --input "<rem>/_work/remediation-input.json" -o "<rem>/PIANO_REMEDIATION.md"`. Se rifiuta i contenuti, correggili e rigenera.
3. **Mostra in chat il contenuto completo di `PIANO_REMEDIATION.md`**, identico al file generato: **non riassumerlo, non parafrasarlo**, non aggiungere commenti. Il piano termina già con la domanda «Approvi il piano di remediation, vuoi modificarlo o annulli?».

**Poi fermati e termina il turno.** Nessun piano di fix prima dell'approvazione. Dopo l'approvazione crea lo stato:

```
python "scripts/remediation_status.py" init --triage "<triage.json>" --input "<rem>/_work/remediation-input.json" --dir "<rem>"
```

Questo scrive `<rem>/REMEDIATION.md` con colonne fisse (ID · Verdetto · Stato · Aperto · Note). Ogni voce ha il campo **Aperto** per decisioni o dipendenze non risolte.

## 4. Scelta del finding

Dopo l'approvazione offri una scelta guidata, senza chiedere di scrivere gli ID a mano (a meno che scelga la risposta libera):

```
python "scripts/remediation_status.py" next --dir "<rem>"
```

Costruisci poche scelte dai raggruppamenti stampati (menu brevi, mai lunghi): **per gravità**, **per passo del piano**, **un singolo finding**. Se il raggruppamento scelto contiene più voci, chiedi quale affrontare per prima: si lavora **un finding alla volta**. Sono candidati solo `High`, `Medium`, `Low` e osservazioni confermate: mai falsi positivi né «Da verificare». Il linguaggio naturale resta sempre ammesso. Se la scelta viola una dipendenza reale, spiegalo in breve prima di proseguire.

## 5. Analisi tecnica

Per il finding scelto (deve essere un candidato): riapri le prove del triage, leggi i sorgenti attuali, verifica la causa radice, guarda chiamanti, lettori e configurazione direttamente coinvolti, rispetta `context.constraints`. Segui `references/fix-guidance.md`. Chiedi solo ciò che il codice non può dire in modo affidabile. Non rifare il triage completo.

## 6. Piano di fix (secondo cancello)

Il piano di fix **non lo scrivi tu**: lo genera uno script con sezioni fisse (Finding · Causa radice · Modifica proposta · File coinvolti · Compatibilità ed effetti collaterali · Percorsi temporanei di compatibilità · Verifica · Passi fuori dal codice · Diff · Punti aperti · Approvazione). Tu fornisci contenuti brevi, **senza patch**.

1. Scrivi `<rem>/_work/<ID>/fix-input.json` da `templates/fix-input.json`: per ogni file la consegna prevista (`diff`, `proposto`, `istruzioni`), un percorso di compatibilità legacy solo se serve, **sempre dichiarato temporaneo con la condizione in cui va rimosso**, e `changes_data_format` se cambia il formato di un valore cifrato o codificato.
2. `python "scripts/make_remediation_plan.py" fix --triage "<triage.json>" --input "<rem>/_work/<ID>/fix-input.json" -o "<rem>/fixes/<ID>/PIANO_FIX.md"`. L'obiettivo è circa 400 parole; **500 è il massimo**: oltre, lo script rifiuta e non scrive nulla, e tu **accorci i contenuti** (nessun taglio automatico).
3. `python "scripts/remediation_status.py" set --dir "<rem>" --id <ID> --status "Piano fix pronto"`.
4. **Mostra in chat il contenuto completo di `PIANO_FIX.md`**, identico al file: niente riassunti né parafrasi. Termina con «Approvi questo piano di fix, vuoi modificarlo o annulli?»

**Poi fermati e termina il turno.** All'approvazione: `remediation_status.py set … --status "Piano fix approvato"`. Se chiede modifiche: aggiorna `fix-input.json`, rigenera, mostra di nuovo il piano completo, attendi di nuovo.

## 7. Proposta (solo dopo il secondo cancello)

1. Verifica i sorgenti: `python "scripts/check_source.py" verify "<sorgenti>" --snapshot "<rem>/_work/snapshot.json"`.
2. Copia **solo** i file coinvolti in `<rem>/_work/<ID>/proposed/<percorso relativo>` e modifica le copie. Non scrivere mai nei sorgenti.
3. Diff, **file per file**:
   `python "scripts/make_diff.py" --sources "<sorgenti>" --proposed "<rem>/_work/<ID>/proposed" -o "<rem>/fixes/<ID>/<ID>.diff" --manifest "<rem>/fixes/<ID>/PROPOSTE.json"`
   - Esito 0: tutti i file sono nel diff.
   - Esito 3: almeno un file è escluso perché il suo diff riporterebbe un segreto. **Gli altri file hanno comunque il loro diff.** Non riportare mai il valore.
4. Per i file esclusi dal diff: `python "scripts/make_proposto.py" --sources "<sorgenti>" --proposed "<rem>/_work/<ID>/proposed" --fix-dir "<rem>/fixes/<ID>"`. Crea `<nome-originale>.proposto` nella cartella del fix («Sostituzione proposta, non applicata automaticamente»), con percorso relativo e SHA-256 dell'originale in `PROPOSTE.json`. Se la proposta contiene ancora un segreto, **non viene emessa**: per quel file restano solo istruzioni a parole, senza il valore.
5. Ripeti `check_source.py verify`: deve dire che i sorgenti sono identici. Altrimenti fermati e non dichiarare sicura la sessione.
6. Elimina `<rem>/_work/<ID>/proposed`.
7. Scrivi `<rem>/_work/<ID>/verification-input.json` da `templates/verification-input.json` e genera la verifica:
   `python "scripts/make_remediation_plan.py" verify --triage "<triage.json>" --input "<rem>/_work/<ID>/verification-input.json" --fix-input "<rem>/_work/<ID>/fix-input.json" --manifest "<rem>/fixes/<ID>/PROPOSTE.json" -o "<rem>/fixes/<ID>/VERIFICA.md"`.
   Comandi solo se dedotti dal progetto (e indicati come tali); mai dichiarare eseguito ciò che non lo è. Se cambia un formato cifrato, copri chi scrive, chi legge, chi valida, la compatibilità con i valori salvati, migrazione e rollback.
8. `python "scripts/check_secrets.py" "<rem>"`. Se segnala, rimuovi il valore e ripeti. Rileggi i file: nessun segreto.
9. `remediation_status.py set … --status "Fix proposto"`. **Mai** automaticamente «Applicato dallo sviluppatore» o «Verificato».

## Risposta finale

Breve: riassumi **solo** cosa hai prodotto e dove, in `sast-output/remediation/fixes/<ID>/` (`PIANO_FIX.md`, `<ID>.diff` se c'è, i file `.proposto` se ci sono, `PROPOSTE.json`, `VERIFICA.md`), file per file se diff, sostituzione proposta o solo istruzioni; «I sorgenti originali non sono stati modificati»; stato «Fix proposto»; «Rivedi la modifica prima di applicarla». **Non iniziare il finding successivo.** Se lo sviluppatore vuole un altro fix, riofferi la scelta guidata (facoltativa); il linguaggio naturale resta sempre ammesso.

## Dopo la proposta

Quando lo sviluppatore conferma di averla applicata: `remediation_status.py set … --status "Applicato dallo sviluppatore" --confirmed-by-developer`. Quando conferma che la verifica è riuscita: `… --status "Verificato" --confirmed-by-developer`. Solo allora. Stati: Da fare · Piano fix pronto · Piano fix approvato · Fix proposto · Applicato dallo sviluppatore · Verificato.

## Quando fermarti

`triage.json` non valido o non ancora prodotto · sorgenti mancanti o non corrispondenti · piano generale non approvato · finding non candidato · piano di fix non approvato · sorgenti cambiati · `check_secrets.py` segnala valori · triage sostanzialmente sbagliato · perimetro superato. Spiega cosa serve per continuare.
