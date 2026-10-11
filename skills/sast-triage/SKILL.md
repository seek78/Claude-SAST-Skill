---
name: sast-triage
description: "Rivaluta con Claude i finding di un report SAST HCL AppScan (CSV, con XML e SCA facoltativi) sul codice sorgente, distinguendo problemi reali, falsi positivi e casi da verificare. Parte da un piano che lo sviluppatore deve approvare, poi produce triage.json e un report sintetico. Usala per fare il triage di un report AppScan o rivalutare i finding SAST. Non corregge il codice: per questo c'è sast-remediation."
---

# sast-triage

Rivaluta i finding di una scansione AppScan sul codice sorgente e produce `triage.json` (letto da `/sast-remediation`) e un report sintetico. Parla sempre in italiano con lo sviluppatore.

I percorsi `scripts/`, `references/` e `templates/` sono relativi alla cartella che contiene questo `SKILL.md`: non chiedere allo sviluppatore dove è installata la skill. Nei comandi usa il percorso completo di quella cartella. Usa `python` (o `python3` se `python` non esiste).

## Dove trovare le cose

| Cosa | File |
|---|---|
| Metodo, verdetti, G1–G4 | `references/methodology.md` |
| Domande per argomento | `references/checks-by-topic.md` |
| Formato di `triage.json` | `references/output-contract.md` |
| Domande iniziali | `templates/intake.md` |
| Contenuti che scrivi tu (piano, analisi) | `templates/plan-input.json`, `templates/analysis-input.json` |
| Script | `scripts/parse_appscan.py`, `build_triage.py`, `make_plan.py`, `make_report.py`, `check_secrets.py` (`triage_contract.py` è un modulo interno) |

## Regole ferme

- Sorgenti **in sola lettura**. I file generati vanno in `<triage>` = `sast-output/triage`, con `sast-output` **accanto** ai sorgenti, mai dentro (un'altra cartella solo se richiesta). `sast-output/remediation` è di `sast-remediation`: qui non si scrive.
- Nei file che produci scrivi i percorsi relativi sempre con `/`.
- **Nessun triage prima dell'approvazione esplicita del piano.**
- Il giudizio di sicurezza è tuo, non degli script.
- **Non scrivere mai** valori di credenziali, chiavi o token in nessun file: oscurali tu. `check_secrets.py` è una rete di sicurezza, non una garanzia.
- Non aggirare né correggere a mano parser e validatore: se falliscono, ti fermi o correggi l'analisi.

## 1. Input

All'avvio **non cercare nulla sul disco**: nessuna ricerca, niente Glob, shell o altre scansioni, finché lo sviluppatore non ha risposto alla prima domanda. Chiedi:

> **Come vuoi indicarmi i file?**
> 1. Cercali tu nella cartella di lavoro
> 2. Li indico io

Usa lo strumento di domande interattive di Claude Code (AskUserQuestion) con queste due opzioni. Se lo strumento di domande interattive non è disponibile, scrivi la stessa domanda in chat con le due risposte numerate e attendi la risposta.

**«Li indico io».** Chiedi in un solo messaggio: la cartella dei sorgenti, il report AppScan CSV (obbligatorio), l'XML AppScan (facoltativo), il report SCA (facoltativo). **Non cercare nulla sul disco** prima di aver ricevuto i percorsi.

**«Cercali tu nella cartella di lavoro».** Ricerca in sola lettura, **solo dentro la cartella di lavoro** (il progetto aperto): non guardare le cartelle superiori né altre posizioni del disco. La ricerca non parte mai se lo sviluppatore non sceglie questa modalità.

- Sorgenti: proponi le cartelle di primo livello plausibili (escluse `.claude`, `.git`, `sast-output` e le cartelle nascoste o di dipendenze) e «Altro percorso».
- Report CSV: proponi i `.csv` plausibili, riconosciuti dall'intestazione AppScan (`Issue Attributes`), e «Altro percorso».
- XML e SCA (facoltativi): proponi i candidati plausibili (XML con radice `xml-report`; HTML con le etichette SCA «ID problema» o «Issue ID»), «Nessuno» e «Altro percorso».
- Presenta le scelte con lo strumento interattivo, in una sola chiamata con le quattro domande: al massimo 3 candidati per domanda, in ordine alfabetico di percorso, più «Nessuno» per XML e SCA; la risposta libera dello strumento vale «Altro percorso». Senza lo strumento: elenco numerato in chat, con «Altro percorso» e «Nessuno».
- Se per sorgenti o CSV non trovi nulla di plausibile, dillo e chiedi il percorso.

Servono sempre la **cartella dei sorgenti** e il **report CSV**: se ne manca uno, chiedilo e non fare altro.

## 2. Parsing e ispezione preliminare

```
python "scripts/parse_appscan.py" "<report.csv>" --sources "<sorgenti>" -o "<triage>/_work/parsed.json" [--xml "<xml>"] [--sca "<sca>"]
```

- Passa **sempre** `--sources`; XML e SCA solo se già forniti.
- Se esce con errore, fermati e spiega in italiano cosa correggere. Non rifare il parsing a mano.
- Poi, in sola lettura: leggi `parsed.json`, individua stack, file di build e rilascio, e le famiglie candidate. Se `sources.not_found` è maggiore di 0, segnalalo: i sorgenti potrebbero non corrispondere alla scansione.
- **Non** assegnare verdetti e **non** seguire i flussi dei dati.

## 3. Contesto

Segui `templates/intake.md`. Chiedi **solo ciò che non si ricava in modo affidabile**, in una sola chiamata interattiva (o in un solo messaggio in chat se lo strumento non c'è):

- **Esposizione**: solo i valori del contratto, `Internet` · `Rete interna` · `Solo locale` · `Non nota`; un dettaglio libero facoltativo va in `exposure_detail`. Con `Non nota` applica lo scenario peggiore ragionevole e scrivilo nelle assunzioni.
- **«Vuoi aggiungere altro?»** (scelta multipla): Nulla · Vincoli · Baseline · Altro. Chiedi i dettagli solo delle voci scelte; con «Nulla» non fare altre domande (se è scelta insieme ad altre, ignorala).
- **Rilascio**: **non chiedere conferma** se lo ricavi da progetto, build o distribuzione: mostralo come «Rilascio: `<valore>` (rilevato)». Chiedilo solo se non è ricavabile.

Poi mostra «Contesto rilevato» (modello in `intake.md`): senza verdetti e senza chiedere un'approvazione a parte; lo sviluppatore può correggerlo. Se XML o SCA arrivano dopo, riesegui il parser con le opzioni aggiunte.

## 4. Piano e approvazione

Il piano **non lo scrivi tu**: lo genera uno script, così ha sempre le stesse sezioni (Input · Contesto · Scanner · Gruppi di analisi · Verifiche standard oltre lo scanner · Controlli trasversali · Punti aperti · Approvazione). Tu fornisci solo i contenuti di giudizio, **senza verdetti**:

1. Scrivi `<triage>/_work/plan-input.json` da `templates/plan-input.json`: contesto rilevato, gruppi di analisi (ogni finding in un solo gruppo, con un motivo breve), al massimo 3 controlli trasversali specifici del progetto, al massimo 2 punti aperti.
2. `python "scripts/make_plan.py" --parsed "<triage>/_work/parsed.json" --input "<triage>/_work/plan-input.json" -o "<triage>/PIANO_TRIAGE.md"`. Conteggi, id e metadati li calcola lo script. Se rifiuta i contenuti, correggili e rigenera: non modificare il file a mano.
3. **Mostra in chat il contenuto completo di `PIANO_TRIAGE.md`**, identico al file appena generato: leggilo e riportalo per intero. **Non riassumerlo, non parafrasarlo, non sostituirlo con un messaggio più breve** e non aggiungere commenti o suggerimenti. Il file è la registrazione; la conversazione è il luogo in cui lo sviluppatore lo rivede. Le verifiche standard oltre lo scanner fanno parte del piano: servono all'approvazione. Il piano termina già con la domanda «Approvi il piano, vuoi modifiche o annulli?».

**Poi fermati e termina il turno:** nessuna analisi, nessun altro file.

- **Approvazione** in linguaggio naturale, sempre valida: «Approvo», «Va bene, procedi», «Approvo il piano» o un'approvazione esplicita equivalente.
- Facoltativi, in aggiunta e mai al posto dell'approvazione scritta: con lo strumento interattivo puoi offrire anche i pulsanti «Approvo» · «Voglio modifiche» · «Annulla».
- **Non sono approvazione**: domande, commenti, richieste di spiegazione, silenzio, risposte ambigue («ok, ma…», «forse»). Rispondi e rimani fermo al cancello: richiedi l'approvazione.
- Se chiede modifiche: aggiorna `plan-input.json`, rigenera `PIANO_TRIAGE.md` con lo script, **mostra di nuovo il piano completo** e attendi di nuovo l'approvazione. Se annulla: fermati.

## 5. Triage (solo dopo l'approvazione)

- Valuta **ogni** finding del report, nessuno escluso: da solo o come famiglia reale (`methodology.md`).
- Riapri il sorgente, segui il flusso dei dati, usa `checks-by-topic.md`.
- Un solo `verdict` per finding: `High`, `Medium`, `Low`, `False Positive`, `Unknown - Needs Review`.
- **G1–G4** documentati per `High`, `Medium`, `Low` e `False Positive`. Per `Unknown`: i cancelli stabiliti e `missing_evidence`. Non inventare prove per completare un cancello.
- Non classificare da: gravità o categoria dello scanner, nome del file, nome del metodo, baseline, somiglianza con un altro finding.
- Baseline: solo per ritrovare un ragionamento. Ricontrolla sempre il sorgente.
- Confine opaco non risolvibile in sola lettura: `Unknown - Needs Review`, nominando il componente.
- Codice pubblico di una libreria condivisa: l'assenza di chiamanti interni non prova l'irraggiungibilità. `False Positive` solo se smentita nel perimetro rilevante; se i consumatori esterni non sono accertabili, `Unknown - Needs Review` (`methodology.md`). Il costo del fix non entra mai nel verdetto.
- **Verifiche standard oltre lo scanner**, dopo i finding: solo le cinque aree di `methodology.md` (endpoint esposti; segreti; trasporto e CORS; SQL o comandi con dati non fidati; crittografia, chiavi e IV). Non è un audit generale. Solo problemi **confermati** diventano `OBS-001`…, con `High`/`Medium`/`Low` e prove, senza duplicare un finding e dentro il perimetro approvato. Niente `OBS` `False Positive` o `Unknown`. L'esito di ciascuna area va in `standard_checks` (`confirmed_observation` · `no_observation` · `not_verifiable`).

## 6. Autovalidazione e output

1. Scrivi `<triage>/_work/analysis.json` da `templates/analysis-input.json`: solo i **tuoi** campi, compresi `defect_present` per ogni finding e `standard_checks` (le cinque aree, in ordine). Titolo, gravità dello scanner, posizione e metadati li aggiunge lo script.
2. Valida e genera:
   ```
   python "scripts/build_triage.py" --parsed "<triage>/_work/parsed.json" --analysis "<triage>/_work/analysis.json" -o "<triage>/triage.json"
   ```
   Se fallisce, **correggi l'analisi** e riesegui. Senza `triage.json` il triage non è completo.
3. Il report **non lo scrivi tu**: lo generano gli script dal solo `triage.json` già validato (conteggi, ordine e formato compresi), così è identico per ogni software:
   ```
   python "scripts/make_report.py" "<triage>/triage.json"
   ```
   Produce `<triage>/TRIAGE_REPORT.md` (da leggere) e `<triage>/TRIAGE_REPORT.csv` (per Excel). Non modificarli a mano: se qualcosa non va, correggi l'analisi e rigenera.
4. `python "scripts/check_secrets.py" "<triage>"`. Se segnala qualcosa, rimuovi il valore e ripeti.
5. Rileggi `PIANO_TRIAGE.md`, `TRIAGE_REPORT.md`, `TRIAGE_REPORT.csv` e `triage.json`: nessuna credenziale, chiave o token deve esserci, anche se lo script non segnala nulla.

`_work/` è interna: non presentarla come risultato.

## Risposta finale

Breve, in italiano: conteggi per verdetto (`High`, `Medium`, `Low`, `False Positive`, Da verificare), i file prodotti in `sast-output/triage/` (`PIANO_TRIAGE.md`, `TRIAGE_REPORT.md`, `TRIAGE_REPORT.csv`, `triage.json`) e la nota che `sast-output/triage/triage.json` si usa con `/sast-remediation`. Il dettaglio sta nel report.

## Quando fermarti

CSV non leggibile · input mancante · piano non approvato · cancelli G1–G4 mancanti · validazione del contratto fallita · `check_secrets.py` segnala valori probabili · proseguire richiederebbe di uscire dal perimetro approvato. Spiega cosa serve per continuare.
