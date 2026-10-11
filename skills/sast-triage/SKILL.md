---
name: sast-triage
description: "Rivaluta con Claude i finding di una scansione SAST sul codice sorgente: report HCL AppScan in CSV (con XML e SCA facoltativi) oppure uno o più file SARIF 2.1.0 di AppScan o di altri strumenti. Distingue problemi reali, falsi positivi e casi da verificare e aggiunge una security review di tutti i sorgenti con il metodo di /security-review. Parte da un piano che lo sviluppatore deve approvare, poi produce triage.json e un report sintetico. Usala per fare il triage di un report AppScan o SARIF o rivalutare i finding SAST. Non corregge il codice: per questo c'è sast-remediation."
---

# sast-triage

Rivaluta i finding di una scansione SAST (CSV AppScan con XML facoltativo, oppure uno o più SARIF) sul codice sorgente, aggiunge una security review di tutti i sorgenti e produce `triage.json` (letto da `/sast-remediation`) e un report sintetico. Parla sempre in italiano con lo sviluppatore.

I percorsi `scripts/`, `references/` e `templates/` sono relativi alla cartella che contiene questo `SKILL.md`: non chiedere allo sviluppatore dove è installata la skill. Nei comandi usa il percorso completo di quella cartella. Usa `python` (o `python3` se `python` non esiste).

## Dove trovare le cose

| Cosa | File |
|---|---|
| Metodo, verdetti, G1–G4 | `references/methodology.md` |
| Terza analisi: security review | `references/security-review.md` |
| Domande per argomento | `references/checks-by-topic.md` |
| Formato di `triage.json` | `references/output-contract.md` |
| Domande iniziali | `templates/intake.md` |
| Contenuti che scrivi tu (piano, analisi, security review) | `templates/plan-input.json`, `templates/analysis-input.json`, `templates/security-review-input.json` |
| Script | `scripts/parse_appscan.py` (CSV + XML), `parse_sarif.py` (uno o più SARIF), `build_triage.py`, `make_plan.py`, `make_report.py`, `check_secrets.py` (`triage_contract.py` è un modulo interno) |

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

**«Li indico io».** Chiedi in un solo messaggio: la cartella dei sorgenti, il report dello scanner (il CSV AppScan, con l'XML AppScan facoltativo, **oppure** uno o più file SARIF), il report SCA (facoltativo). **Non cercare nulla sul disco** prima di aver ricevuto i percorsi.

**«Cercali tu nella cartella di lavoro».** Ricerca in sola lettura, **solo dentro la cartella di lavoro** (il progetto aperto): non guardare le cartelle superiori né altre posizioni del disco. La ricerca non parte mai se lo sviluppatore non sceglie questa modalità.

- Sorgenti: proponi le cartelle di primo livello plausibili (escluse `.claude`, `.git`, `sast-output` e le cartelle nascoste o di dipendenze) e «Altro percorso».
- Report dello scanner: proponi i `.csv` plausibili, riconosciuti dall'intestazione AppScan (`Issue Attributes`), e i `.sarif` (o `.sarif.json`) plausibili, riconosciuti da `"version": "2.1.0"` e dall'elenco `runs`; nella descrizione di ogni scelta indica il tipo (CSV AppScan o SARIF). Più «Altro percorso». Questa domanda è a scelta multipla: si possono scegliere più SARIF, un solo CSV.
- XML e SCA (facoltativi): proponi i candidati plausibili (XML con radice `xml-report`, utile solo con un CSV; HTML con le etichette SCA «ID problema» o «Issue ID»), «Nessuno» e «Altro percorso».
- Presenta le scelte con lo strumento interattivo, in una sola chiamata con le quattro domande: al massimo 3 candidati per domanda, in ordine alfabetico di percorso, più «Nessuno» per XML e SCA; la risposta libera dello strumento vale «Altro percorso». Senza lo strumento: elenco numerato in chat, con «Altro percorso» e «Nessuno».
- Se per sorgenti o report non trovi nulla di plausibile, dillo e chiedi il percorso.

Servono sempre la **cartella dei sorgenti** e il report dello scanner, **un** CSV AppScan oppure **uno o più** SARIF: se manca uno dei due, chiedilo e non fare altro. CSV e SARIF sono alternativi: se li ricevi entrambi, chiedi quale usare. Più SARIF si leggono insieme; più CSV no: se ne ricevi più di uno, chiedi quale usare. Con il SARIF l'XML non serve (le tracce sono nei `codeFlows`): se è stato indicato, dillo e non usarlo.

## 2. Parsing e ispezione preliminare

Con il CSV AppScan:

```
python "scripts/parse_appscan.py" "<report.csv>" --sources "<sorgenti>" -o "<triage>/_work/parsed.json" [--xml "<xml>"] [--sca "<sca>"]
```

Con il SARIF:

```
python "scripts/parse_sarif.py" "<report.sarif>" ["<altro.sarif>" ...] --sources "<sorgenti>" -o "<triage>/_work/parsed.json" [--sca "<sca>"]
```

- Passa **sempre** `--sources`; XML e SCA solo se già forniti.
- I due parser scrivono lo stesso `parsed.json`: da qui in poi il flusso non cambia.
- SARIF: lo script ricava la gravità dello scanner (campo dello strumento, poi `security-severity`, poi `level`), risolve i nomi di classe di AppScan nei file dei sorgenti ed esclude i risultati soppressi nello strumento, quelli `absent` e quelli che non sono problemi (`pass`, `notApplicable`, `informational`), contandoli. Se ha escluso risultati soppressi, dillo nel «Contesto rilevato»: se lo sviluppatore li vuole nel triage, riesegui con `--include-suppressed`.
- Più SARIF: una sola numerazione `AS-xxx`, nell'ordine dei file indicati. Un risultato già letto da un file precedente (stesso strumento, regola, file, riga e identificativo) conta una volta sola: lo script lo esclude e lo segnala. Il nome del report diventa l'elenco dei file uniti da « + » e la data è la più recente. Nel «Contesto rilevato» indica i file e gli eventuali duplicati esclusi.
- Se esce con errore, fermati e spiega in italiano cosa correggere. Non rifare il parsing a mano.
- Poi, in sola lettura: leggi `parsed.json`, individua stack, file di build e rilascio, e le famiglie candidate. Se `sources.not_found` è maggiore di 0, segnalalo: i sorgenti potrebbero non corrispondere alla scansione. Eccezione: nel CSV di AppScan i finding del codice compilato indicano la classe invece del file (es. `Azienda.Modulo.Classe.cs`, senza cartelle) e restano non trovati anche con i sorgenti giusti; `/sast-remediation` non può usarli. Se sono molti, dillo e suggerisci l'export SARIF della stessa scansione, che `parse_sarif.py` risolve nei file reali.
- **Non** assegnare verdetti e **non** seguire i flussi dei dati.

## 3. Contesto

Segui `templates/intake.md`. Chiedi **solo ciò che non si ricava in modo affidabile**, in una sola chiamata interattiva (o in un solo messaggio in chat se lo strumento non c'è):

- **Esposizione**: solo i valori del contratto, `Internet` · `Rete interna` · `Solo locale` · `Non nota`; un dettaglio libero facoltativo va in `exposure_detail`. Con `Non nota` applica lo scenario peggiore ragionevole e scrivilo nelle assunzioni.
- **«Vuoi aggiungere altro?»** (scelta multipla): Nulla · Vincoli · Baseline · Altro. Chiedi i dettagli solo delle voci scelte; con «Nulla» non fare altre domande (se è scelta insieme ad altre, ignorala).
- **Rilascio**: **non chiedere conferma** se lo ricavi da progetto, build o distribuzione: mostralo come «Rilascio: `<valore>` (rilevato)». Chiedilo solo se non è ricavabile.

Poi mostra «Contesto rilevato» (modello in `intake.md`): senza verdetti e senza chiedere un'approvazione a parte; lo sviluppatore può correggerlo. Se XML o SCA arrivano dopo, riesegui il parser con le opzioni aggiunte.

## 4. Piano e approvazione

Il piano **non lo scrivi tu**: lo genera uno script, così ha sempre le stesse sezioni (Input · Contesto · Scanner · Gruppi di analisi · Verifiche standard oltre lo scanner · Controlli trasversali · Punti aperti · Approvazione). La sezione delle verifiche standard termina con la riga della terza analisi, la security review di tutti i sorgenti. Tu fornisci solo i contenuti di giudizio, **senza verdetti**:

1. Scrivi `<triage>/_work/plan-input.json` da `templates/plan-input.json`: contesto rilevato, gruppi di analisi (ogni finding in un solo gruppo, con un motivo breve; con più SARIF, i finding di strumenti diversi sullo stesso punto vanno nello stesso gruppo), al massimo 3 controlli trasversali specifici del progetto, al massimo 2 punti aperti.
2. `python "scripts/make_plan.py" --parsed "<triage>/_work/parsed.json" --input "<triage>/_work/plan-input.json" -o "<triage>/PIANO_TRIAGE.md"`. Conteggi, id e metadati li calcola lo script. Se rifiuta i contenuti, correggili e rigenera: non modificare il file a mano.
3. **Mostra in chat il contenuto completo di `PIANO_TRIAGE.md`**, identico al file appena generato: leggilo e riportalo per intero. **Non riassumerlo, non parafrasarlo, non sostituirlo con un messaggio più breve** e non aggiungere commenti o suggerimenti. Il file è la registrazione; la conversazione è il luogo in cui lo sviluppatore lo rivede. Le verifiche standard oltre lo scanner e la security review fanno parte del piano: servono all'approvazione. Il piano termina già con la domanda «Approvi il piano, vuoi modifiche o annulli?».

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
- **Security review (terza analisi)**, dopo le verifiche standard: segui `references/security-review.md`. Applichi a **tutta** la cartella dei sorgenti il metodo di `/security-review` (un sub-agent di ricerca, un sub-agent per candidata per il filtro dei falsi positivi, soglia di confidenza 8), poi riverifichi tu ogni candidata sul sorgente. Solo le vulnerabilità confermate e non già coperte da un finding o da un'altra `OBS` diventano nuove `OBS-xxx`, con `analysis_summary` che inizia con «Security review:»; se rientrano in una delle cinque aree, vanno anche in `standard_checks` di quell'area. **Non invocare il comando `/security-review`**: esamina solo il diff del branch.

## 6. Autovalidazione e output

1. Scrivi `<triage>/_work/analysis.json` da `templates/analysis-input.json`: solo i **tuoi** campi, compresi `defect_present` per ogni finding e `standard_checks` (le cinque aree, in ordine). Titolo, gravità dello scanner, posizione e metadati li aggiunge lo script.
2. Scrivi `<triage>/_work/security-review.json` da `templates/security-review-input.json`: una voce per **ogni** candidata della security review, anche scartata, con esito `observation` (`ref` = la nuova `OBS`), `duplicate` (`ref` = il finding o l'`OBS` già presente) o `discarded` (con il motivo). Elenco vuoto se la ricerca non ha trovato nulla.
3. Valida e genera:
   ```
   python "scripts/build_triage.py" --parsed "<triage>/_work/parsed.json" --analysis "<triage>/_work/analysis.json" --security-review "<triage>/_work/security-review.json" -o "<triage>/triage.json"
   ```
   Se fallisce, **correggi l'analisi** (o `security-review.json`) e riesegui. Senza `triage.json` il triage non è completo.
4. Il report **non lo scrivi tu**: lo generano gli script dal solo `triage.json` già validato (conteggi, ordine e formato compresi), così è identico per ogni software:
   ```
   python "scripts/make_report.py" "<triage>/triage.json"
   ```
   Produce `<triage>/TRIAGE_REPORT.md` (da leggere) e `<triage>/TRIAGE_REPORT.csv` (per Excel). Non modificarli a mano: se qualcosa non va, correggi l'analisi e rigenera.
5. `python "scripts/check_secrets.py" "<triage>"`. Se segnala qualcosa, rimuovi il valore e ripeti.
6. Rileggi `PIANO_TRIAGE.md`, `TRIAGE_REPORT.md`, `TRIAGE_REPORT.csv` e `triage.json`: nessuna credenziale, chiave o token deve esserci, anche se lo script non segnala nulla.

`_work/` è interna: non presentarla come risultato.

## Risposta finale

Breve, in italiano: conteggi per verdetto (`High`, `Medium`, `Low`, `False Positive`, Da verificare), l'esito della security review (candidate esaminate, `OBS` create, duplicati, scartate), i file prodotti in `sast-output/triage/` (`PIANO_TRIAGE.md`, `TRIAGE_REPORT.md`, `TRIAGE_REPORT.csv`, `triage.json`) e la nota che `sast-output/triage/triage.json` si usa con `/sast-remediation`. Il dettaglio sta nel report.

## Quando fermarti

Report (CSV o SARIF) non leggibile · input mancante · piano non approvato · cancelli G1–G4 mancanti · security review non eseguita o non registrata · validazione del contratto fallita · `check_secrets.py` segnala valori probabili · proseguire richiederebbe di uscire dal perimetro approvato. Spiega cosa serve per continuare.
