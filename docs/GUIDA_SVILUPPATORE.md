# SAST Claude Toolkit — Guida per sviluppatori

## 1. Cos'è SAST Claude Toolkit

Il toolkit aiuta a rivalutare i risultati di una scansione SAST **HCL AppScan** (o di un altro strumento che esporta **SARIF**) confrontandoli con il codice sorgente e con le prove disponibili, e a preparare correzioni controllate.

- **Non sostituisce lo scanner**: lo scanner trova i finding, il toolkit li rivaluta e aggiunge una security review di tutti i sorgenti.
- La gravità dello scanner è un **input**, non il verdetto finale: ogni finding viene riaperto sul sorgente.
- Le correzioni sono **proposte**: tu le rivedi e le applichi.
- Resti sempre tu a decidere: ci sono approvazioni esplicite prima del triage e prima di ogni fix.

Due skill di Claude Code:

- **`sast-triage`**: stabilisce, per ogni finding, se il problema è reale e quanto è grave; poi esegue le verifiche standard e la security review.
- **`sast-remediation`**: legge il risultato del triage e prepara, un finding alla volta, piano di fix, modifica proposta e verifica.

**Il toolkit non modifica mai automaticamente i sorgenti.**

## 2. Requisiti

- Claude Code.
- Python 3, disponibile come `python` o `python3`. Nessun pacchetto Python di terze parti.
- Il codice sorgente dell'applicazione.
- Il report dello scanner (obbligatorio): AppScan in **CSV**, con il report AppScan **XML** facoltativo, **oppure** un file **SARIF 2.1.0** di AppScan o di un altro strumento SAST.
- Il report **SCA** (facoltativo).

Git non è obbligatorio.

## 3. Installazione

### Installazione per progetto (consigliata)

Dalla cartella del progetto:

```
python <percorso-toolkit>/install.py
```

oppure indicando la cartella:

```
python install.py "<cartella-progetto>"
```

Eseguendo `python install.py` dalla cartella del toolkit, lo script chiede `Cartella del progetto >`: incolla o trascina il percorso (anche tra virgolette o con spazi); Invio a vuoto annulla senza scrivere nulla.

Lo script crea `<progetto>/.claude/skills/`, copia le due skill e ne controlla l'integrità. Non sovrascrive nulla di diverso e non tocca altre skill o impostazioni; se qualcosa va storto non lascia installazioni a metà.

Opzioni:

- `--controlla`: mostra cosa farebbe, senza scrivere nulla.
- `--personale`: installa in `~/.claude/skills`, per **tutti** i progetti; per questo non è la scelta consigliata di default.
- `--sovrascrivi`: sostituisce una versione già installata ma diversa (vedi il capitolo 14).

### Alternativa manuale

Copia le cartelle

```
skills/sast-triage
skills/sast-remediation
```

in

```
<progetto>/.claude/skills/
```

### Verifica

1. Apri una **sessione nuova** di Claude Code nel progetto.
2. Scrivi `/`.
3. Controlla che compaiano `sast-triage` e `sast-remediation`.

## 4. Flusso generale

```
/sast-triage
→ input
→ contesto rilevato
→ piano
→ approvazione
→ triage (finding, verifiche standard, security review)
→ report + triage.json

/sast-remediation
→ piano remediation
→ approvazione
→ scelta finding
→ piano fix
→ approvazione
→ proposta + verifica
```

## 5. Triage

Avvio:

```
/sast-triage
```

Claude chiede «Come vuoi indicarmi i file?»:

- **Cercali tu nella cartella di lavoro**: Claude cerca in sola lettura **solo dentro la cartella in cui hai aperto Claude Code** e ti propone i candidati da scegliere. La ricerca non parte mai se non la scegli.
- **Li indico io**: scrivi tu i percorsi; Claude non cerca nulla sul disco.

Servono sempre:

- la **cartella dei sorgenti**;
- il **report dello scanner**: il **CSV AppScan** oppure un file **SARIF** (sono alternativi: se ne indichi entrambi, Claude chiede quale usare).

Sono facoltativi il report **XML** (solo con il CSV), il report **SCA** e una baseline o un contesto aggiuntivo (vincoli, un triage precedente: è solo contesto e non decide mai il verdetto).

### Report SARIF

Il SARIF sostituisce la coppia CSV + XML: contiene i finding e, nei `codeFlows`, le tracce dei flussi di dati. Va bene l'export SARIF di AppScan (on Cloud, 360°, Source) o il SARIF 2.1.0 di un altro strumento SAST. Lo legge `parse_sarif.py`, che produce gli stessi dati intermedi del CSV: piano, report, CSV e `triage.json` hanno lo stesso formato.

- **Un finding per risultato**, nell'ordine del file, numerati `AS-001`, `AS-002`… anche se il SARIF non viene da AppScan.
- **Gravità dello scanner**, sulla scala `Critical` · `High` · `Medium` · `Low` · `Informational`, presa nell'ordine da:
  1. il campo di gravità dello strumento (es. `properties.Severity` di AppScan);
  2. `security-severity` (punteggio CVSS: da 9.0 `Critical`, da 7.0 `High`, da 4.0 `Medium`, da 0.1 `Low`);
  3. `level` (`error` `High`, `warning` `Medium`, `note` `Low`, `none` `Informational`).
- **File**: i percorsi diventano relativi ai sorgenti come per il CSV. Per il codice compilato AppScan indica la classe invece del file (es. `Azienda.Modulo.Repositories.OrderRepository.cs`): il parser trova `OrderRepository.cs` nella cartella che corrisponde al namespace. Il CSV di AppScan on Cloud usa la stessa forma nella colonna `Source File`, ma il suo parser resta quello della versione 1.0.0 e non la risolve: quei finding risultano «non trovati» nei sorgenti e `/sast-remediation` non li accetta. Per lavorarli usa l'export SARIF della stessa scansione.
- **Tracce e titoli**: rispetto alla coppia CSV + XML della stessa scansione, il SARIF ha le tracce solo per i finding con flusso di dati (l'XML riporta anche la riga di codice evidenziata per gli altri); il titolo è il messaggio del SARIF, uguale al tipo di problema del CSV nella maggior parte dei casi e più descrittivo negli altri (es. «Throwing generic exceptions in C#» invece di «ErrorHandling»).
- **Esclusi**, e contati: i risultati soppressi nello strumento (salvo richiesta esplicita), quelli non più presenti (`baselineState` `absent`) e quelli che non sono problemi (`kind` `pass`, `notApplicable`, `informational`).
- **Data del report**: quella dichiarata negli `invocations`. L'export SARIF di AppScan non la riporta: nel report compare «data non disponibile».

Ti viene chiesta l'**esposizione**, una tra:

- `Internet`
- `Rete interna`
- `Solo locale`
- `Non nota` (Claude assume lo scenario peggiore ragionevole e lo dichiara)

Il modo di rilascio viene dedotto dal progetto e mostrato come «Rilascio: … (rilevato)»; ti viene chiesto solo se non è ricavabile.

Poi Claude:

1. ispeziona le prove disponibili (progetto, build, rilascio) e **mostra il contesto rilevato**, che puoi correggere;
2. crea `sast-output/triage/PIANO_TRIAGE.md` (gruppi di analisi, cinque verifiche standard, security review, controlli previsti, nessun verdetto);
3. **mostra in chat il piano completo**, identico al file;
4. si ferma e aspetta.

**Nessun triage parte senza un'approvazione esplicita** («Approvo», «Va bene, procedi»). Una domanda, un commento, una richiesta di spiegazione o una risposta ambigua («ok, ma…») **non sono approvazione**: Claude risponde e resta fermo. Se chiedi modifiche, rigenera il piano e te lo mostra di nuovo per intero.

## 6. Metodo di valutazione

Per ogni finding Claude verifica quattro cancelli:

- **G1 raggiungibilità**: il codice è eseguibile in un flusso reale?
- **G2 controllabilità**: un attaccante può influenzare il dato?
- **G3 presenza nell'artefatto**: il codice fa parte di ciò che viene rilasciato?
- **G4 effetto rilevante**: il risultato raggiunge un effetto utile a un attaccante?

Verdetti canonici: `High`, `Medium`, `Low`, `False Positive`, `Unknown - Needs Review`. La gravità dello scanner resta un campo separato.

- `False Positive` richiede **prove esplicite** su tutti e quattro i cancelli.
- Se le prove sono incomplete il verdetto è `Unknown - Needs Review`, con scritto quale prova manca. È un esito valido, non un errore.
- Un difetto reale del software **senza impatto di sicurezza sfruttabile** può essere `False Positive`, e il report lo segnala esplicitamente.
- Il codice pubblico di una **libreria condivisa** non è considerato irraggiungibile solo perché nel prodotto analizzato non ha chiamanti: se i consumatori esterni non si possono accertare, il verdetto è `Unknown - Needs Review`.
- Costo e difficoltà della correzione non cambiano mai il verdetto.

Dopo i finding Claude esegue **cinque verifiche standard**, uguali per tutti i software: autenticazione e autorizzazione degli endpoint esposti; segreti; trasporto e CORS; SQL e comandi; crittografia. Per ogni area l'esito è: nessuna osservazione confermata, una o più osservazioni, oppure non verificabile con le prove disponibili. Solo i problemi **confermati** diventano `OBS-xxx`, separati dai finding dello scanner. Non è un audit generale.

Infine la **terza analisi**: una **security review di tutta la cartella dei sorgenti** con il metodo del comando `/security-review` di Claude Code (stesse categorie, esclusioni e filtro dei falsi positivi, soglia di confidenza 8 su 10). Il comando nativo esamina solo il diff del branch rispetto a `origin/HEAD` e richiede Git: per questo la skill ne applica le istruzioni a tutti i sorgenti, senza invocarlo. Ogni vulnerabilità candidata viene poi riverificata sul sorgente con le regole del toolkit: diventano `OBS-xxx` solo quelle confermate e non già coperte da un finding o da un'altra osservazione. Nel report le riconosci perché la sintesi inizia con «Security review:»; se rientrano in una delle cinque aree, compaiono anche nella tabella delle verifiche standard. La review è annunciata nel piano, quindi coperta dalla tua approvazione.

Le regole complete sono nei riferimenti delle skill; qui basta sapere che si basano sulle prove, non sulla gravità dello scanner.

## 7. Output del triage

La cartella `sast-output/` viene creata accanto alla cartella indicata come root dei sorgenti. Di conseguenza, se come sorgenti indichi direttamente la root del progetto, `sast-output/` viene creata nella directory superiore.

```
sast-output/triage/
├── PIANO_TRIAGE.md
├── TRIAGE_REPORT.md
├── TRIAGE_REPORT.csv
├── triage.json
└── _work/
```

- `PIANO_TRIAGE.md`: il piano che hai approvato.
- `TRIAGE_REPORT.md`: il report da leggere, sempre con le stesse sezioni (riepilogo, finding confermati, `False Positive`, `Unknown - Needs Review`, verifiche standard, osservazioni aggiuntive).
- `TRIAGE_REPORT.csv`: una riga per ogni finding e osservazione, da aprire in Excel (separatore `;`, UTF-8).
- `triage.json`: il **contratto stabile e validato** tra `sast-triage` e `sast-remediation`. Contiene, in sintesi: metadati del progetto e del report scanner, contesto rilevato, finding con verdetto, prove e cancelli G1–G4, esito delle cinque verifiche standard e osservazioni aggiuntive (anche quelle della security review). `/sast-remediation` parte da questo risultato validato invece di rifare il triage.
- `_work/`: dati di lavoro interni, non sono il risultato principale. `_work/security-review.json` registra ogni candidata della security review con il suo esito (osservazione, duplicato o scartata, e perché).

Il formato dei file è lo stesso qualunque sia il report di partenza (CSV o SARIF).

## 8. Remediation

Avvio:

```
/sast-remediation
```

Usa `sast-output/triage/triage.json` e la cartella dei sorgenti. Se il file esiste nel percorso canonico, Claude lo propone come prima scelta; altrimenti puoi indicare un altro percorso. Per i sorgenti propone le cartelle di primo livello che contengono i file citati dal triage. Se il triage non è ancora stato prodotto, esegui prima `/sast-triage`.

Flusso:

1. **piano generale** (`PIANO_REMEDIATION.md`), mostrato per intero in chat;
2. **prima approvazione**: finché non approvi non si prepara nessun fix;
3. **scelta guidata** di un finding o di un'osservazione confermata (per gravità, per passo del piano o singolo);
4. **analisi tecnica** della causa radice sul sorgente attuale;
5. **piano di fix** (`PIANO_FIX.md`, al massimo 500 parole), mostrato per intero;
6. **seconda approvazione**: nessun diff né file proposto prima;
7. **generazione della proposta** e della verifica.

Si lavora **un finding alla volta**: finita la proposta, la skill si ferma e non passa al successivo da sola.

Finding correlati possono avere dipendenze tra loro. Il piano di remediation ne indica l'ordine; prima del rilascio le modifiche dipendenti devono essere verificate insieme come un'unica modifica coerente.

Sono candidati solo `High`, `Medium`, `Low` e le `OBS-xxx` confermate. I `False Positive` e gli `Unknown - Needs Review` non vengono proposti per la correzione. Anche qui domande e richieste di modifica non valgono come approvazione.

## 9. Output della remediation

```
sast-output/remediation/
├── PIANO_REMEDIATION.md
├── REMEDIATION.md
├── _work/
└── fixes/
    └── <ID>/
        ├── PIANO_FIX.md
        ├── VERIFICA.md
        ├── *.diff
        ├── *.proposto
        └── PROPOSTE.json
```

`<ID>` può essere un finding dello scanner, come `AS-xxx`, oppure un'osservazione aggiuntiva confermata (dalle verifiche standard o dalla security review), come `OBS-xxx`.

**Non ogni fix produce tutti i tipi di file.** La remediation non scrive mai in `sast-output/triage/`.

- `REMEDIATION.md`: stato di ogni candidato (`Da fare`, `Piano fix pronto`, `Piano fix approvato`, `Fix proposto`, `Applicato dallo sviluppatore`, `Verificato`) e decisioni ancora aperte.
- `*.diff`: patch sicura, con percorsi relativi, per i file che si possono rappresentare senza mostrare segreti.
- `*.proposto`: sostituzione proposta sicura per un file il cui diff non sarebbe sicuro. **Non viene applicata automaticamente.** Percorso e SHA-256 dell'originale sono registrati nel manifest e in `VERIFICA.md`.
- `PROPOSTE.json`: manifest degli artefatti, file per file.
- `VERIFICA.md`: controlli da fare prima e dopo l'applicazione, cosa non è stato compilato né testato, rollback.

## 10. Applicare una correzione

**Il toolkit propone, lo sviluppatore applica. Il toolkit non cambia mai i file sorgente.**

Procedura consigliata:

1. lavora su un **ramo dedicato**;
2. un fix alla volta;
3. leggi `PIANO_FIX.md`;
4. rivedi il diff o la proposta;
5. applica a mano o con i normali strumenti di sviluppo;
6. compila ed esegui i test previsti;
7. fai il commit;
8. solo allora conferma alla skill «Applicato dallo sviluppatore»;
9. solo dopo una verifica reale conferma «Verificato».

Un diff si applica, dalla radice dei sorgenti, con:

```
git apply <file>.diff
```

Git non serve per generare gli output del toolkit: serve solo se scegli di applicare così la patch. Prima di sostituire un file con una proposta `.proposto`, confronta l'SHA-256 del file originale con quello registrato (PowerShell: `Get-FileHash <file> -Algorithm SHA256`; altrove `sha256sum <file>`): se è cambiato, la proposta va rigenerata.

Puoi anche chiedere a Claude, **in una normale sessione di sviluppo fuori dalla skill**, di applicare una proposta già rivista, per esempio su un ramo nuovo.

## 11. Segreti

- Non incollare mai valori segreti (password, chiavi, token) nella conversazione.
- I file prodotti non espongono valori segreti: descrivono dove sono e di che tipo.
- Un file che contiene un segreto può essere escluso dal diff; gli altri file della stessa correzione hanno comunque il loro diff.
- Un `.proposto` viene emesso solo se è sicuro; altrimenti la skill dà istruzioni a parole.
- Rotazione o revoca di una credenziale esposta possono essere necessarie, **fuori** dalla modifica al codice: il piano di fix e la verifica le indicano.

## 12. Permessi e sorgenti

- Claude Code può chiederti il permesso di eseguire Python o di creare i file di output: è normale.
- L'accesso del toolkit ai sorgenti è in **sola lettura**.
- Gli output stanno in `sast-output/`, separati dai sorgenti.

## 13. Buone pratiche

- Leggi il piano completo prima di approvare.
- Non inventare prove mancanti: `Unknown - Needs Review` è un esito valido.
- Non condividere mai valori segreti.
- Lavora un fix alla volta.
- Rivedi ogni proposta.
- Compila ed esegui i test previsti prima di segnare un fix come verificato.

## 14. Aggiornamento e rimozione

**Aggiornamento.** Per sostituire di proposito una versione già installata ma diversa:

```
python <percorso-toolkit>/install.py --sovrascrivi
```

Se il terminale è già aperto nella cartella del toolkit, la forma più breve `python install.py --sovrascrivi` è equivalente. Senza questa opzione una skill diversa viene lasciata invariata.

**Rimozione.** In un'installazione di progetto elimina:

```
<progetto>/.claude/skills/sast-triage
<progetto>/.claude/skills/sast-remediation
```

Non serve uno script di disinstallazione.
