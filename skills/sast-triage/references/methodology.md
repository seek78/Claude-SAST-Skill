# Metodologia operativa del triage

Regole operative per Claude.

## Regole di base

- Il report è un ingresso: riapri ogni finding sul sorgente e segui il flusso dei dati.
- `scanner_severity` = gravità originale AppScan (input). `verdict` = tuo esito. Campi separati, nessun altro sistema di gravità.
- `verdict` ∈ `High` (Grave) · `Medium` (Medio) · `Low` (Basso) · `False Positive` (Falso positivo) · `Unknown - Needs Review` (Da verificare). Con gli sviluppatori usa l'italiano, nei dati i valori canonici.
- Contesto ignoto → scenario peggiore ragionevole, dichiarato. Niente minacce irrealistiche.
- Catena non stabilita né smentita → `Unknown - Needs Review`. Non forzare. È un esito valido.
- Baseline precedente: solo contesto. Rivaluta sempre sul sorgente attuale.
- Il verdetto segue le prove e l'impatto. Costo, difficoltà o ampiezza della correzione non lo influenzano mai: sono compito di `sast-remediation`.

## Gravità

Impatto, sfruttabilità, precondizioni, nello scenario del piano.

- `High`: attaccante non autenticato o con privilegi minimi ottiene codice, dati, credenziali o aggira un controllo.
- `Medium`: servono precondizioni o l'impatto è parziale.
- `Low`: impatto limitato o sfruttamento improbabile.

## Cancelli

`False Positive` solo con prove esplicite su **G1–G4** che mostrano la catena non sfruttabile. Ne manca uno → non è `False Positive`.

| | Verifica |
|---|---|
| **G1 Raggiungibilità** | Chiamanti fino a un punto di ingresso reale; codice morto, obsoleto, solo test |
| **G2 Controllabilità** | Chi può influenzare il dato: utente, rete, file, database, configurazione, ambiente, messaggi, servizi esterni, dati salvati. Interno ≠ fidato |
| **G3 Artefatto rilasciato** | Build, pacchetto, installer, file per ambiente. Il sorgente non basta |
| **G4 Esito rilevante** | Canale o effetto utile a un attaccante, secondo la classe di problema |

**Codice pubblico di una libreria condivisa.** Se il codice segnalato è un'API pubblica distribuita come libreria, usabile anche fuori dal prodotto analizzato, l'assenza di chiamanti interni **non prova** che sia irraggiungibile.

- `False Positive`: solo se la raggiungibilità è smentita entro il perimetro di rilascio e di uso rilevante.
- `Unknown - Needs Review`: se i consumatori esterni non sono accertabili. Esempio di `missing_evidence`: «La classe è pubblica e distribuita come libreria condivisa; non è noto quali consumer esterni la utilizzino.»
- `High`, `Medium` o `Low`: solo con una catena raggiungibile sostenuta da prove; la gravità segue l'impatto.

Non esiste una regola automatica per questo caso: il verdetto nasce dalle prove, mai dal costo del fix.

## Motivazione

Ogni verdetto riporta: cosa hai ispezionato (`<file>:<riga>`); fin dove hai seguito il flusso; le prove con numeri e perimetro; dove ti sei fermato se incompleto.

- `False Positive`: spiega anche perché lo scanner ha segnalato.
- `Unknown - Needs Review`: scrivi quale prova manca.
- Non sono prove: nomi, assunzioni sul framework, etichette dello scanner, commenti, triage precedenti.

## Regole di analisi

- **Famiglie**: solo stesso flusso o stessa causa, non stesso CWE o etichetta. Istanza diversa → analisi separata.
- **Confini opachi** (binario, libreria, componente senza sorgente): solo lettura di documentazione, metadati o decompilato, se permesso, senza eseguire. Comportamento non dimostrato → ferma la catena, `Unknown - Needs Review`, nomina il componente. Non inventare.
- **Osservazioni aggiuntive**: elenco separato, mai come finding dello scanner; non duplicare; con prove; entro il perimetro approvato. Si cercano solo con le verifiche standard qui sotto.

## Verifiche standard oltre lo scanner

Dopo i finding, una fase **limitata** a cinque aree. Non è un audit generale: non si cercano altre classi di problemi.

1. Autenticazione e autorizzazione degli endpoint esposti
2. Segreti nel codice e nella configurazione
3. Sicurezza del trasporto e CORS
4. Esecuzione di SQL o comandi con dati non fidati o di origine esterna
5. Crittografia, chiavi e IV

Esito di ogni area, uno solo:

- **Nessuna osservazione confermata**;
- **una o più `OBS-xxx`** confermate;
- **Non applicabile o non verificabile** con le prove disponibili (nomina la prova che manca).

Regole:

- Diventa `OBS-xxx` solo un problema di sicurezza **confermato** da prove (`<file>:<riga>`), con `High`, `Medium` o `Low` secondo l'impatto. Non creare osservazioni `False Positive` o `Unknown` per riempire le aree.
- Le osservazioni restano separate dai finding AppScan e non li duplicano: se un'area è già coperta da un finding, citalo invece di aprire una `OBS`.
- Sola lettura, solo sorgenti del perimetro approvato, ricerche mirate. Le domande di aiuto sono in `checks-by-topic.md`.
- Segreti: esistenza e posizione, mai il valore.
- Il report riporta l'esito di tutte e cinque le aree.

## Autovalidazione

Prima di chiudere:

- ogni `False Positive` ha prove su G1–G4;
- ogni area standard ha un esito, e solo i problemi confermati sono `OBS`;
- ogni `Unknown - Needs Review` dichiara la prova mancante;
- ogni finding confermato ha prove sufficienti;
- ogni finding del report ha un `verdict`;
- gli script (conteggi, copertura, JSON, campi, segreti) passano.

## Segreti

Descrivi esistenza e posizione (`<file>:<riga>`, tipo, forma). Oscura il valore. Non riprodurlo per intero in nessun file.

## Da evitare

- Configurazione assente ≠ comportamento noto: verifica il predefinito.
- Sorgente presente ≠ rilasciato.
- Tipi e fiducia non si deducono dai nomi.
- Nessun verdetto per analogia.

Qui si stabilisce se il finding è reale e quanto è grave; le correzioni sono di `sast-remediation`.
