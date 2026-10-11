# Contratto di output del triage

`sast-triage` produce un file JSON che `sast-remediation` legge. È l'unica interfaccia tra le due skill e contiene solo ciò che serve alla remediation. Versione: `"schema_version": "1.0"`.

## Struttura

```json
{
  "schema_version": "1.0",
  "metadata": {
    "project_name": "<nome-cartella-sorgenti>",
    "scanner_report_name": "<report-appscan.csv>",
    "scanner_report_date": "2026-01-15",
    "toolkit_version": "<versione>"
  },
  "context": {
    "stack": ["<linguaggio e framework>"],
    "exposure": "Internet | Rete interna | Solo locale | Non nota",
    "exposure_detail": "<dettaglio libero, anche vuoto>",
    "release_model": "<come viene rilasciato>",
    "constraints": ["<vincolo>"],
    "assumptions": ["<assunzione>"]
  },
  "findings": [
    {
      "id": "AS-001",
      "title": "<titolo del finding>",
      "scanner_severity": "Medium",
      "verdict": "High",
      "defect_present": null,
      "location": { "file": "src/modulo/File.ext", "line": 42 },
      "analysis_summary": "<perché questo verdetto>",
      "evidence": [
        { "file": "src/modulo/File.ext", "line": 42, "note": "<cosa si vede>" }
      ],
      "gates": { "g1": "", "g2": "", "g3": "", "g4": "" },
      "missing_evidence": []
    }
  ],
  "additional_observations": [],
  "standard_checks": [
    {
      "area": "authentication_authorization",
      "status": "no_observation",
      "observation_ids": [],
      "missing_evidence": []
    }
  ]
}
```

`standard_checks` contiene sempre **cinque** voci (qui ne è mostrata una sola).

## Campi

**`metadata`**: scritto **dallo script**, mai da Claude. Serve a confrontare triage di software e momenti diversi.

| Campo | Origine |
|---|---|
| `project_name` | nome dell'ultima cartella del percorso dei sorgenti indicato allo strumento; non si ricava dal contenuto dei sorgenti |
| `scanner_report_name` | nome del file CSV AppScan (senza cartelle) |
| `scanner_report_date` | data `AAAA-MM-GG` dichiarata dallo scanner nel CSV (sezione `Report Attributes`, UTC); `null` se non c'è o non è valida. Mai la data del file, della copia o di oggi |
| `toolkit_version` | versione del toolkit, una costante dello script |

**`context`**: contesto che può influenzare le correzioni.

| Campo | Significato |
|---|---|
| `stack` | tecnologie rilevate |
| `exposure` | esposizione usata nel triage, solo uno tra: `Internet`, `Rete interna`, `Solo locale`, `Non nota` |
| `exposure_detail` | dettaglio libero sull'esposizione (può essere vuoto) |
| `release_model` | come viene rilasciato il software |
| `constraints` | vincoli indicati dallo sviluppatore |
| `assumptions` | assunzioni fatte, in particolare lo scenario peggiore ragionevole |

**`findings`**: una voce per **ogni** segnalazione del report AppScan.

| Campo | Significato |
|---|---|
| `id` | identificativo univoco nel file (es. `AS-001`), usato da triage e remediation |
| `title` | titolo breve |
| `scanner_severity` | gravità originale di AppScan, separata dal verdetto |
| `verdict` | esito del triage (vedi sotto) |
| `defect_present` | solo per `False Positive`: `true` = esiste un difetto software reale ma la catena verificata non ha impatto di sicurezza; `false` = non è stato stabilito nessun difetto rilevante per il finding. Per ogni altro verdetto è `null` |
| `location` | punto segnalato: `file` relativo ai sorgenti, `line` numero oppure `null` |
| `analysis_summary` | perché il finding ha quel verdetto, in poche righe |
| `evidence` | punti di codice da riaprire per capire o correggere: `file`, `line`, `note` breve. Niente blocchi di codice |
| `gates` | per G1–G4, la prova in una frase. Obbligatori per `High`, `Medium`, `Low` e `False Positive`; per `Unknown - Needs Review` restano vuoti solo i cancelli non verificabili |
| `missing_evidence` | prove mancanti; vuoto salvo `Unknown - Needs Review` |

**`additional_observations`**: problemi notati fuori dal report, mai duplicati di un finding. Campi: `id` (es. `OBS-001`), `title`, `verdict` (solo `High`, `Medium` o `Low`), `location`, `analysis_summary`, `evidence`. Si registra solo ciò che è sostenuto da prove.

**`standard_checks`**: l'esito delle cinque verifiche standard oltre lo scanner. Una voce per area, in questo ordine e una volta sola: `authentication_authorization`, `secrets`, `transport_cors`, `sql_commands`, `cryptography`.

| Campo | Significato |
|---|---|
| `area` | uno dei cinque identificatori sopra, nessun altro |
| `status` | `confirmed_observation` · `no_observation` · `not_verifiable` |
| `observation_ids` | gli `OBS-xxx` confermati per quell'area; ogni id esiste in `additional_observations` |
| `missing_evidence` | prove mancanti, frasi brevi (al massimo 200 caratteri) |

Regole: `confirmed_observation` richiede almeno un `OBS-xxx`; `no_observation` richiede `observation_ids` e `missing_evidence` vuoti; `not_verifiable` richiede almeno una prova mancante e nessuna osservazione. Per queste verifiche non si creano osservazioni `False Positive` né `Unknown`.

## Regole

- **Valori di `verdict`**: `High`, `Medium`, `Low`, `False Positive`, `Unknown - Needs Review`. Un finding è **confermato** se è `High`, `Medium` o `Low`.
- Ogni segnalazione del report compare **una sola volta** in `findings`, qualunque sia il verdetto.
- **`defect_present`** è obbligatorio in ogni finding: `true` o `false` se il verdetto è `False Positive`, `null` in tutti gli altri casi. Vale `true` solo se il difetto è dimostrato dal codice, non per sospetto.
- **`metadata`** non si scrive nell'analisi: lo script lo aggiunge. **`exposure`** ammette solo i quattro valori sopra; il resto va in `exposure_detail`.
- **`High`, `Medium`, `Low`, `False Positive`**: `analysis_summary`, `evidence` e `gates.g1`, `g2`, `g3`, `g4` tutti non vuoti. Una vulnerabilità confermata ha la catena documentata per intero, come un falso positivo ha le prove per respingerla.
- **`Unknown - Needs Review`**: `analysis_summary` e almeno un elemento in `missing_evidence` che spiega cosa impedisce di chiudere. I cancelli completati riportano comunque la prova; quelli non verificabili possono restare vuoti.
- Le osservazioni confermate (`High`, `Medium`, `Low`) sono candidate valide per `sast-remediation`. Restano separate dai finding e usano gli `id` `OBS-...`.
- **Percorsi**: relativi alla cartella dei sorgenti, con `/`, senza lettera di unità né `..`. La cartella assoluta non è nel file: la indica lo sviluppatore a `sast-remediation`.
- **Segreti**: mai il valore. Descrivi esistenza, posizione e forma.
- **Testi**: i nomi dei campi sono in inglese, i testi liberi in italiano.
- Non aggiungere campi non descritti qui.

## Cosa non contiene

Record grezzi di AppScan, contenuti XML/HTML, dati SCA, blocchi di sorgente, tracce dello scanner, percorsi assoluti, segreti, cronologia, approvazioni, data o ora di esecuzione (l'unica data è quella del report dello scanner, in `metadata`), log.
