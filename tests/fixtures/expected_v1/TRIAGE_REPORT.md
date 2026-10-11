# Report di triage SAST

## Contesto

- Progetto: `demo`
- Report scanner: `report.csv` (2026-01-15)
- Versione toolkit: `1.0.0`
- Stack: C# .NET Framework 4.8; ASP.NET MVC
- Esposizione: Internet — Portale ordini pubblicato su IIS
- Rilascio: Pacchetto Web Deploy
- Vincoli: Nessuno
- Assunzioni: Esposizione Internet senza controlli a monte dichiarati.

## Riepilogo

| Verdetto | Finding |
|---|---|
| `High` | 1 |
| `Medium` | 1 |
| `Low` | 0 |
| `False Positive` | 2 |
| `Unknown - Needs Review` | 1 |
| Totale | 5 |

- Gravità dello scanner: Critical 0 · High 3 · Medium 1 · Low 1 · Informational 0
- Falsi positivi con difetto presente: 1
- Osservazioni aggiuntive confermate: 2

## Finding confermati

### `AS-001` · SQL Injection
- Verdetto: `High` · Scanner: `High`
- Posizione: `Src/Demo.Shop/Persistence/OrderRepository.cs:17`
- Sintesi: Il termine di ricerca arriva dalla query string e finisce nel testo SQL tramite string.Format: SQL injection raggiungibile senza autenticazione.

### `AS-003` · Weak cipher algorithm detected
- Verdetto: `Medium` · Scanner: `Medium`
- Posizione: `Src/Demo.Shop/Infrastructure/Crypto.cs:9`
- Sintesi: Crypto usa DES, algoritmo debole; la chiave è fornita dal chiamante. Impatto parziale: serve l'accesso ai dati cifrati.

## Falsi positivi

### `AS-002` · SQL Injection
- Verdetto: `False Positive` · Scanner: `High`
- Posizione: `Src/Demo.Shop/Persistence/OrderRepository.cs:28`
- Sintesi: Il valore inserito con string.Format è un intero: nessuna iniezione possibile. Resta un difetto reale (SQL composto a mano) senza impatto di sicurezza; lo scanner segnala lo schema string.Format su CommandText.
- Nota: Difetto presente, nessun impatto di sicurezza.

### `AS-005` · Throwing generic exceptions in C#
- Verdetto: `False Positive` · Scanner: `Low`
- Posizione: `Src/Demo.Shop/Services/ReportService.cs:11`
- Sintesi: L'eccezione generica ha un messaggio statico e non espone dati; lo scanner segnala l'uso del tipo Exception.

## Da verificare

### `AS-004` · Debug mode enabled in ASP.NET project configuration
- Verdetto: `Unknown - Needs Review` · Scanner: `High`
- Posizione: `Src/Demo.Shop/Web.config:4`
- Sintesi: Web.config ha debug=true, ma non c'è una trasformazione di rilascio: il valore effettivo in esercizio non è noto.
- Prove mancanti: Manca la trasformazione di configurazione usata per il rilascio (Web.Release.config).

## Verifiche standard oltre lo scanner

| Area | Esito | Dettaglio |
|---|---|---|
| Autenticazione e autorizzazione degli endpoint esposti | Non verificabile | Configurazione IIS di esercizio non disponibile. |
| Segreti nel codice e nella configurazione | Nessuna osservazione | — |
| Sicurezza del trasporto e CORS | Osservazione confermata | `OBS-001` |
| Esecuzione di SQL o comandi con dati non fidati o di origine esterna | Nessuna osservazione | — |
| Crittografia, chiavi e IV | Nessuna osservazione | — |

## Osservazioni aggiuntive

### `OBS-001` · Nessun redirect da HTTP a HTTPS
- Verdetto: `Low`
- Posizione: `Src/Demo.Shop/Web.config:9`
- Sintesi: Le regole di rewrite sono vuote: la configurazione del sito non forza HTTPS.

### `OBS-002` · Path traversal nel download dei report
- Verdetto: `High`
- Posizione: `Src/Demo.Shop/Web/ReportController.cs:13`
- Sintesi: Security review: il nome del file arriva dalla richiesta e viene unito alla cartella dei report senza controlli, permettendo la lettura di file arbitrari.
