# Piano di triage

## Input
- Progetto: `demo`
- Report scanner: `report.csv` (2026-01-15)
- Sorgenti: file del report trovati 5 su 5
- XML: 5 finding abbinati su 5
- SCA: non fornito

## Contesto
- Stack: C# .NET Framework 4.8; ASP.NET MVC
- Esposizione: Internet — Portale ordini pubblicato su IIS
- Rilascio: Pacchetto Web Deploy
- Vincoli: Nessuno
- Assunzioni: Esposizione Internet senza controlli a monte dichiarati.

## Scanner
- Finding: 5
- Gravità: Critical 0 · High 3 · Medium 1 · Low 1 · Informational 0

## Gruppi di analisi
| Gruppo | Finding | ID | Motivo |
|---|---|---|---|
| SQL Injection | 2 | AS-001, AS-002 | Stesso repository: verificare se il flusso dei dati è lo stesso |
| Crittografia debole | 1 | AS-003 | Algoritmo e chiave effettivi a runtime da verificare |
| Configurazione di debug | 1 | AS-004 | Verificare la configurazione effettiva di rilascio |
| Gestione degli errori | 1 | AS-005 | Eccezione generica: verificare dove finisce il messaggio |

Raggruppamento provvisorio: un'istanza che differisce si analizza a parte.

## Verifiche standard oltre lo scanner
Autenticazione e autorizzazione degli endpoint esposti · Segreti nel codice e nella configurazione · Sicurezza del trasporto e CORS · Esecuzione di SQL o comandi con dati non fidati o di origine esterna · Crittografia, chiavi e IV

Dopo i finding. Non è un audit generale: producono solo osservazioni `OBS` confermate, separate dai finding.

## Controlli trasversali
- Verificare le trasformazioni di Web.config usate per il rilascio

## Punti aperti
Nessuno.

## Approvazione
Il piano non anticipa verdetti. Approvi il piano, vuoi modifiche o annulli?
