# Intake

Chiedi il minimo che serve. Prima **ispeziona** (in sola lettura, solo dopo aver ricevuto i percorsi o la scelta di cercare), poi chiedi **solo ciò che non si ricava dai file**, in **una sola chiamata** interattiva (AskUserQuestion) o, se non è disponibile, in **un solo messaggio** in chat con risposte numerate.

## 1. Come indicare i file

Prima domanda, sempre, senza cercare nulla sul disco:

> **Come vuoi indicarmi i file?**
> 1. Cercali tu nella cartella di lavoro
> 2. Li indico io

- **Li indico io**: chiedi in un solo messaggio cartella dei sorgenti, report dello scanner (obbligatorio: CSV AppScan, con XML facoltativo, **oppure** SARIF), SCA (facoltativo). Nessuna ricerca sul disco prima dei percorsi.
- **Cercali tu nella cartella di lavoro**: ricerca in sola lettura solo dentro la cartella di lavoro, mai nelle cartelle superiori. Candidati a scelta:

| Voce | Candidati | Sempre presenti |
|---|---|---|
| Cartella dei sorgenti | cartelle di primo livello plausibili | Altro percorso |
| Report dello scanner | file `.csv` con intestazione AppScan; file `.sarif` (o `.sarif.json`) con `"version": "2.1.0"` e `runs` | Altro percorso |
| Report AppScan XML (facoltativo, solo con il CSV) | file `.xml` con radice `xml-report` | Nessuno · Altro percorso |
| Report SCA (facoltativo) | file `.html` con etichette SCA | Nessuno · Altro percorso |

CSV e SARIF sono alternativi: se lo sviluppatore li indica entrambi, chiedi quale usare.

## 2. Domande di contesto (solo ciò che non si ricava)

| Voce | Quando si chiede | Valori |
|---|---|---|
| Esposizione | se non è nota | `Internet` · `Rete interna` · `Solo locale` · `Non nota` (e un dettaglio libero facoltativo) |
| Vuoi aggiungere altro? | sempre, facoltativa, scelta multipla | Nulla · Vincoli · Baseline · Altro |
| Rilascio | solo se non è ricavabile da progetto, build o distribuzione | installer · pacchetto · container · cartella pubblicata · servizio · altro |

- Con `Non nota` si applica lo scenario peggiore ragionevole, dichiarato nelle assunzioni.
- «Vuoi aggiungere altro?»: chiedi i dettagli **solo** delle voci scelte (vincoli: compatibilità, runtime datato, parti da escludere; baseline: un triage o una scansione precedente, **solo contesto**, mai il verdetto). Con «Nulla» nessuna domanda su vincoli o baseline.
- **Rilascio ricavato**: non chiedere conferma; scrivilo nel contesto come «Rilascio: `<valore>` (rilevato)» e lascia correggere.

## 3. Da ricavare, non da chiedere

Linguaggio, framework e versione, file di progetto e di build, presenza di Git, file di rilascio evidenti, struttura delle cartelle, modalità di rilascio. Se è ambiguo, fai **una sola** domanda di chiarimento.

## 4. Cartella di lavoro

Nessuna domanda. Di default `sast-output/triage`, con `sast-output` **accanto** alla cartella dei sorgenti, mai dentro. Se lo sviluppatore indica un'altra cartella `sast-output`, usala (il triage resta nella sottocartella `triage`).

## 5. Contesto rilevato

Prima del piano mostra, senza verdetti:

```
Contesto rilevato

- Progetto: <nome della cartella dei sorgenti>
- Stack: … (rilevato)
- Esposizione: <Internet | Rete interna | Solo locale | Non nota> [— dettaglio]
- Rilascio: <valore> (rilevato)
- Report AppScan: <file CSV> (<data o «data non disponibile»>)
  oppure, con il SARIF: Report SARIF: <file> (<data o «data non disponibile»>) — <strumento>[; <n> risultati soppressi esclusi]
- XML: fornito / non fornito (con il SARIF: non previsto, le tracce vengono dai codeFlows)
- SCA: fornito / non fornito
- Assunzioni e punti aperti: …
```

Segna «(rilevato)» ciò che hai dedotto. Non chiedere un'approvazione separata: il cancello è il piano.
