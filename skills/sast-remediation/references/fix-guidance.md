# Guida alla preparazione di un fix

Principi generici per Claude. Il triage ha stabilito **che** il problema è reale; qui si stabilisce **come** correggerlo in sicurezza. Non si rifà il triage.

## Prima di progettare

- Riapri le prove del triage e il sorgente attuale: le prove non bastano per progettare il fix.
- Trova la **causa radice**, non solo la riga segnalata. Cerca le altre occorrenze dello stesso schema nel perimetro del finding.
- Guarda chiamanti, lettori e configurazione solo quanto serve al fix. Fai domande **solo** su ciò che il codice non può dire in modo affidabile (per esempio chi scrive un dato in un altro prodotto).
- Rispetta `context.constraints` (compatibilità, runtime, parti da non toccare) e `context.release_model`.

## Come correggere

- Correggi la causa radice con **la modifica più piccola che sia sicura**.
- Mantieni il comportamento pubblico, a meno che la correzione di sicurezza non richieda di cambiarlo: in quel caso dichiaralo nel piano.
- Nessun refactoring non collegato, nessun cambio di stile, nessuna pulizia "già che ci sei".
- Usa solo ciò che il progetto già offre (versione del linguaggio, librerie presenti). Una nuova dipendenza va dichiarata e motivata nel piano.

## Segreti

- Un segreto non si sostituisce mai con un altro segreto scritto nel codice, e **non si inventano credenziali sostitutive**. Il segreto va spostato dove il progetto già gestisce i segreti, oppure si usa un'API o un meccanismo di configurazione; se serve un valore esterno, nel codice resta un segnaposto sicuro e il passo operativo va in «Passi fuori dal codice».
- **Rotazione o revoca**: un valore già esposto va considerato compromesso. Rotazione e revoca sono passi operativi separati dal codice: segnalali nel piano e nella verifica.
- **Mai il valore** di un segreto esistente in un `.diff`, in un `.proposto`, in Markdown, in JSON, nei nomi dei file, nei metadati, in chat o nella console.
- **Segreti in memoria**: dove possibile non convertirli in stringhe immutabili in chiaro. Se un'API della piattaforma richiede una conversione temporanea in chiaro o in memoria non gestita, libera o azzera quella memoria con il meccanismo previsto dalla piattaforma. Non prescrivere schemi di pulizia non sicuri.

## Formati cifrati o codificati che cambiano

Quando una modifica cambia il formato di un valore cifrato o codificato (prefisso, lunghezza, codifica, algoritmo), `changes_data_format` è `true` e la verifica deve coprire:

- **chi scrive** il valore, anche in altri prodotti o componenti;
- **chi lo legge**;
- **chi ne valida** lunghezza, formato o prefisso (controlli, colonne con vincoli, schemi);
- la **compatibilità con i valori già salvati**;
- la **migrazione** e il **rollback**.

## Percorsi di compatibilità temporanei

Un percorso che mantiene il vecchio comportamento o formato (`legacy`) è sempre **temporaneo**: va dichiarato in `legacy_paths` con **la condizione in cui va rimosso** (per esempio «quando nessun prodotto scrive più il vecchio formato»). Non esistono percorsi di compatibilità senza scadenza.

## Cosa valutare nel piano

- **Dati e migrazioni**: la modifica cambia il formato di dati già salvati o già cifrati? Serve un passo di migrazione?
- **Rilascio e configurazione**: serve modificare la configurazione di esercizio, non solo il codice?
- **Dipendenze tra fix**: ce ne sono di precedenti o successivi (vedi il piano generale)?
- **Test**: quale test mirato dimostra che il problema è chiuso e che il comportamento utile resta?
- **Rollback**: come si torna indietro se qualcosa va storto?

## Consegna delle modifiche, file per file

- I sorgenti restano in sola lettura. Lavora su copie dei **soli** file coinvolti, fuori dalla cartella dei sorgenti; tutto ciò che produci sta in `sast-output/remediation/fixes/<ID>/`.
- Ogni file ha **una sola** consegna, valutata da solo:
  - **diff**: patch con percorsi relativi, che non richiede Git;
  - **proposto**: se il diff riporterebbe un segreto già presente nell'originale (anche solo nel contesto) ma una versione sicura si può produrre, il file `<nome-originale>.proposto` nella cartella del fix, con percorso e SHA-256 dell'originale. È una «Sostituzione proposta, non applicata automaticamente»;
  - **istruzioni**: se neanche la proposta è sicura, istruzioni **a parole**, senza il valore.
- Un segreto in un file **non** impedisce i diff degli altri file della stessa correzione.
- Generare un diff o una proposta non significa che la modifica sia stata applicata.

## Comandi di verifica

- Indica solo comandi di compilazione o di test che si deducono ragionevolmente dal progetto, etichettati come **dedotti**. Se non puoi dedurli, scrivi «da definire» e cosa serve: non inventarli.
- Non dichiarare mai che un comando è stato eseguito se non lo è stato davvero.

## Quando fermarsi

- La causa radice è diversa da quella del triage, o il triage sembra sostanzialmente sbagliato: **ferma quel finding**, spiega l'incoerenza e consiglia di rifare il triage con `/sast-triage`. Non cambiare tu il verdetto in silenzio.
- La correzione richiederebbe di uscire dal perimetro approvato: fermati e chiedi.
