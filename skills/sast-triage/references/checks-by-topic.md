# Controlli rapidi per argomento

Promemoria dei punti ciechi più comuni. Usa solo le domande pertinenti al finding: servono a stabilire se il problema è reale, non a correggerlo.

**Autenticazione**
- Chi raggiunge la funzione senza autenticarsi?
- Il controllo è applicato davvero sul percorso, o solo dichiarato? Esistono percorsi alternativi?

**Autorizzazione**
- Chi verifica che il chiamante possa operare su *questo* dato, e prima dell'effetto?
- Cosa significa, per il framework, l'assenza di un controllo esplicito?

**SQL e database**
- Il testo del comando contiene dati influenzabili da un attaccante?
- Il testo viene letto da una fonte modificabile? Chi può scriverla?
- I controlli sul testo coprono tutte le forme eseguibili?

**Comandi e processi**
- Quali parti del comando o degli argomenti non sono fidate?
- Passa da una shell o viene avviato direttamente?

**File system**
- Il percorso è composto con dati esterni (`..`, percorsi assoluti, collegamenti)?
- Chi può leggere o scrivere il file?

**Crittografia e segreti**
- Il segreto è nel sorgente, nella configurazione o nel pacchetto?
- Chiave e vettore sono costanti o riutilizzati? Quali algoritmo e modalità sono usati a runtime?
- Descrivi la posizione, non il valore.

**Log ed errori**
- Il valore scritto nel log può contenere ritorni a capo? Qual è il suo tipo reale?
- Dove finisce l'eccezione e cosa contiene il messaggio restituito?

**Rete e API**
- Cosa espone il servizio nella configurazione di *esercizio*?
- Chi lo raggiunge e con quali controlli a monte?

**Configurazione**
- Il valore è quello effettivo nell'ambiente rilasciato? Esistono file diversi per ambiente?
- Qual è il valore predefinito se manca?

**Contenuto del rilascio (G3)**
- Quale file di build o installazione elenca ciò che viene distribuito?
- Il file segnalato è incluso, o solo presente nel repository? Lo script viene davvero eseguito?

**Deserializzazione ed esecuzione dinamica**
- Dati o nomi di tipo arrivano da una fonte non fidata? Il formato permette di scegliere il tipo?
- Codice o espressioni sono valutati a partire da dati esterni?

**Verifiche standard oltre lo scanner** (cinque aree, usa gli argomenti sopra)
1. *Endpoint esposti*: quali metodi sono raggiungibili dall'esterno e quali non hanno alcun controllo di autenticazione o autorizzazione nella configurazione di esercizio?
2. *Segreti*: nei file di configurazione e nei template di rilascio ci sono credenziali in chiaro o cifrate con una chiave nota o presente nel sorgente?
3. *Trasporto e CORS*: in esercizio sono ammessi HTTP in chiaro, verifiche del certificato disattivate o origini CORS senza limite?
4. *SQL e comandi*: il testo eseguito contiene dati non fidati, o è letto da una fonte modificabile?
5. *Crittografia*: algoritmo, modalità, chiave e vettore effettivi a runtime, e dove vivono la chiave e il vettore.
