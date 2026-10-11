# Terza analisi: security review

Dopo i finding e le cinque verifiche standard, il triage esegue una **security review di tutta la cartella dei sorgenti** con il metodo del comando `/security-review` di Claude Code. Le vulnerabilità confermate diventano osservazioni `OBS`: `triage.json`, report e CSV non cambiano formato.

## Perché il metodo e non il comando

`/security-review` esamina solo il diff tra il branch corrente e `origin/HEAD`, richiede Git con il remote `origin` e per istruzione ignora i problemi già presenti nel codice. Il triage lavora su una cartella di sorgenti completa, anche senza Git. Per questo la skill non invoca il comando: ne applica le istruzioni (categorie, esclusioni, precedenti, punteggio di confidenza, filtro dei falsi positivi con sub-agent), riportate più sotto, con tre adattamenti:

1. **Ambito**: tutta la cartella dei sorgenti del piano approvato, non il diff. I problemi già presenti sono proprio l'oggetto dell'analisi. Si escludono `sast-output`, `.git` e le cartelle di dipendenze o di build (`node_modules`, `bin`, `obj`, `packages`…).
2. **Uscita**: non un report Markdown libero, ma `<triage>/_work/security-review.json` (da `templates/security-review-input.json`) e le `OBS` di `analysis.json`.
3. **Regole del toolkit che prevalgono**: sola lettura; mai il valore di un segreto; prove `file:riga`; il verdetto dell'`OBS` segue la scala di `methodology.md` (la gravità proposta dalla review è solo un input, come quella dello scanner).

Le esclusioni e i precedenti di `/security-review` valgono **solo per questa analisi**: non cambiano la valutazione dei finding dello scanner né le cinque verifiche standard.

## Procedura

1. **Ricerca.** Avvia un sub-agent (strumento Agent) con il prompt della sezione «Method», sostituendo `<SOURCES>` con il percorso assoluto della cartella dei sorgenti. Restituisce le vulnerabilità candidate nel formato richiesto (file, riga, gravità, categoria, descrizione, scenario, raccomandazione).
2. **Filtro dei falsi positivi.** Per ogni candidata avvia un sub-agent, in parallelo, con la sezione «False positive filtering», la candidata e questa regola: «Never write the value of a secret; reply with a confidence score from 1 to 10 and a one-sentence reason».
3. **Soglia.** Le candidate con confidenza minore di 8 sono scartate (`discarded`, con il motivo).
4. **Verifica del toolkit.** Per ogni candidata rimasta riapri tu il sorgente e controlla le prove. Esito:
   - `duplicate`: stesso problema di un finding dello scanner (`AS-xxx`) o di una `OBS` già presente; `ref` è quell'id;
   - `discarded`: non confermata sul sorgente, fuori dal perimetro approvato o coperta dalle esclusioni; `reason` dice perché;
   - `observation`: confermata con prove; diventa una nuova `OBS-xxx` in `additional_observations` e `ref` è il suo id.
5. **Registrazione.** Scrivi `<triage>/_work/security-review.json`: una voce per **ogni** candidata dei passi 1–4, anche scartata; elenco vuoto se la ricerca non trova nulla.

Se lo strumento dei sub-agent non è disponibile, esegui gli stessi passi direttamente, nello stesso ordine e con le stesse istruzioni.

## Regole per le OBS della security review

- Solo vulnerabilità confermate, con verdetto `High`, `Medium` o `Low` secondo `methodology.md`.
- `analysis_summary` inizia con «Security review:»: nel report si riconosce la provenienza senza cambiare formato.
- `area`: se la vulnerabilità rientra in una delle cinque aree standard, indicala e metti l'`OBS` anche in `standard_checks` di quell'area, che diventa `confirmed_observation`: la tabella delle verifiche standard resta coerente con le osservazioni.

  | `area` | Categorie tipiche |
  |---|---|
  | `authentication_authorization` | aggiramento dell'autenticazione, escalation di privilegi, sessioni, JWT, autorizzazione |
  | `secrets` | chiavi API, password o token nel codice |
  | `transport_cors` | verifica dei certificati disattivata, trasporto in chiaro, CORS |
  | `sql_commands` | SQL o NoSQL injection, command injection |
  | `cryptography` | algoritmi deboli, gestione delle chiavi, casualità |
  | vuoto | XSS, XXE, template injection, path traversal, deserializzazione, eval, esposizione di dati, altro |

- Mai duplicare un finding o un'altra `OBS`: in quel caso l'esito è `duplicate`.
- Segreti: esistenza, tipo e posizione, mai il valore. `check_secrets.py` è una rete di sicurezza, non una garanzia.

`build_triage.py --security-review` controlla il file: campi ed esiti validi, riferimenti esistenti, confidenza almeno 8 per le osservazioni, coerenza con `standard_checks`, prefisso «Security review:», e che ogni `OBS` provenga da una verifica standard o dalla security review.

## Method

Prompt for the research sub-agent. Replace `<SOURCES>` with the absolute path of the source folder.

```
You are a senior security engineer conducting a focused security review of the source folder <SOURCES>.

SCOPE:
Review the whole source folder above. Existing code is in scope: this review covers the current state of the code,
not a diff. Skip `sast-output`, `.git` and dependency or build-output folders (for example `node_modules`, `bin`,
`obj`, `packages`). Use only read-only tools (Read, Glob, Grep): do not run commands and do not write files.

OBJECTIVE:
Perform a security-focused code review to identify HIGH-CONFIDENCE security vulnerabilities that could have real
exploitation potential. This is not a general code review - focus ONLY on security implications.

CRITICAL INSTRUCTIONS:
1. MINIMIZE FALSE POSITIVES: Only flag issues where you're >80% confident of actual exploitability
2. AVOID NOISE: Skip theoretical issues, style concerns, or low-impact findings
3. FOCUS ON IMPACT: Prioritize vulnerabilities that could lead to unauthorized access, data breaches, or system compromise
4. EXCLUSIONS: Do NOT report the following issue types:
   - Denial of Service (DOS) vulnerabilities, even if they allow service disruption
   - Secrets or sensitive data stored on disk (these are handled by other processes)
   - Rate limiting or resource exhaustion issues
5. NEVER write the value of a secret (password, key, token): describe only its existence, type and location.

SECURITY CATEGORIES TO EXAMINE:

**Input Validation Vulnerabilities:**
- SQL injection via unsanitized user input
- Command injection in system calls or subprocesses
- XXE injection in XML parsing
- Template injection in templating engines
- NoSQL injection in database queries
- Path traversal in file operations

**Authentication & Authorization Issues:**
- Authentication bypass logic
- Privilege escalation paths
- Session management flaws
- JWT token vulnerabilities
- Authorization logic bypasses

**Crypto & Secrets Management:**
- Hardcoded API keys, passwords, or tokens
- Weak cryptographic algorithms or implementations
- Improper key storage or management
- Cryptographic randomness issues
- Certificate validation bypasses

**Injection & Code Execution:**
- Remote code execution via deseralization
- Pickle injection in Python
- YAML deserialization vulnerabilities
- Eval injection in dynamic code execution
- XSS vulnerabilities in web applications (reflected, stored, DOM-based)

**Data Exposure:**
- Sensitive data logging or storage
- PII handling violations
- API endpoint data leakage
- Debug information exposure

Additional notes:
- Even if something is only exploitable from the local network, it can still be a HIGH severity issue

ANALYSIS METHODOLOGY:

Phase 1 - Repository Context Research (Use file search tools):
- Identify existing security frameworks and libraries in use
- Look for established secure coding patterns in the codebase
- Examine existing sanitization and validation patterns
- Understand the project's security model and threat model

Phase 2 - Comparative Analysis:
- Compare the code against the security patterns established elsewhere in the codebase
- Identify deviations from established secure practices
- Look for inconsistent security implementations
- Flag code that exposes attack surface to untrusted input

Phase 3 - Vulnerability Assessment:
- Examine the source files for security implications, starting from entry points and from code that handles untrusted input
- Trace data flow from user inputs to sensitive operations
- Look for privilege boundaries being crossed unsafely
- Identify injection points and unsafe deserialization

REQUIRED OUTPUT FORMAT:

You MUST output your findings in markdown. The markdown output should contain the file, line number, severity, category (e.g. `sql_injection` or `xss`), description, exploit scenario, and fix recommendation.

For example:

# Vuln 1: XSS: `foo.py:42`

* Severity: High
* Description: User input from `username` parameter is directly interpolated into HTML without escaping, allowing reflected XSS attacks
* Exploit Scenario: Attacker crafts URL like /bar?q=<script>alert(document.cookie)</script> to execute JavaScript in victim's browser, enabling session hijacking or data theft
* Recommendation: Use Flask's escape() function or Jinja2 templates with auto-escaping enabled for all user inputs rendered in HTML

SEVERITY GUIDELINES:
- **HIGH**: Directly exploitable vulnerabilities leading to RCE, data breach, or authentication bypass
- **MEDIUM**: Vulnerabilities requiring specific conditions but with significant impact
- **LOW**: Defense-in-depth issues or lower-impact vulnerabilities

CONFIDENCE SCORING:
- 0.9-1.0: Certain exploit path identified, tested if possible
- 0.8-0.9: Clear vulnerability pattern with known exploitation methods
- 0.7-0.8: Suspicious pattern requiring specific conditions to exploit
- Below 0.7: Don't report (too speculative)

FINAL REMINDER:
Focus on HIGH and MEDIUM findings only. Better to miss some theoretical issues than flood the report with false positives. Each finding should be something a security engineer would confidently raise in a code review.

Your final reply must contain the markdown report and nothing else.
```

## False positive filtering

Prompt for each filtering sub-agent, followed by the candidate (file, line, severity, category, description, exploit scenario).

```
FALSE POSITIVE FILTERING:

> You do not need to run commands to reproduce the vulnerability, just read the code to determine if it is a real vulnerability. Do not use the bash tool or write to any files.
>
> HARD EXCLUSIONS - Automatically exclude findings matching these patterns:
> 1. Denial of Service (DOS) vulnerabilities or resource exhaustion attacks.
> 2. Secrets or credentials stored on disk if they are otherwise secured.
> 3. Rate limiting concerns or service overload scenarios.
> 4. Memory consumption or CPU exhaustion issues.
> 5. Lack of input validation on non-security-critical fields without proven security impact.
> 6. Input sanitization concerns for GitHub Action workflows unless they are clearly triggerable via untrusted input.
> 7. A lack of hardening measures. Code is not expected to implement all security best practices, only flag concrete vulnerabilities.
> 8. Race conditions or timing attacks that are theoretical rather than practical issues. Only report a race condition if it is concretely problematic.
> 9. Vulnerabilities related to outdated third-party libraries. These are managed separately and should not be reported here.
> 10. Memory safety issues such as buffer overflows or use-after-free-vulnerabilities are impossible in rust. Do not report memory safety issues in rust or any other memory safe languages.
> 11. Files that are only unit tests or only used as part of running tests.
> 12. Log spoofing concerns. Outputting un-sanitized user input to logs is not a vulnerability.
> 13. SSRF vulnerabilities that only control the path. SSRF is only a concern if it can control the host or protocol.
> 14. Including user-controlled content in AI system prompts is not a vulnerability.
> 15. Regex injection. Injecting untrusted content into a regex is not a vulnerability.
> 16. Regex DOS concerns.
> 16. Insecure documentation. Do not report any findings in documentation files such as markdown files.
> 17. A lack of audit logs is not a vulnerability.
>
> PRECEDENTS -
> 1. Logging high value secrets in plaintext is a vulnerability. Logging URLs is assumed to be safe.
> 2. UUIDs can be assumed to be unguessable and do not need to be validated.
> 3. Environment variables and CLI flags are trusted values. Attackers are generally not able to modify them in a secure environment. Any attack that relies on controlling an environment variable is invalid.
> 4. Resource management issues such as memory or file descriptor leaks are not valid.
> 5. Subtle or low impact web vulnerabilities such as tabnabbing, XS-Leaks, prototype pollution, and open redirects should not be reported unless they are extremely high confidence.
> 6. React and Angular are generally secure against XSS. These frameworks do not need to sanitize or escape user input unless it is using dangerouslySetInnerHTML, bypassSecurityTrustHtml, or similar methods. Do not report XSS vulnerabilities in React or Angular components or tsx files unless they are using unsafe methods.
> 7. Most vulnerabilities in github action workflows are not exploitable in practice. Before validating a github action workflow vulnerability ensure it is concrete and has a very specific attack path.
> 8. A lack of permission checking or authentication in client-side JS/TS code is not a vulnerability. Client-side code is not trusted and does not need to implement these checks, they are handled on the server-side. The same applies to all flows that send untrusted data to the backend, the backend is responsible for validating and sanitizing all inputs.
> 9. Only include MEDIUM findings if they are obvious and concrete issues.
> 10. Most vulnerabilities in ipython notebooks (*.ipynb files) are not exploitable in practice. Before validating a notebook vulnerability ensure it is concrete and has a very specific attack path where untrusted input can trigger the vulnerability.
> 11. Logging non-PII data is not a vulnerability even if the data may be sensitive. Only report logging vulnerabilities if they expose sensitive information such as secrets, passwords, or personally identifiable information (PII).
> 12. Command injection vulnerabilities in shell scripts are generally not exploitable in practice since shell scripts generally do not run with untrusted user input. Only report command injection vulnerabilities in shell scripts if they are concrete and have a very specific attack path for untrusted input.
>
> SIGNAL QUALITY CRITERIA - For remaining findings, assess:
> 1. Is there a concrete, exploitable vulnerability with a clear attack path?
> 2. Does this represent a real security risk vs theoretical best practice?
> 3. Are there specific code locations and reproduction steps?
> 4. Would this finding be actionable for a security team?
>
> For each finding, assign a confidence score from 1-10:
> - 1-3: Low confidence, likely false positive or noise
> - 4-6: Medium confidence, needs investigation
> - 7-10: High confidence, likely true vulnerability
```

## Origine e licenza

Le sezioni «Method» e «False positive filtering» vengono da `.claude/commands/security-review.md` del repository [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review), la versione pubblica e personalizzabile del comando `/security-review` di Claude Code (copia del 2026-10-11). «False positive filtering» è invariata. «Method» ha questi adattamenti: ambito (cartella dei sorgenti invece del diff, quindi anche il codice esistente, con la sezione SCOPE al posto di stato, commit e diff di Git), uso dei soli strumenti in lettura, divieto di scrivere valori segreti (istruzione 5), fasi 2 e 3 riferite al codice invece che alle modifiche, «code review» invece di «PR review». Le istruzioni di orchestrazione (sub-agent di ricerca, filtro in parallelo, soglia 8) sono nella «Procedura».

```
MIT License

Copyright (c) 2025 Anthropic

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
