# AiCheckSecCode

AiCheckSecCode è un crawler CLI/Web che riceve il link di un repository Git, lo clona temporaneamente e ne valuta la qualità in termini di sicurezza e hygiene. Il report finale mostra tre sezioni distinte: regole interne, Semgrep e Trivy.

> **Versione corrente:** 0.2.0 — 76 regole built-in

---

## Funzionalità

### Regole interne (76 regole)

**Sicurezza**
- Segreti committati (AWS key, GitHub token, chiavi private, password hardcoded)
- Esecuzione dinamica di codice: `eval`/`exec` in Python, PHP, Ruby; `Function()` in JS; reflection in Java; `Process.Start` in C#; shell in Go
- Iniezione SQL, NoSQL, XPath, LDAP, CRLF, log injection
- Deserializzazione non sicura (`pickle`, `yaml.load`, `ObjectInputStream`, ecc.)
- TLS disabilitato, protocolli SSL/TLS obsoleti (SSLv3, TLS 1.0/1.1)
- Primitive crittografiche deboli (MD5/SHA1, DES, RC4, ECB, chiavi RSA < 2048 bit)
- Password hashate con algoritmi veloci invece di bcrypt/Argon2
- CORS wildcard, CSRF disabilitato, cookie non sicuri (HttpOnly/Secure/SameSite)
- XSS sink (`innerHTML`, `dangerouslySetInnerHTML`, `mark_safe`)
- Path traversal, SSRF, open redirect, template injection lato server
- Prototype pollution, ReDoS
- JWT algorithm `none` o verify disabilitato
- Credenziali di default hardcoded
- Header di sicurezza disabilitati (CSP, HSTS, X-Frame-Options)
- Debug mode abilitato, stack trace esposti, directory listing
- Randomness non crittografica per token/secret/nonce
- Esecuzione di script scaricati da remoto (`curl | bash`)
- Funzioni C/C++ non sicure (`strcpy`, `gets`), format string, `eval` in shell
- Binding su `0.0.0.0`

**Container / IaC / CI**
- Dockerfile: utente root, `ADD` remoto, segreti in `ENV`/`ARG`, immagine `latest`
- Kubernetes: `privileged: true`, `hostNetwork`, `runAsNonRoot: false`, escalation
- Terraform: ACL aperte `0.0.0.0/0`, bucket pubblici, storage non cifrato
- GitHub Actions: `pull_request_target`, action non pinnate (`@master`/`@main`), expression injection

**Dipendenze**
- Dipendenze non pinnate (Python, npm, Ruby, PHP, Java, Go)
- Versioni sotto soglie CVE curate per 50+ librerie comuni
- Lock file mancanti
- Dependency scanner non configurato

**Hygiene**
- README, licenza, `.gitignore`, test, CI mancanti
- File troppo grandi esclusi dalla scansione
- Marker `TODO`/`FIXME`/`HACK`

### Semgrep (automatico se installato)

Analisi statica con le regole ufficiali Semgrep (`--config auto`). Se `semgrep` è nel PATH o installato come dipendenza Python viene eseguito automaticamente e i risultati appaiono nella sezione dedicata del report.

### Trivy (automatico, download se assente)

Scansione di vulnerabilità CVE nelle dipendenze, segreti e misconfigurazioni IaC tramite `trivy fs`. Se il binario non è nel PATH viene scaricato automaticamente da GitHub Releases (~40MB, pinnato a v0.51.4) e cachato in `~/.cache/aicheckseccode/trivy`.

---

## Installazione

```bash
pip install -e .
```

Semgrep viene installato come dipendenza diretta. Trivy viene scaricato automaticamente al primo utilizzo.

---

## Uso CLI

```bash
# Audit base
aicheckseccode https://github.com/owner/repo.git

# Output JSON
aicheckseccode https://github.com/owner/repo.git --format json

# Report Excel
aicheckseccode https://github.com/owner/repo.git --excel report.xlsx

# CI con soglia minima di score
aicheckseccode https://github.com/owner/repo.git --fail-under 80 --excel report.xlsx

# Repository locale
aicheckseccode /path/to/repository --format text
```

---

## Uso Web

```bash
aicheckseccode-web --host 127.0.0.1 --port 8000
```

Apri `http://127.0.0.1:8000`, inserisci l'URL Git o il path locale e ottieni un report con quattro sezioni:

1. **Controls** — stato di tutti i 76 controlli built-in (passed/failed)
2. **Internal rules** — finding delle regole built-in
3. **Semgrep** — finding dall'analisi statica Semgrep
4. **Trivy** — CVE, segreti e misconfigurazioni IaC

---

## Deploy su Vercel

```bash
npx vercel --prod
```

Il progetto include `api/app.py` (Flask WSGI) e `vercel.json` pronti per il deploy. Trivy viene scaricato automaticamente al primo audit; i file Excel sono disponibili per il download nella stessa sessione.

---

## Estendere le regole

Le regole sono in `src/aicheckseccode/rules.py`:

1. Aggiungi un pattern in `_DANGEROUS_CODE_PATTERNS` o `_ENTERPRISE_SECURITY_PATTERNS`
2. Aggiungi la voce corrispondente in `RULE_CATALOG`
3. Scrivi un test in `tests/`

Per integrare nuovi tool esterni, aggiungi una funzione in `src/aicheckseccode/integrations.py` che restituisce `list[Finding]` con `source="nometool"`.

---

## Limiti

- I controlli sono euristici e possono generare falsi positivi o falsi negativi.
- Le soglie sulle versioni delle librerie sono curate e conservative: non sostituiscono un feed CVE/SCA aggiornato in tempo reale.
- I segreti rilevati devono essere ruotati: rimuoverli dal codice non basta se sono già entrati nella history Git.
- La scansione non esegue codice del repository target.
- Su Vercel, i file Excel/JSON nel download scadono al termine dell'istanza serverless — scaricarli subito dopo l'audit.
