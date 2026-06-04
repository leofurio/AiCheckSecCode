# AiCheckSecCode

AiCheckSecCode e un crawler CLI/Web che riceve il link di un repository Git, lo clona in modo temporaneo e ne valuta la qualita in termini di sicurezza e hygiene del progetto.

Il progetto e pensato come base estendibile per controlli lightweight di code review automatica: non sostituisce SAST/DAST professionali, ma aiuta a individuare segnali rapidi di rischio e debito tecnico.

## Funzionalita

- Clonazione di repository remoti Git con clone shallow (`--depth 1`) o scansione di path locali.
- Crawler del filesystem con esclusione di directory pesanti come `.git`, `node_modules`, `vendor`, `target` e ambienti virtuali.
- Controlli di sicurezza:
  - potenziali segreti committati;
  - uso di `eval`, `exec`, `subprocess(..., shell=True)` e pattern simili;
  - URL HTTP non cifrati;
  - assenza di `SECURITY.md`;
  - manifest di dipendenze senza configurazione di dependency scanning nota;
  - dipendenze dirette non pinnate e versioni legacy sotto soglie di sicurezza curate;
  - TLS verification disabilitata, deserializzazione unsafe, primitive crittografiche deboli, CORS wildcard e sink di command injection;
  - Dockerfile/container senza utente non-root, immagini `latest` o script installati via `curl | sh`.
- Controlli di hygiene:
  - assenza di README, licenza, `.gitignore`, test o CI;
  - assenza di lock file per manifest comuni;
  - file troppo grandi esclusi dalla scansione;
  - marker `TODO`, `FIXME` o `HACK`.
- Output in formato testo o JSON.
- Esportazione Excel `.xlsx` con dettaglio dei controlli eseguiti, stato e findings.
- Interfaccia web locale con report navigabile e file Excel scaricabile dal browser.
- Score finale 0-100 e supporto `--fail-under` per pipeline CI.

## Installazione in sviluppo

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


## Deploy su Vercel

Il progetto include `api/index.py` e `vercel.json` per eseguire la UI web come Python Serverless Function su Vercel. Su Vercel non serve uno start command: la piattaforma invoca direttamente la classe `handler` in `api/index.py`.

Impostazioni consigliate su Vercel:

- Framework Preset: `Other`;
- Build Command: lascia vuoto oppure usa `python -m pip install -e .` se vuoi forzare l'installazione del package;
- Output Directory: lascia vuoto;
- Install Command: default di Vercel.

Per Render continua invece a usare uno start command long-running, ad esempio:

```bash
aicheckseccode-web --host 0.0.0.0 --port $PORT
```

Nota: i report scaricabili generati su Vercel vengono salvati nello storage temporaneo `/tmp` della funzione serverless, quindi possono scadere o non essere disponibili dopo cold start/nuove istanze.

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
- I segreti rilevati devono essere ruotati: rimuoverli dal codice non basta se sono gia entrati nella history Git.
- La scansione non esegue codice del repository target.
- Su Vercel, i file Excel/JSON nel download scadono al termine dell'istanza serverless — scaricarli subito dopo l'audit.
