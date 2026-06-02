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
python -m pip install -e .
```

## Uso CLI

```bash
aicheckseccode https://github.com/owner/repo.git
```

Output JSON:

```bash
aicheckseccode https://github.com/owner/repo.git --format json
```

Generazione del file Excel con elenco dettagliato dei controlli e risultati:

```bash
aicheckseccode https://github.com/owner/repo.git --excel report.xlsx
```

Uso in CI con soglia minima e artifact Excel:

```bash
aicheckseccode https://github.com/owner/repo.git --fail-under 80 --excel report.xlsx
```

Scansione di una repository locale:

```bash
aicheckseccode /path/to/repository --format text
```

## Uso Web

Avvia il server locale:

```bash
aicheckseccode-web --host 127.0.0.1 --port 8000
```

Poi apri `http://127.0.0.1:8000`, inserisci il path o l'URL Git del repository e scarica il report Excel generato dalla pagina.

## Estendere le regole

Le regole e il catalogo dei controlli esportati nel report Excel sono centralizzati in `src/aicheckseccode/rules.py`. Per aggiungere un nuovo controllo:

1. aggiungi una funzione privata nella classe `RuleEngine` oppure un nuovo pattern;
2. restituisci uno o piu oggetti `Finding`;
3. copri il comportamento con test in `tests/`.

## Limiti

- I controlli sono euristici e possono generare falsi positivi o falsi negativi.
- Le soglie sulle versioni delle librerie sono curate e conservative: non sostituiscono un feed CVE/SCA aggiornato in tempo reale.
- I segreti rilevati devono essere ruotati: rimuoverli dal codice non basta se sono gia entrati nella history Git.
- La scansione non esegue codice del repository target.
- Questa sessione non puo pubblicare automaticamente il servizio su Internet senza credenziali o accesso a un hosting.
