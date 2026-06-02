# AiCheckSecCode

AiCheckSecCode è un crawler CLI che riceve il link di un repository Git, lo clona in modo temporaneo e ne valuta la qualità in termini di **sicurezza** e **hygiene** del progetto.

Il progetto è pensato come base estendibile per controlli lightweight di code review automatica: non sostituisce SAST/DAST professionali, ma aiuta a individuare segnali rapidi di rischio e debito tecnico.

## Funzionalità

- Clonazione di repository remoti Git con clone shallow (`--depth 1`) o scansione di path locali.
- Crawler del filesystem con esclusione di directory pesanti come `.git`, `node_modules`, `vendor`, `target` e ambienti virtuali.
- Controlli di sicurezza:
  - potenziali segreti committati;
  - uso di `eval`, `exec`, `subprocess(..., shell=True)` e pattern simili;
  - URL HTTP non cifrati;
  - assenza di `SECURITY.md`;
  - manifest di dipendenze senza configurazione di dependency scanning nota.
- Controlli di hygiene:
  - assenza di README, licenza, `.gitignore`, test o CI;
  - assenza di lock file per manifest comuni;
  - file troppo grandi esclusi dalla scansione;
  - marker `TODO`, `FIXME` o `HACK`.
- Output in formato testo o JSON.
- Score finale 0-100 e supporto `--fail-under` per pipeline CI.

## Installazione in sviluppo

```bash
python -m pip install -e .
```

## Uso

```bash
aicheckseccode https://github.com/owner/repo.git
```

Output JSON:

```bash
aicheckseccode https://github.com/owner/repo.git --format json
```

Uso in CI con soglia minima:

```bash
aicheckseccode https://github.com/owner/repo.git --fail-under 80
```

Scansione di una repository locale:

```bash
aicheckseccode /path/to/repository --format text
```

## Estendere le regole

Le regole sono centralizzate in `src/aicheckseccode/rules.py`. Per aggiungere un nuovo controllo:

1. aggiungi una funzione privata nella classe `RuleEngine` oppure un nuovo pattern;
2. restituisci uno o più oggetti `Finding`;
3. copri il comportamento con test in `tests/`.

## Limiti

- I controlli sono euristici e possono generare falsi positivi o falsi negativi.
- I segreti rilevati devono essere ruotati: rimuoverli dal codice non basta se sono già entrati nella history Git.
- La scansione non esegue codice del repository target.
