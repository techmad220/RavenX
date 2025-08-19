
# RavenX (H1-style AI research)

Authorized-only reconnaissance & reporting pipeline with AI triage.

## Quick start
```bash
unzip ravenx-project-prod.zip && cd ravenx-project
./scripts/bootstrap.sh
printf "https://example.com\n" > configs/targets.txt
ravenx --targets configs/targets.txt --attest-authorized yes --enable-param-miner --llm-triage --output out
```

## GLM-4.5 via OpenAI-compatible endpoint
```bash
# example (vLLM/SGLang)
export OPENAI_API_KEY=sk-local123
ravenx --targets configs/targets.txt --attest-authorized yes   --llm-triage --openai-base-url http://localhost:8000/v1 --openai-model glm-4.5   --output out
```

## HackerOne integration
Dry-run submission preview:
```bash
export H1_USER=your_username
export H1_TOKEN=your_api_token
ravenx --targets configs/targets.txt --attest-authorized yes   --llm-triage   --h1-username "$H1_USER" --h1-token "$H1_TOKEN"   --h1-program your_program_handle --h1-auto-scope   --h1-submit --h1-dry-run   --output out
```

## Exporters
- GitHub: `--export-github owner/repo` (needs `GITHUB_TOKEN`)
- Jira: `--jira-base https://your.atlassian.net --jira-project ABC --jira-email you@example.com --jira-token <token>`

## API viewer
```bash
uvicorn ravenx.api.main:app --host 0.0.0.0 --port 8080
```


## Production hardening

### Observability
Set `SENTRY_DSN` (and optional `SENTRY_TRACES`) to enable Sentry.

### Review queue (manual approval before submissions)
Start the queue UI:
```bash
export RAVENX_REVIEW_DB=out/review.db
uvicorn ravenx.review:app --host 0.0.0.0 --port 8090
```
Run a scan with queue enabled:
```bash
ravenx --targets configs/targets.txt --attest-authorized yes   --llm-triage --review-queue --review-db out/review.db   --output out
```
Then submit the **approved** ones:
```bash
ravenx --targets configs/targets.txt --attest-authorized yes   --submit-approved --review-db out/review.db   --h1-username $H1_USER --h1-token $H1_TOKEN --h1-program <handle>   --output out
```

### Crawl bounds
Set in `configs/ravenx.yaml`:
```yaml
per_host_rate: 2.0
max_pages_per_host: 150
time_budget_sec: 600
```


## OAuth/OIDC targeted checks
- **oauth_redirect_uri_external (HIGH):** flags `redirect_uri` pointing to a different host on OAuth/OIDC authorize endpoints (GET-only heuristic).
- **oauth_implicit_flow_enabled (LOW):** notes `response_type=token` (implicit flow) when seen.

## Slack alerts
Provide a Slack **Incoming Webhook** URL and get pings for HIGH/CRITICAL items after triage:
```bash
ravenx --targets configs/targets.txt --attest-authorized yes   --llm-triage --slack-webhook https://hooks.slack.com/services/XXX/YYY/ZZZ   --output out
```

## Bigger param miner wordlist
Edit `configs/param_words.txt` (already populated). It’s auto-loaded when present.


## New Heuristics

### SAML
- **saml_request_param_exposed (MEDIUM):** flags `SAMLRequest` or `SAMLResponse` params in URLs.

### OAuth PKCE
- **oauth_pkce_missing (MEDIUM):** flags OAuth code flows missing `code_challenge` (PKCE).

### Subdomain takeover
- **subdomain_takeover_possible (HIGH):** flags NXDOMAIN hosts or known error signatures suggesting dangling DNS/CNAMEs.


## New checks for leaderboard hunting
- **OAuth PKCE heuristic**: flags authorization requests using `response_type=code` without `code_challenge`, or with non-`S256` method.
- **SAML RelayState open redirect**: flags `RelayState` pointing off-site during SAML flows.
- **SAML GET exposure**: notes `SAMLRequest` via GET (HTTP-Redirect binding).
- **Subdomain takeover probe**: CNAME + body-signature heuristics for unclaimed providers (GitHub Pages, S3, Heroku, Fastly, Vercel, etc.).

> All probes are **GET-only** and scoped to allowed hosts.


## Extra hunting (ultra)
- **CSP weak policy** detection (`unsafe-inline`/`unsafe-eval`).
- **Mixed content** on HTTPS pages.
- **JSONP reflection** detection via `callback` param.
- **OIDC discovery** checks (`/.well-known/openid-configuration`): warn when PKCE S256 not advertised; implicit enabled.
- **Subdomain enumeration**: passive DNS-based, wordlist in `configs/subenum_words.txt`.
- **CT intake**: feed additional hosts via `--ct-seeds path/to/ct_seeds.txt` (one domain per line).
- **Summary**: `out/summary.md` for quick scan stats.

### Subenum usage
```bash
ravenx --targets configs/targets.txt --attest-authorized yes   --subenum --subenum-wordlist configs/subenum_words.txt   --enable-param-miner --llm-triage --output out
```

### CT seeds usage
```bash
# Put discovered hostnames in a file, one per line
ravenx --targets configs/targets.txt --attest-authorized yes   --ct-seeds configs/ct_seeds.txt   --output out
```


## LLM Panel (ensemble voting)
Run multiple models as a panel of experts to vet findings and (optionally) propose extra param keys.

Enable in CLI:
```bash
ravenx --targets configs/targets.txt --attest-authorized yes   --llm-triage --llm-panel --panel-agree 2   --openai-base-url http://localhost:8000/v1 --openai-model glm-4.5   --output out
```
Outputs:
- `out/panel.json` — raw votes per finding
- `out/triaged_panel.json` — triage adjusted by panel decision

Use panel to propose extra param keys, then re-run miner automatically:
```bash
ravenx --targets configs/targets.txt --attest-authorized yes   --enable-param-miner --panel-propose   --llm-panel --llm-triage   --openai-base-url http://localhost:8000/v1 --openai-model glm-4.5   --output out
```

Configure panel models in `configs/ravenx.yaml` under `llm_panel.models`.


## BOSS 20B slot (alias) + sequential panel
Set **one** mid/large OSS model as your panel's lead ("boss 20b") via env:
```bash
export BOSS20B_MODEL="mixtral:8x7b"   # or any installed Ollama model, e.g., deepseek-coder-v2:16b
```
Run the **sequential** panel (turn‑taking):
```bash
ravenx --targets configs/targets.txt --attest-authorized yes   --llm-triage --llm-panel --panel-mode sequential   --openai-base-url http://localhost:8000/v1 --openai-model glm-4.5   --output out
```
Each model reads prior turns and gives a JSON verdict; we record **turns** and a final **decision**.


## PoC Cross-Check (dual coders)
Enable a **two-coder verification loop**. Each coder independently generates a minimal PoC (URL/cURL only), then cross-validates the other's PoC. A finding is **verified** when classes match, outputs hash-match, or both validations return `valid: true`.

CLI:
```bash
ravenx --targets configs/targets.txt --attest-authorized yes   --llm-triage --llm-panel --panel-mode sequential --panel-agree 2   --poc-crosscheck --coder-models codellama:13b-instruct,mistral-coder:7b   --openai-base-url http://localhost:8000/v1 --openai-model glm-4.5   --output out
```
Artifacts:
- `out/verified_pocs/_index.json` — per-finding cross-check results
- `out/poc_crosscheck.json` — summary counts

## OSS-20B alias
Set your 20B-class OSS model once:
```bash
export OSS20B_MODEL="oss-20b"   # e.g., yi-1.5:20b-q4, mixtral:8x7b, deepseek-coder-v2:16b
```


## Plugin system (drop-in)
RavenX supports **drop-in plugins** from the `plugins/` directory. Each plugin exposes a `register(api)` function.
The `api` object lets you attach new checks, exporters, triage hooks, and CLI args at runtime.

**Create a plugin:**
```
plugins/
  mycheck/
    plugin.py
```

**plugin.py**
```python
from ravenx.checks.base import BaseCheck, CheckContext

def register(api):
  class MyCheck(BaseCheck):
    name = "my_custom_check"
    severity = "medium"
    async def run(self, url, resp, body, ctx: CheckContext):
        # ...your logic...
        return []
  api.register_check(lambda: MyCheck())

  # Optional: add custom CLI args
  # api.register_cli(lambda ap: ap.add_argument("--myflag", action="store_true"))
```

Plugins are discovered automatically at runtime. You don’t have to rebuild—just drop in your `plugin.py`.
