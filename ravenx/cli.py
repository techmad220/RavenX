
from __future__ import annotations
import argparse, os, asyncio, json, yaml
from rich.console import Console
from .policy import Scope
from .crawl import Crawler
from .report import render_markdown
from .summary import write_summary
from .param_miner import run_param_miner
from .triage import llm_triage
from .llm_panel import run_panel_votes, run_panel_sequential, panel_suggest_params
from .poc_crosscheck import crosscheck
from .evidence import screenshot
from .exporters.github import export_github
from .exporters.jira import export_jira
from .exporters.slack import send_slack_highlights
from .exporters.h1_submit import submit_findings
from .h1 import H1Client, policy_disallows_scanners
from .models import Finding
from .observability import init_observability
from .plugins_loader import discover_plugins
from .review import enqueue as review_enqueue
from .subenum import base_domains, wordlist_from_file, enumerate_subdomains
from .ct_feed import load_ct_seeds

console = Console()

def load_cfg(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def main():
    init_observability()
    ap = argparse.ArgumentParser("ravenx", description="AI-powered H1 research (authorized-only).")
    ap.add_argument("--targets", required=True, help="file with seed URLs")
    ap.add_argument("--output", default="out")
    ap.add_argument("--config", default="configs/ravenx.yaml")
    ap.add_argument("--attest-authorized", default="no", choices=["yes","no"])
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--enable-param-miner", action="store_true")
    ap.add_argument("--llm-triage", action="store_true")
    ap.add_argument("--ollama-host", default="http://localhost:11434")
    ap.add_argument("--model-bias", default="oss-20b,glm-4.5,deepseek")
    ap.add_argument("--openai-base-url", default=None)
    ap.add_argument("--openai-model", default=None)
    ap.add_argument("--browser-crawl", action="store_true")
    ap.add_argument("--llm-panel", action="store_true", help="Run ensemble voting across multiple LLMs")
    ap.add_argument("--panel-agree", type=int, default=None, help="Votes needed to adopt higher severity")
    ap.add_argument("--panel-mode", default="sequential", choices=["sequential","votes"], help="Panel style: turn-taking or independent votes")
    ap.add_argument("--poc-crosscheck", action="store_true", help="Generate PoCs with two coder models and cross-verify")
    ap.add_argument("--coder-models", default="codellama:13b-instruct,mistral-coder:7b", help="Comma-separated coder models (Ollama names) in order")
    ap.add_argument("--panel-propose", action="store_true", help="Use panel to propose extra param keys and re-run miner")
    ap.add_argument("--auth-flow", default=None)
    ap.add_argument("--export-github", default=None)
    ap.add_argument("--export-min-sev", default="medium")
    ap.add_argument("--jira-base", default=None)
    ap.add_argument("--jira-project", default=None)
    ap.add_argument("--jira-email", default=None)
    ap.add_argument("--jira-token", default=None)
    ap.add_argument("--slack-webhook", default=None)
    # HackerOne
    ap.add_argument("--h1-username", default=None)
    ap.add_argument("--h1-token", default=None)
    ap.add_argument("--h1-program", default=None)
    ap.add_argument("--h1-auto-scope", action="store_true")
    ap.add_argument("--h1-submit", action="store_true")
    ap.add_argument("--h1-dry-run", action="store_true")
    ap.add_argument("--h1-min-sev", default="medium")
    ap.add_argument("--subenum", action="store_true")
    ap.add_argument("--subenum-wordlist", default="configs/subenum_words.txt")
    ap.add_argument("--ct-seeds", default=None)
    ap.add_argument("--review-queue", action="store_true")
    ap.add_argument("--review-db", default="out/review.db")
    ap.add_argument("--submit-approved", action="store_true")
    ap.add_argument("--attest-post", default="no", choices=["yes","no"], help="Allow POST-based checks if 'yes'")

    args = ap.parse_args()
    os.makedirs(args.output, exist_ok=True)
    if args.attest_authorized != "yes":
        console.print("[red]Refusing to run: you must pass --attest-authorized yes and only test assets you are allowed to test.[/red]")
        raise SystemExit(2)

    cfg = load_cfg(args.config) if os.path.exists(args.config) else {}
    scope = Scope.from_config(args.targets, cfg)
    # Subdomain enumeration (optional)
    if args.subenum:
        bases = base_domains(scope.seeds)
        words = wordlist_from_file(args.subenum_wordlist)
        subs = enumerate_subdomains(bases, words)
        for h in subs:
            scope.allowed_hosts.add(h)
            scope.seeds.append('https://' + h)
        console.print(f"[green]Subenum added {len(subs)} hosts to seeds.[/green]")
    # CT seeds intake (optional)
    if args.ct_seeds:
        ct_domains = load_ct_seeds(args.ct_seeds)
        for d in ct_domains:
            host = d if '://' not in d else d.split('://',1)[1]
            scope.allowed_hosts.add(host)
            scope.seeds.append('https://' + host)
        console.print(f"[green]CT seeds added {len(ct_domains)} hosts to seeds.[/green]")

    # H1 policy + scope sync
    h1_cfg = cfg.get("h1", {})
    h1_username = args.h1_username or h1_cfg.get("username")
    h1_token = args.h1_token or h1_cfg.get("token")
    h1_program = args.h1_program or h1_cfg.get("program_handle")
    h1_auto_scope = args.h1_auto_scope or bool(h1_cfg.get("auto_scope", False))

    h1_client = None
    h1_scopes = []
    if h1_username and h1_token and h1_program:
        h1_client = H1Client(h1_username, h1_token)
        prog = h1_client.get_program(h1_program)
        policy = (prog.get("data",{}).get("attributes",{}) or {}).get("policy","")
        if policy_disallows_scanners(policy):
            console.print("[red]Program policy disallows automated scanning. Aborting.[/red]")
            raise SystemExit(3)
        if h1_auto_scope:
            h1_scopes = h1_client.get_structured_scopes(h1_program)
            allowed_hosts = []
            for s in h1_scopes:
                a = s.get("attributes") or {}
                if not a.get("eligible_for_submission", True): continue
                atype = (a.get("asset_type") or "").lower()
                ident = (a.get("asset_identifier") or "")
                if atype in ("url","website","wildcard","other") and ident:
                    allowed_hosts.append(ident)
            if allowed_hosts:
                scope.allowed_hosts.update(ah.lower() for ah in allowed_hosts)
                console.print(f"[green]H1 scope synced ({len(allowed_hosts)} assets).[/green]")

    async def run():
        per_host_qps = float(cfg.get('per_host_rate', 2.0))
        max_pages_per_host = int(cfg.get('max_pages_per_host', 150))
        time_budget_sec = int(cfg.get('time_budget_sec', 600))
        crawler = Crawler(scope, concurrency=args.concurrency, per_host_qps=per_host_qps, max_pages_per_host=max_pages_per_host, time_budget_sec=time_budget_sec)
        # Extend checks from plugins
        try:
            for factory in plugins.check_factories:
                crawler.checks.append(factory())
        except Exception as e:
            console.print(f"[yellow][plugin] failed to add checks: {e}[/yellow]")

        try:
            await crawler.crawl()
            findings = []  # will collect below
            # Save initial crawl findings
            findings = await crawler.crawl()
        finally:
            await crawler.close()

        # Param miner (optional)
        if args.enable_param_miner:
            wordlist = cfg.get("param_miner",{}).get("wordlist", ["q","s","search","id","page","lang","debug","callback","redirect","url"])
            wl_file = cfg.get("param_miner_wordlist_file")
            from .param_miner import load_wordlist
            wordlist = load_wordlist(wordlist, wl_file)
            # Panel propose step
            if args.panel_propose or bool(cfg.get("panel_propose", False)):
                bias = [x.strip() for x in (args.model_bias or "").split(",") if x.strip()]
                panel_cfg = cfg.get("llm_panel", {})
                agree = int(args.panel_agree or panel_cfg.get("agree", 2))
                models = panel_cfg.get("models", [])
                extra = panel_suggest_params(list(set(crawler.visited)), bias, args.ollama_host, models)
                wordlist = list(dict.fromkeys(wordlist + extra))
            max_params = int(cfg.get("param_miner",{}).get("max_params_per_host", 40))
            pm = await run_param_miner(crawler.client, list(set(crawler.visited)), max_params, wordlist)  # type: ignore
            findings.extend(pm.values())

        # Evidence screenshots (best-effort)
        evdir = os.path.join(args.output, "evidence")
        for f in findings[:30]:
            try:
                await screenshot(f.url, evdir, f.fingerprint)
            except Exception:
                pass

        # Write report
        with open(os.path.join(args.output, "report.json"), "w", encoding="utf-8") as f:
            json.dump([fi.to_dict() for fi in findings], f, indent=2)
        with open(os.path.join(args.output, "report.md"), "w", encoding="utf-8") as f:
            f.write(render_markdown(findings))
        write_summary(findings, os.path.join(args.output, "summary.md"))

        # LLM triage
        if args.llm_triage:
            bias = [x.strip() for x in (args.model_bias or "").split(",") if x.strip()]
            openai_cfg = cfg.get("openai", {})
            openai_base_url = args.openai_base_url or openai_cfg.get("base_url")
            openai_model = args.openai_model or openai_cfg.get("model")
            # triage pre-hooks
            for hook in plugins.triage_pre:
                try:
                    findings = hook(findings)
                except Exception as e:
                    console.print(f"[yellow][plugin] triage_pre failed: {e}[/yellow]")
            triaged = llm_triage(findings, bias, args.ollama_host, openai_base_url=openai_base_url, openai_model=openai_model)
            for hook in plugins.triage_post:
                try:
                    triaged = hook(triaged)
                except Exception as e:
                    console.print(f"[yellow][plugin] triage_post failed: {e}[/yellow]")
            with open(os.path.join(args.output, "triaged.json"), "w", encoding="utf-8") as f:
                json.dump(triaged, f, indent=2)
            # Slack alert for HIGH/CRITICAL (optional)
            if args.slack_webhook:
                pass  # Slack webhook logic placeholder
            # Panel ensemble (if enabled)
            if args.llm_panel or (cfg.get('llm_panel',{}).get('enable', False)):
                panel_cfg = cfg.get('llm_panel',{})
                agree = args.panel_agree or int(panel_cfg.get('agree', 2))
                models = panel_cfg.get('models', [])
                if (args.panel_mode or 'sequential') == 'sequential':
                    panel = run_panel_sequential([Finding.from_dict(x['finding']) if isinstance(x, dict) and x.get('finding') else x for x in triaged], bias, args.ollama_host, models)
                else:
                    panel = run_panel_votes([Finding.from_dict(x['finding']) if isinstance(x, dict) and x.get('finding') else x for x in triaged], bias, args.ollama_host, models, agree=agree, openai_fallback=(openai_base_url, openai_model) if openai_base_url and openai_model else None)
                import json as _json
                with open(os.path.join(args.output, 'panel.json'), 'w', encoding='utf-8') as pf:
                    _json.dump(panel, pf, indent=2)
                # Build triaged_panel.json by replacing severities with panel decision when higher
                triaged_panel = []
                for p in panel:
                    fdict = p.get('finding')
                    dec = (p.get('panel') or {}).get('decision')
                    if fdict and dec:
                        fdict['severity'] = dec
                        triaged_panel.append({'provider':'panel', 'finding': fdict})
                with open(os.path.join(args.output, 'triaged_panel.json'), 'w', encoding='utf-8') as tf:
                    _json.dump(triaged_panel, tf, indent=2)
            # Slack alert for HIGH/CRITICAL (optional)
            if args.slack_webhook:
                try:
                    send_slack_highlights(args.slack_webhook, triaged)
                except Exception:
                    pass
        else:
            triaged = [{"provider":"rule","finding": fi.to_dict()} for fi in findings]

        # Review queue
        if args.review_queue:
            os.environ['RAVENX_REVIEW_DB'] = args.review_db
            review_enqueue(triaged)
            console.print(f"[yellow]Queued {len(triaged)} items for manual review in {args.review_db}. Serve with: uvicorn ravenx.review:app --port 8090[/yellow]")

        # GitHub export
        if args.export_github and os.getenv("GITHUB_TOKEN"):
            created = export_github(findings, args.export_github, os.getenv("GITHUB_TOKEN"), args.export_min_sev)  # type: ignore
            console.print(f"[cyan]Exported {created} findings to GitHub issues in {args.export_github}[/cyan]")

        # Jira export
        if args.jira_base and args.jira_project and args.jira_email and args.jira_token:
            created = export_jira(findings, args.jira_base, args.jira_project, args.jira_email, args.jira_token, args.export_min_sev)
            console.print(f"[cyan]Exported {created} findings to Jira project {args.jira_project}[/cyan]")

        # H1 submit
        if h1_client and (args.h1_submit or h1_cfg.get("submit", False)):
            dry = args.h1_dry_run or h1_cfg.get("dry_run", True)
            weaknesses = []
            try: weaknesses = h1_client.list_weaknesses(h1_program)  # type: ignore
            except Exception: pass
            pack = [Finding.from_dict(x["finding"]) if isinstance(x, dict) and x.get("finding") else x for x in triaged]  # type: ignore
            results = submit_findings(h1_client, h1_program, pack, h1_scopes, weaknesses, attachments_dir=evdir, min_sev=(args.h1_min_sev or h1_cfg.get("min_severity","medium")), dry_run=dry)  # type: ignore
            with open(os.path.join(args.output, "h1_submit.json"), "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)



# Submit approved items (if requested)
if args.submit_approved and h1_client:
    # Read approved items from DB
    import sqlite3, json as _json
    os.environ['RAVENX_REVIEW_DB'] = args.review_db
    c = sqlite3.connect(args.review_db)
    rows = c.execute("SELECT payload FROM queue WHERE approved=1 AND rejected=0").fetchall()
    c.close()
    approved = [ _json.loads(r[0]) for r in rows ]
    pack = [Finding.from_dict(x["finding"]) if isinstance(x, dict) and x.get("finding") else x for x in approved]  # type: ignore
    weaknesses = []
    try: weaknesses = h1_client.list_weaknesses(h1_program)  # type: ignore
    except Exception: pass
    results = submit_findings(h1_client, h1_program, pack, h1_scopes, weaknesses, attachments_dir=evdir, min_sev=(args.h1_min_sev or h1_cfg.get("min_severity","medium")), dry_run=False)  # type: ignore
    with open(os.path.join(args.output, "h1_submit_approved.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    console.print("[green]Submitted approved items to HackerOne.[/green]")
    asyncio.run(run())

if __name__ == "__main__":
    main()
