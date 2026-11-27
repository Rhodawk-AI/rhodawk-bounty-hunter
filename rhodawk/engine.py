#!/usr/bin/env python3
"""
engine.py — Standalone RhodawkAI Bounty Hunter CLI
Works WITHOUT Claude Code or any AI subscription.

Providers (auto-detected, first available wins):
  FREE:  ollama   — local model, zero cost
                    install: curl -fsSL https://ollama.ai/install.sh | sh
                    then:    ollama pull qwen2.5:14b
         groq     — cloud free tier (fast), set GROQ_API_KEY
                    get key: https://console.groq.com
         deepseek — very cheap cloud,       set DEEPSEEK_API_KEY
                    get key: https://platform.deepseek.com
  PAID:  claude   — set ANTHROPIC_API_KEY
         openai   — set OPENAI_API_KEY
         grok     — set XAI_API_KEY
         openrouter — multi-model gateway, set OPENROUTER_API_KEY
                    get key: https://openrouter.ai/keys
         orcarouter — multi-model gateway, set ORCAROUTER_API_KEY
                    get key: https://www.orcarouter.ai
         litellm    — 100+ provider gateway (SDK), routes by "provider/model"
                    prefix using each provider's own key; or set
                    LITELLM_API_KEY/LITELLM_API_BASE for a LiteLLM proxy
                    docs: https://docs.litellm.ai
         requesty   - multi-model gateway, set REQUESTY_API_KEY
                    get key: https://app.requesty.ai/api-keys
                    docs: https://docs.requesty.ai
         nvidia     — NVIDIA NIM (hosted or self-hosted), set NVIDIA_API_KEY
                    get key: https://build.nvidia.com
                    base URL: NVIDIA_NIM_BASE_URL
                    (default https://integrate.api.nvidia.com/v1)

Usage:
  rhodawk setup                        one-time config wizard
  rhodawk recon  <target>              recon + AI surface analysis
  rhodawk hunt   <target>              full hunt pipeline
  rhodawk validate "<finding>"         7-Question Gate on a finding
  rhodawk report [--findings-dir DIR]  write submission-ready report
  rhodawk chain  [--findings-dir DIR]  build A->B->C exploit chain
  rhodawk triage "<finding>"           fast triage (pass/kill/downgrade)
  rhodawk chat                         interactive Q&A shell
  rhodawk models                       list available models
  rhodawk status                       show hunt status
  rhodawk providers                    show all providers + API key status
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
try:
    from rhodawk._compat import get_env, ensure_home_migrated
    from rhodawk.tools.credentials import redact_env_for_scanners
except ImportError:  # flat / script execution — resolve package dir
    import os as _compat_os, sys as _compat_sys
    _compat_dir = _compat_os.path.abspath(__file__)
    for _ in range(1):
        _compat_dir = _compat_os.path.dirname(_compat_dir)
    if _compat_dir not in _compat_sys.path:
        _compat_sys.path.insert(0, _compat_dir)
    from _compat import get_env, ensure_home_migrated
    try:  # package layout (rhodawk/ on sys.path)
        from tools.credentials import redact_env_for_scanners
    except ImportError:
        from credentials import redact_env_for_scanners

# ── Paths ──────────────────────────────────────────────────────────────────────
HERE     = Path(__file__).resolve().parent  # resolve symlink first so /usr/local/bin/rhodawk -> repo dir
AGENTS   = HERE / "agents"
TOOLS    = HERE / "tools"
# Writable output goes under a user data home, not the install dir, so the tool
# works whether it runs from a git clone or a read-only pip install.
# Override with RHODAWK_HOME; defaults to ~/.rhodawk. The install/source
# directory is deliberately NOT used as a fallback: honoring writability of
# HERE made a plain `pytest` run (and any hunt from a git clone) write
# recon/findings/reports into the source tree, which then leaked into built
# wheels (release audit R-01).
def _data_home():
    import os
    env = get_env("RHODAWK_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".rhodawk"

DATA_HOME = _data_home()
RECON    = DATA_HOME / "recon"
FINDINGS = DATA_HOME / "findings"
REPORTS  = DATA_HOME / "reports"
CONFIG   = Path.home() / ".rhodawk" / "config.json"

# ── Colors ─────────────────────────────────────────────────────────────────────
GREEN  = "\033[0;32m"
CYAN   = "\033[0;36m"
YELLOW = "\033[1;33m"
RED    = "\033[0;31m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
NC     = "\033[0m"


def ok(msg):   print(f"{GREEN}{BOLD}[+]{NC} {msg}")
def info(msg): print(f"{CYAN}{BOLD}[*]{NC} {msg}")
def warn(msg): print(f"{YELLOW}{BOLD}[!]{NC} {msg}")
def err(msg):  print(f"{RED}{BOLD}[-]{NC} {msg}")


def header(title: str):
    width = max(len(title) + 4, 60)
    print(f"\n{BOLD}{'═' * width}{NC}")
    print(f"{BOLD}  {title}{NC}")
    print(f"{BOLD}{'═' * width}{NC}\n")


def load_config() -> dict:
    if CONFIG.exists():
        try:
            return json.loads(CONFIG.read_text())
        except json.JSONDecodeError as e:
            warn(f"Corrupted config file {CONFIG}, using defaults: {e}")
        except OSError as e:
            warn(f"Could not read config file {CONFIG}: {e}")
    return {}


def save_config(cfg: dict):
    # The config can hold API keys. write_text() would create the file under
    # the process umask (often 0o644) and only chmod afterward, leaving a brief
    # world-readable window on a multi-user host. Create it 0o600 from the
    # start (and tighten the dir), then chmod in case it pre-existed.
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG.parent, 0o700)
    except OSError:
        pass
    fd = os.open(str(CONFIG), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(cfg, indent=2))
    os.chmod(CONFIG, 0o600)


COMMAND_ALIASES = {
    "setup": {"setup", "init"},
    "login": {"login", "auth"},
    "providers": {"providers", "p"},
    "models": {"models", "m"},
    "status": {"status", "s"},
    "chat": {"chat", "ask"},
    "recon": {"recon", "r"},
    "hunt": {"hunt", "h"},
    "validate": {"validate", "v"},
    "triage": {"triage", "t"},
    "report": {"report", "rep"},
    "chain": {"chain", "c"},
    "doctor": {"doctor"},
}


def _print_quick_help():
    print(textwrap.dedent("""
    RhodawkAI Bounty Hunter — fast commands

    rhodawk help                 Show full help
    rhodawk setup                Configure your AI provider
    rhodawk recon target.com     Map the attack surface
    rhodawk hunt target.com      Run the full hunt pipeline
    rhodawk validate "finding"   Run the 7-Question Gate
    rhodawk report               Write a submission-ready report
    rhodawk status               Show pipeline status

    Short aliases:
      init=setup   p=providers   m=models   s=status   r=recon
      h=hunt       v=validate    t=triage   rep=report   c=chain
    """).strip())


_KNOWN_COMMANDS = (set().union(*COMMAND_ALIASES.values()) | set(COMMAND_ALIASES)
                   | {"mcp"})


def _normalize_cli_argv(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    # Step 1A shorthand: `rhodawk <target> -recon` / `--recon` is exactly
    # `rhodawk recon <target>`. All later flags forward identically because
    # the rewritten argv flows through the same parser.
    if (len(argv) >= 2 and not argv[0].startswith("-")
            and argv[0] not in _KNOWN_COMMANDS
            and argv[1] in ("-recon", "--recon")):
        argv = ["recon", argv[0], *argv[2:]]
    if argv[0] in {"help", "-help"}:
        return ["--help", *argv[1:]]
    return ["--help" if item == "-help" else item for item in argv]


def load_agent_prompt(agent_name: str) -> str:
    """Read agents/<name>.md, strip YAML frontmatter, return body as system prompt."""
    md = AGENTS / f"{agent_name}.md"
    if not md.exists():
        return ""
    text = md.read_text()
    if text.startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            text = text[end + 3:].lstrip()
    return text.strip()


def _import_brain():
    """Import Brain and LLMClient from brain.py."""
    sys.path.insert(0, str(HERE))
    try:
        from brain import Brain, LLMClient  # noqa: PLC0415
        return Brain, LLMClient
    except ImportError as e:
        err(f"Could not import brain.py: {e}")
        sys.exit(1)


def _configured_model(cfg: dict, provider: str | None) -> str | None:
    """Resolve a model override from env or the per-provider saved config."""
    if os.environ.get("BRAIN_MODEL"):
        return os.environ["BRAIN_MODEL"]
    models = cfg.get("models", {})
    if isinstance(models, dict) and provider:
        return models.get(provider) or None
    return None


def _get_client(provider: str | None = None):
    """Return an LLMClient, applying saved config if no env override."""
    _, LLMClient = _import_brain()
    cfg = load_config()
    provider = provider or os.environ.get("BRAIN_PROVIDER") or cfg.get("provider")
    if provider:
        os.environ["BRAIN_PROVIDER"] = provider
    model = _configured_model(cfg, provider)
    if model:
        os.environ["BRAIN_MODEL"] = model
    return LLMClient(provider, model=model)


def _get_brain(provider: str | None = None):
    """Return a Brain instance."""
    Brain, _ = _import_brain()
    cfg = load_config()
    provider = provider or os.environ.get("BRAIN_PROVIDER") or cfg.get("provider")
    if provider:
        os.environ["BRAIN_PROVIDER"] = provider
    model = _configured_model(cfg, provider)
    if model:
        os.environ["BRAIN_MODEL"] = model
    return Brain(model=model, provider=provider)


def _run_shell(cmd: list[str], cwd: str | None = None, timeout: int = 3600,
               env: dict | None = None, full_env: bool = False) -> tuple[bool, str]:
    """Run a command with live output, return (success, combined_output).
    Takes an argv list, not a shell string — see
    SECURITY-REVIEW-2026-08-22.md finding #5 for why shell=True with
    f-string-interpolated targets was a command injection bug.
    `env`, when given, is merged over the current environment — EXCEPT when
    `full_env=True`, where `env` IS the child's complete environment. The
    scanner spawns (cmd_recon/cmd_hunt) pass full_env=True with an env that
    went through tools.credentials.redact_env_for_scanners(): vault/platform/
    LLM secrets must not reach scanner subprocesses (mission fix 4), which a
    merge could never achieve."""
    proc_env = env if (env is not None and full_env) else (
        {**os.environ, **env} if env else None)
    try:
        proc = subprocess.Popen(
            cmd, shell=False, cwd=cwd or str(HERE), env=proc_env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        lines = []
        for line in proc.stdout:
            print(line, end="", flush=True)
            lines.append(line)
        proc.wait(timeout=timeout)
        return proc.returncode == 0, "".join(lines)
    except subprocess.TimeoutExpired:
        proc.kill()
        return False, "timed out"
    except Exception as e:
        return False, str(e)


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_setup(args):
    """Interactive setup wizard."""
    header("RhodawkAI Bounty Hunter Setup")

    # ── Multi-platform credential bootstrap (Commit 1) ─────────────────────
    # Configure every supported platform/tool credential (HackerOne,
    # Bugcrowd, Intigriti, YesWeHack, PDCP, Chaos, LLM keys) before the
    # provider wizard, so recon + platform tools leave setup fully wired.
    # Skipped on non-TTY stdin (CI / piped runs) — run
    # `python3 -m rhodawk.tools.credentials --setup` instead.
    _run_onboarding = None
    try:
        sys.path.insert(0, str(HERE))
        from tools.credentials import run_interactive_onboarding as _run_onboarding  # noqa: PLC0415
    except ImportError:
        try:
            from credentials import run_interactive_onboarding as _run_onboarding  # noqa: PLC0415
        except ImportError:
            _run_onboarding = None
    if _run_onboarding is not None:
        if sys.stdin.isatty():
            try:
                _run_onboarding()
            except Exception as exc:
                warn(f"credential bootstrap failed: {exc}")
            print()
        else:
            info("Skipping interactive credential bootstrap (no TTY) — run later:")
            info("  python3 -m rhodawk.tools.credentials --setup")

    providers = {
        "1":  ("ollama",     "Ollama     (local, FREE)       — needs ollama running locally"),
        "2":  ("groq",       "Groq       (cloud, FREE tier)  — needs GROQ_API_KEY"),
        "3":  ("deepseek",   "DeepSeek   (cloud, very cheap)— needs DEEPSEEK_API_KEY"),
        "4":  ("claude",     "Claude     (paid)              — needs ANTHROPIC_API_KEY"),
        "5":  ("openai",     "OpenAI     (paid)              — needs OPENAI_API_KEY"),
        "6":  ("grok",       "Grok/xAI   (paid)              — needs XAI_API_KEY"),
        "7":  ("openrouter", "OpenRouter (multi-model)       — needs OPENROUTER_API_KEY"),
        "8":  ("orcarouter", "OrcaRouter (multi-model)       — needs ORCAROUTER_API_KEY"),
        "9":  ("litellm",     "LiteLLM     (100+ providers)    — uses per-provider keys or LITELLM_API_KEY"),
        "10": ("requesty",    "Requesty    (multi-model)       — needs REQUESTY_API_KEY"),
        "11": ("antigravity", "Antigravity / Gemini (Google OAuth — Gemini AI)"),
        "13": ("nvidia",     "NVIDIA NIM (hosted / self-hosted) — needs NVIDIA_API_KEY"),
    }

    requested_provider = (
        getattr(args, "setup_provider", None)
        or getattr(args, "provider", None)
    )
    if requested_provider:
        provider = requested_provider.lower()
        info(f"Selected provider: {provider}")
    else:
        print("Choose your AI backend:\n")
        for k, (_, desc) in providers.items():
            print(f"  {k:>2}) {desc}")
        print()

        choice = input("Enter number [1]: ").strip() or "1"
        provider = providers.get(choice, ("ollama", ""))[0]

    # NVIDIA NIM aliases normalize to the canonical provider id.
    if provider in ("nim", "nvidia-nim", "nvidia_nim"):
        provider = "nvidia"

    if provider in ("gemini", "gemini-oauth", "google-oauth", "agy") and not os.environ.get("GEMINI_API_KEY"):
        provider = "antigravity"

    requested_model = (
        getattr(args, "setup_model", None)
        or getattr(args, "model", None)
    )

    cfg = load_config()
    cfg["provider"] = provider

    env_map = {
        "groq":       "GROQ_API_KEY",
        "deepseek":   "DEEPSEEK_API_KEY",
        "claude":     "ANTHROPIC_API_KEY",
        "openai":     "OPENAI_API_KEY",
        "grok":       "XAI_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "orcarouter": "ORCAROUTER_API_KEY",
        "requesty":   "REQUESTY_API_KEY",
        "nvidia":     "NVIDIA_API_KEY",
        "gemini":     "GEMINI_API_KEY",
    }

    if provider == "antigravity":
        sys.path.insert(0, str(HERE))
        from tools.google_oauth import (
            ANTIGRAVITY_MODEL_LABELS,
            get_valid_credentials,
            interactive_google_oauth_login,
            resolve_antigravity_model,
        )
        creds = get_valid_credentials()
        if creds and creds.get("access_token"):
            email = creds.get("email") or "Google Account"
            ok(f"Google OAuth session active: {email}")
            if not requested_provider and sys.stdin.isatty():
                relogin = input("Login with another Google account? (y/N): ").strip().lower()
                if relogin.startswith("y"):
                    no_browser = input("Use manual authorization code instead of browser? (y/N): ").strip().lower().startswith("y")
                    creds = interactive_google_oauth_login(no_browser=no_browser)
                    ok(f"Google OAuth login successful: {creds.get('email', 'authenticated')}")
        elif not requested_provider and sys.stdin.isatty():
            do_oauth = input("Sign in with Google OAuth in browser now? (Y/n): ").strip().lower()
            if not do_oauth.startswith("n"):
                no_browser = input("Use manual copy-paste code instead of opening browser? (y/N): ").strip().lower().startswith("y")
                try:
                    creds = interactive_google_oauth_login(no_browser=no_browser)
                    ok(f"Google OAuth login successful: {creds.get('email', 'authenticated')}")
                except Exception as exc:
                    warn(f"Browser OAuth skipped ({exc}) — using active Antigravity CLI session")

    elif provider in env_map:
        env_var = env_map[provider]
        existing = os.environ.get(env_var, "")
        print(f"\nEnter {env_var} (blank = keep existing): ", end="")
        try:
            api_key = input().strip()
        except EOFError:
            # Non-interactive `setup --provider <p> --model <m>`: keep whatever
            # the environment (or an earlier setup) already configured instead
            # of crashing with an EOFError traceback.
            api_key = ""
        if api_key:
            cfg[env_var] = api_key
            os.environ[env_var] = api_key
        elif existing:
            info(f"Using existing {env_var} from environment")
        else:
            warn(f"No {env_var} set — provider may not work")

    # NVIDIA NIM: optional endpoint override for self-hosted / regional NIM
    # deployments (the hosted default is applied in brain.py when unset).
    if provider == "nvidia":
        shown = (os.environ.get("NVIDIA_NIM_BASE_URL", "")
                 or cfg.get("NVIDIA_NIM_BASE_URL", "")
                 or "https://integrate.api.nvidia.com/v1")
        try:
            nim_base = input(f"\nEnter NVIDIA_NIM_BASE_URL (blank = {shown}): ").strip()
        except EOFError:
            nim_base = ""
        if nim_base:
            cfg["NVIDIA_NIM_BASE_URL"] = nim_base
            os.environ["NVIDIA_NIM_BASE_URL"] = nim_base
        elif cfg.get("NVIDIA_NIM_BASE_URL"):
            os.environ.setdefault("NVIDIA_NIM_BASE_URL", cfg["NVIDIA_NIM_BASE_URL"])

    # Test connection
    info("Testing connection...")
    _, LLMClient = _import_brain()
    if provider in env_map and cfg.get(env_map[provider]):
        os.environ[env_map[provider]] = cfg[env_map[provider]]

    client = LLMClient(provider)
    if client.available:
        ok(f"Connected: {client.description}")
        selected_model = None
        if provider == "ollama":
            models = client.list_models()
            if models:
                if requested_model:
                    if requested_model not in models:
                        err(f"Ollama model '{requested_model}' is not installed")
                        print("  Available models:")
                        for model_name in models:
                            print(f"    {model_name}")
                        print(f"  Install it with: ollama pull {requested_model}")
                        return
                    selected_model = requested_model
                else:
                    saved_models = cfg.get("models", {})
                    current = saved_models.get("ollama") if isinstance(saved_models, dict) else None
                    default_index = models.index(current) + 1 if current in models else 1
                    print("\nChoose the Ollama model RhodawkAI Bounty Hunter should use:\n")
                    for index, model_name in enumerate(models, start=1):
                        marker = " (current)" if model_name == current else ""
                        print(f"  {index}) {model_name}{marker}")
                    choice = input(f"\nEnter number [{default_index}]: ").strip()
                    try:
                        selected_model = models[int(choice or default_index) - 1]
                    except (ValueError, IndexError):
                        warn("Invalid model choice — using the default selection")
                        selected_model = models[default_index - 1]
                if not isinstance(cfg.get("models"), dict):
                    cfg["models"] = {}
                cfg.setdefault("models", {})["ollama"] = selected_model
                os.environ["BRAIN_MODEL"] = selected_model
                ok(f"Selected model: {selected_model}")
            else:
                warn("No local Ollama models found — pull one, then run setup again")
        elif provider == "antigravity" and not requested_model and sys.stdin.isatty():
            sys.path.insert(0, str(HERE))
            from tools.google_oauth import ANTIGRAVITY_MODEL_LABELS, resolve_antigravity_model
            models = client.list_models()
            if models:
                saved_models = cfg.get("models", {})
                current = saved_models.get(provider) if isinstance(saved_models, dict) else None
                if current:
                    current = resolve_antigravity_model(current)
                default_index = models.index(current) + 1 if current in models else 1
                print("\nChoose the Antigravity / Gemini model RhodawkAI Bounty Hunter should use:\n")
                for index, model_name in enumerate(models, start=1):
                    label = ANTIGRAVITY_MODEL_LABELS.get(model_name, "")
                    label_str = f" — {label}" if label else ""
                    marker = " (current)" if model_name == current else ""
                    print(f"  {index:>2}) {model_name:<25}{label_str}{marker}")
                choice = input(f"\nEnter number [{default_index}]: ").strip()
                try:
                    selected_model = models[int(choice or default_index) - 1]
                except (ValueError, IndexError):
                    selected_model = models[default_index - 1]
                if not isinstance(cfg.get("models"), dict):
                    cfg["models"] = {}
                cfg.setdefault("models", {})[provider] = selected_model
                os.environ["BRAIN_MODEL"] = selected_model
                ok(f"Selected model: {selected_model}")
        elif requested_model:
            if provider == "antigravity":
                sys.path.insert(0, str(HERE))
                from tools.google_oauth import resolve_antigravity_model
                requested_model = resolve_antigravity_model(requested_model)
            if not isinstance(cfg.get("models"), dict):
                cfg["models"] = {}
            cfg.setdefault("models", {})[provider] = requested_model
            os.environ["BRAIN_MODEL"] = requested_model
            selected_model = requested_model
            ok(f"Selected model: {selected_model}")

        save_config(cfg)
        ok(f"Config saved to {CONFIG}")
        # max_tokens >= 256: reasoning models (e.g. NVIDIA NIM nemotron) spend
        # budget on reasoning_content before emitting final content — a tiny
        # cap (10) makes the connectivity ping return an empty reply.
        reply = client.chat(selected_model, "You are a helpful assistant.",
                            "Reply with exactly: READY", max_tokens=256)
        ok(f"Model responded: {reply.strip()}" if reply else "Connected (no reply — pull a model if using Ollama)")
    else:
        if not requested_model:
            save_config(cfg)
            ok(f"Config saved to {CONFIG}")
        else:
            warn("Configuration was not changed because the requested model could not be verified")
        err(f"Provider '{provider}' not available")
        if provider == "ollama":
            print(f"\n  {YELLOW}Install Ollama:{NC}")
            print("    curl -fsSL https://ollama.ai/install.sh | sh")
            print("    ollama pull qwen2.5:14b")
        elif provider in env_map:
            print(f"\n  {YELLOW}Set API key:{NC}  export {env_map[provider]}=your_key_here")


def cmd_login(args):
    """Google OAuth 2.0 login / status / logout for Gemini AI Pro."""
    header("Google OAuth — Gemini AI Pro")
    sys.path.insert(0, str(HERE))
    from tools.google_oauth import (
        RHODAWK_OAUTH_FILE,
        clear_oauth_credentials,
        get_valid_credentials,
        interactive_google_oauth_login,
    )

    if getattr(args, "logout", False):
        if clear_oauth_credentials():
            ok(f"Removed saved Google OAuth credentials ({RHODAWK_OAUTH_FILE})")
        else:
            info("No saved Google OAuth credentials to remove.")
        return

    if getattr(args, "status", False):
        creds = get_valid_credentials()
        if creds and creds.get("access_token"):
            email = creds.get("email") or "authenticated"
            tier = creds.get("user_tier_name") or creds.get("user_tier") or "Gemini AI Pro"
            proj = creds.get("project_id") or "auto"
            ok(f"Google OAuth active: {email}")
            info(f"Tier: {tier} | Project: {proj}")
            info(f"Credentials file: {creds.get('_source_path', RHODAWK_OAUTH_FILE)}")
        else:
            warn("Not logged in with Google OAuth. Run: rhodawk login")
        return

    no_browser = bool(getattr(args, "no_browser", False))
    try:
        creds = interactive_google_oauth_login(no_browser=no_browser)
    except Exception as exc:
        err(f"Google OAuth login failed: {exc}")
        sys.exit(1)

    email = creds.get("email") or "Google Account"
    tier = creds.get("user_tier_name") or creds.get("user_tier") or "Gemini AI Pro (Antigravity)"
    ok(f"Logged in as: {email} ({tier})")
    ok(f"Credentials saved to: {RHODAWK_OAUTH_FILE}")

    cfg = load_config()
    cfg["provider"] = "antigravity"
    cfg.setdefault("models", {})["antigravity"] = (
        getattr(args, "model", None) or cfg.get("models", {}).get("antigravity") or "gemini-4-argon-high"
    )
    save_config(cfg)
    ok(f"Active provider set to 'antigravity' (model: {cfg['models']['antigravity']})")


def cmd_providers(args):
    """Show all providers and API key status."""
    import shutil
    _, LLMClient = _import_brain()
    cfg = load_config()
    saved = cfg.get("provider", "")
    if saved in ("gemini", "gemini-oauth", "google-oauth", "agy") and not os.environ.get("GEMINI_API_KEY"):
        saved = "antigravity"

    sys.path.insert(0, str(HERE))
    try:
        from tools.google_oauth import load_oauth_credentials
        oauth_creds = load_oauth_credentials()
    except Exception:
        oauth_creds = None

    env_map = {
        "ollama":       None,
        "antigravity":  None,
        "groq":         "GROQ_API_KEY",
        "deepseek":     "DEEPSEEK_API_KEY",
        "claude":       "ANTHROPIC_API_KEY",
        "openai":       "OPENAI_API_KEY",
        "grok":         "XAI_API_KEY",
        "openrouter":   "OPENROUTER_API_KEY",
        "orcarouter":   "ORCAROUTER_API_KEY",
        "requesty":     "REQUESTY_API_KEY",
        "nvidia":       "NVIDIA_API_KEY",
    }
    tier = {
        "ollama":       "FREE (local)",
        "antigravity":  "Gemini AI Pro",
        "groq":         "FREE tier",
        "deepseek":     "cheap",
        "claude":       "paid",
        "openai":       "paid",
        "grok":         "paid",
        "openrouter":   "subscription",
        "orcarouter":   "subscription",
        "requesty":     "pay-as-you-go",
        "nvidia":       "pay-as-you-go",
    }

    print(f"\n  {'PROVIDER':<14} {'TIER':<16} {'STATUS':<22} {'NOTE'}")
    print(f"  {'─'*14} {'─'*16} {'─'*22} {'─'*30}")

    for prov, env_var in env_map.items():
        if prov == "antigravity":
            agy_bin = os.environ.get("AGY_BIN") or shutil.which("agy") or str(Path.home() / ".local" / "bin" / "agy")
            email = (oauth_creds or {}).get("email")
            if agy_bin and os.path.isfile(agy_bin) and os.access(agy_bin, os.X_OK):
                status = f"{GREEN}OAuth ready{NC}"
                note = f"{email} (Google OAuth)" if email else "Google OAuth / agy"
            else:
                status = f"{RED}not installed{NC}"
                note = "install Antigravity CLI"
        elif env_var:
            key_set = bool(os.environ.get(env_var) or cfg.get(env_var))
            status  = f"{GREEN}key set{NC}" if key_set else f"{RED}no key{NC}"
            note    = env_var if not key_set else ""
        else:
            try:
                import urllib.request
                urllib.request.urlopen("http://localhost:11434", timeout=1)
                status = f"{GREEN}running{NC}"
                note   = ""
            except Exception:
                status = f"{YELLOW}not running{NC}"
                note   = "ollama serve"

        marker = f" {BOLD}<- active{NC}" if prov == saved else ""
        print(f"  {BOLD}{prov:<14}{NC} {tier[prov]:<16} {status:<32} {DIM}{note}{NC}{marker}")

    print(f"\n  Config: {CONFIG}")
    print(f"  Change: rhodawk setup\n")


def cmd_models(args):
    """List available models for the active provider."""
    cfg = load_config()
    provider = getattr(args, "provider", None) or cfg.get("provider")
    client = _get_client(provider)
    if not client.available:
        err(f"Provider '{client.provider}' not available. Run: rhodawk setup")
        return
    models = client.list_models()
    info(f"Provider: {client.description}")
    selected = _configured_model(cfg, client.provider)
    if models:
        sys.path.insert(0, str(HERE))
        try:
            from tools.google_oauth import ANTIGRAVITY_MODEL_LABELS
        except Exception:
            ANTIGRAVITY_MODEL_LABELS = {}
        for m in models:
            label = ANTIGRAVITY_MODEL_LABELS.get(m, "")
            label_str = f" — {DIM}{label}{NC}" if label else ""
            marker = f" {BOLD}<- selected{NC}" if m == selected else ""
            print(f"  {GREEN}•{NC} {m:<25}{label_str}{marker}")
    else:
        warn("No models found")
        if client.provider == "ollama":
            print("  Pull a model: ollama pull qwen2.5:14b")


def _add_scope_args(parser) -> None:
    """Scope flags for subcommands that invoke recon_engine.sh. Forwarded
    verbatim to the script, whose reconFTW gap-fill adapter (Phases 1.5/5.5)
    enforces them fail-closed: reconFTW delegation never runs without explicit
    scope patterns or --no-scope-check."""
    parser.add_argument("--scope-domain", action="append", default=[],
                        help="In-scope pattern for reconFTW gap-fill (repeat or comma-separate). "
                             "Without it, gap-fill delegation fails closed.")
    parser.add_argument("--scope-exclude", action="append", default=[],
                        help="Out-of-scope pattern for reconFTW gap-fill (repeat or comma-separate).")
    parser.add_argument("--no-scope-check", action="store_true",
                        help="Opt out of the gap-fill scope gate (local demo testing only).")


def _scope_flag_args(args) -> list[str]:
    """Build the recon_engine.sh scope-forwarding argv fragment."""
    out: list[str] = []
    if getattr(args, "no_scope_check", False):
        out.append("--no-scope-check")
        return out
    for vals, flag in ((getattr(args, "scope_domain", []) or [], "--scope-domain"),
                       (getattr(args, "scope_exclude", []) or [], "--scope-exclude")):
        for v in vals:
            for part in str(v).split(","):
                part = part.strip()
                if part:
                    out += [flag, part]
    return out


def _js_crawl_args(args) -> list[str]:
    """Forward the opt-in --js-crawl flag to recon_engine.sh (Phase 5.75)."""
    return ["--js-crawl"] if getattr(args, "js_crawl", False) else []


def cmd_recon(args):
    """Run recon pipeline then AI surface analysis."""
    from tools.target_normalize import recon_dirname

    target = args.target
    # The scanners need a bare host; the output dir must match what
    # recon_engine.sh writes. Both derive it the same way (host, or host_port
    # so two ports on one host never collide — C10), and we pin RECON_OUT_DIR
    # so the two never disagree across install layouts.
    # Reject anything that isn't a safe single path component — never fall
    # back to the raw target, or `recon ../../etc/x` / `recon /etc/x` would
    # write outside the recon sandbox.
    host = recon_dirname(target)
    if not host:
        err(f"Refusing unsafe target {target!r} — expected a hostname, IP or CIDR")
        return
    recon_dir = RECON / host
    header(f"Recon: {host}")

    script = TOOLS / "recon_engine.sh"
    if script.exists():
        info("Running recon pipeline...")
        # B2: whenever scoping is active (explicit patterns, or the fail-closed
        # self-scoped path), tell recon_engine.sh to run scope-enforced so
        # httpx does NOT follow redirects blindly — an in-scope host must not
        # be able to 302 the probe onto an out-of-scope host. Same rule as
        # tools/hunt.py run_recon.
        # full_env=True + redaction: vault/platform/LLM secrets never reach
        # scanner subprocesses (mission fix 4); RECON_OUT_DIR still pinned.
        child_env = {**redact_env_for_scanners(os.environ),
                     "RECON_OUT_DIR": str(recon_dir)}
        if not getattr(args, "no_scope_check", False):
            child_env["SCOPE_ENFORCED"] = "1"
        success, output = _run_shell(["bash", str(script), target, *_scope_flag_args(args),
                                      *_js_crawl_args(args)],
                                     env=child_env, full_env=True)
        if "SCOPE BLOCK" in output:
            # Live-run fix: the pre-flight scope gate fired — 0 packets sent,
            # 0 tools executed. Abort the whole command with a non-zero exit
            # instead of continuing to AI analysis on an out-of-scope target.
            err("Recon blocked by the pre-flight scope gate — aborting")
            sys.exit(3)
        if not success:
            warn("Recon had issues — continuing with AI analysis")
    else:
        warn("recon_engine.sh not found — skipping to AI analysis")

    info("Running AI surface analysis...")
    brain = _get_brain()
    result = brain.analyze_recon(str(recon_dir) if recon_dir.exists() else target)
    # Step 1C: brain._stream already prints the analysis live — printing the
    # return value here duplicated the entire report (once before the
    # "[+] Saved: .../01_recon_analysis.md" line, once right after). One print.
    if not result:
        warn("AI analysis returned no output — check provider with: rhodawk providers")


def cmd_hunt(args):
    """Full hunt pipeline: recon + vuln scan + AI analysis."""
    from tools.target_normalize import recon_dirname

    target = args.target
    host = recon_dirname(target)
    if not host:
        err(f"Refusing unsafe target {target!r} — expected a hostname, IP or CIDR")
        return
    header(f"Hunt: {host}")

    recon_dir = RECON / host

    # Run recon
    script = TOOLS / "recon_engine.sh"
    if script.exists():
        info("Phase 1: Recon...")
        # B2: scope-enforced mode whenever scoping is active (see cmd_recon).
        # full_env=True + redaction: vault/platform/LLM secrets never reach
        # scanner subprocesses (mission fix 4); RECON_OUT_DIR still pinned.
        child_env = {**redact_env_for_scanners(os.environ),
                     "RECON_OUT_DIR": str(recon_dir)}
        if not getattr(args, "no_scope_check", False):
            child_env["SCOPE_ENFORCED"] = "1"
        _rc_success, _rc_output = _run_shell(
            ["bash", str(script), target, *_scope_flag_args(args),
             *_js_crawl_args(args)],
            env=child_env, full_env=True)
        if "SCOPE BLOCK" in _rc_output:
            # Live-run fix: never let the hunt continue (the vuln scanner
            # probes the target itself) once the pre-flight scope gate has
            # blocked recon — abort with a non-zero exit.
            err("Hunt blocked by the pre-flight scope gate — aborting")
            sys.exit(3)

    # Run vuln scan
    vuln_script = TOOLS / "vuln_scanner.sh"
    if vuln_script.exists() and recon_dir.exists():
        info("Phase 2: Vuln scan...")
        _run_shell(["bash", str(vuln_script), str(recon_dir)])

    # AI analysis
    info("Phase 3: AI analysis...")
    brain = _get_brain()
    findings_dir = FINDINGS / host
    if findings_dir.exists():
        brain.interpret_scan(str(findings_dir))
    elif recon_dir.exists():
        brain.analyze_recon(str(recon_dir))
    else:
        warn(f"No data for {host} — run recon first")


def cmd_validate(args):
    """Run 7-Question Gate on a finding description."""
    finding = getattr(args, "finding", "") or ""
    if not finding:
        finding = _read_stdin_or_prompt("Paste your finding description (Ctrl+D when done):\n")

    header("7-Question Gate")
    info(f"Finding: {finding[:120]}{'...' if len(finding) > 120 else ''}")

    brain = _get_brain()
    decision, explanation = brain.triage_finding(finding)

    print(f"\n{BOLD}{'─'*60}{NC}")
    if decision.startswith("PASS"):
        color = GREEN
    elif "DOWNGRADE" in decision or "CHAIN" in decision:
        color = YELLOW
    else:
        color = RED
    print(f"{color}{BOLD}DECISION: {decision}{NC}")
    if explanation:
        print(f"\n{explanation}")
    print(f"{BOLD}{'─'*60}{NC}\n")


def cmd_triage(args):
    """Alias for validate."""
    cmd_validate(args)


def cmd_report(args):
    """Generate a submission-ready bug report."""
    findings_dir = getattr(args, "findings_dir", "") or ""
    if not findings_dir:
        targets = sorted(FINDINGS.glob("*/")) if FINDINGS.exists() else []
        if targets:
            findings_dir = str(targets[-1])
            info(f"Using findings dir: {findings_dir}")
        else:
            err("No findings dir found. Use: rhodawk report --findings-dir findings/<target>")
            sys.exit(1)

    header("Report Writer")
    brain = _get_brain()

    recon_dir = ""
    target_name = Path(findings_dir).name
    candidate = RECON / target_name
    if candidate.exists():
        recon_dir = str(candidate)

    result = brain.write_report(findings_dir, recon_dir)
    if result:
        print(f"\n{result}")
        ok("Report written.")
    else:
        warn("No report output — ensure findings directory has data")


def cmd_chain(args):
    """Build A->B->C exploit chain."""
    findings_dir = getattr(args, "findings_dir", "") or ""
    finding = getattr(args, "finding", "") or ""

    if not findings_dir:
        targets = sorted(FINDINGS.glob("*/")) if FINDINGS.exists() else []
        if targets:
            findings_dir = str(targets[-1])

    header("Chain Builder")

    if findings_dir and Path(findings_dir).exists():
        brain = _get_brain()
        result = brain.build_chains(findings_dir)
        if result:
            print(f"\n{result}")
            return

    # Fallback: agent-prompt mode with finding description
    if not finding:
        finding = _read_stdin_or_prompt("Describe the bug to chain from:\n")

    system = load_agent_prompt("chain-builder")
    client = _get_client()
    if not client.available:
        err("No AI provider available. Run: rhodawk setup")
        sys.exit(1)
    sys.path.insert(0, str(HERE))
    from brain import BRAIN_SYSTEM  # noqa: PLC0415
    result = client.chat(None, system or BRAIN_SYSTEM,
                         f"Build an exploit chain starting from this bug:\n\n{finding}")
    if result:
        print(f"\n{result}")


def cmd_chat(args):
    """Interactive Q&A shell."""
    header("RhodawkAI Bounty Hunter Chat")
    client = _get_client()
    if not client.available:
        err("No AI provider available. Run: rhodawk setup")
        sys.exit(1)

    sys.path.insert(0, str(HERE))
    from brain import BRAIN_SYSTEM  # noqa: PLC0415

    ok(f"Connected: {client.description}")
    print(f"{DIM}Type 'exit' or Ctrl+C to quit{NC}\n")

    history: list[dict] = []
    while True:
        try:
            user_input = input(f"{CYAN}{BOLD}you>{NC} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if user_input.lower() in ("exit", "quit", "q"):
            break
        if not user_input:
            continue

        ctx_parts = []
        for turn in history[-4:]:
            ctx_parts.append(f"[you] {turn['user']}")
            ctx_parts.append(f"[assistant] {turn['assistant']}")
        prompt = ("\n".join(ctx_parts) + "\n\n" if ctx_parts else "") + f"[you] {user_input}"

        reply = client.chat(None, BRAIN_SYSTEM, prompt, max_tokens=2000)
        if reply:
            print(f"\n{reply}\n")
            history.append({"user": user_input, "assistant": reply})
        else:
            warn("No response — check provider with: rhodawk providers")


def cmd_status(args):
    """Show pipeline status."""
    header("Hunt Status")

    recon_targets = sorted(RECON.glob("*/")) if RECON.exists() else []
    print(f"  {BOLD}Recon completed:{NC} {len(recon_targets)} target(s)")
    for t in recon_targets[:5]:
        subs = t / "subdomains" / "all.txt"
        live = t / "live" / "urls.txt"
        n_subs = sum(1 for _ in subs.open()) if subs.exists() else 0
        n_live = sum(1 for _ in live.open()) if live.exists() else 0
        print(f"    {GREEN}•{NC} {t.name}: {n_subs} subdomains, {n_live} live hosts")

    finding_targets = sorted(FINDINGS.glob("*/")) if FINDINGS.exists() else []
    print(f"\n  {BOLD}Findings:{NC} {len(finding_targets)} target(s)")
    for t in finding_targets[:5]:
        summary = t / "summary.txt"
        if summary.exists():
            m = re.search(r"TOTAL FINDINGS:\s*(\d+)", summary.read_text())
            count = m.group(1) if m else "?"
            print(f"    {GREEN}•{NC} {t.name}: {count} findings")

    report_targets = sorted(REPORTS.glob("*/")) if REPORTS.exists() else []
    print(f"\n  {BOLD}Reports:{NC} {len(report_targets)} target(s)")
    for t in report_targets[:5]:
        print(f"    {GREEN}•{NC} {t.name}: {len(list(t.glob('*.md')))} report(s)")

    print(f"\n  {BOLD}Provider:{NC} ", end="")
    client = _get_client()
    if client.available:
        model = _configured_model(load_config(), client.provider)
        model_note = f" | model: {model}" if model else " | model: automatic"
        print(f"{GREEN}{client.description}{model_note}{NC}")
    else:
        print(f"{RED}not configured{NC} — run: rhodawk setup")
    print()


def _doctor_chromium_path() -> str:
    """The single managed Chromium path recorded by install_tools.sh --browser
    (capabilities.json "chromium_path"). Never scans the disk for browsers —
    reads only the recorded value."""
    env = os.environ.get("RHODAWK_CAPABILITIES_FILE")
    if env:
        path = Path(env).expanduser()
    else:
        home = get_env("RHODAWK_HOME")
        path = (Path(home).expanduser() if home
                else Path.home() / ".rhodawk") / "capabilities.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8")).get("chromium_path", "")
        return value if isinstance(value, str) else ""
    except (OSError, ValueError, AttributeError):
        return ""


def cmd_doctor(args):
    """Step 3: `rhodawk doctor` — fast (<5s) environment diagnostic.
    PASS / WARN / FAIL per check with the exact one-line fix command.
    Exit 0 when nothing FAILs, 1 otherwise."""
    import shutil  # noqa: PLC0415
    import concurrent.futures  # noqa: PLC0415

    sys.path.insert(0, str(HERE))
    try:
        from tools.capability_registry import check_rtw_repo  # noqa: PLC0415
    except ImportError:
        from capability_registry import check_rtw_repo  # noqa: PLC0415

    results = []  # (status, label, detail, fix)

    def record(status, label, detail, fix=""):
        results.append((status, label, detail, fix))

    # 1. Core binaries
    core = ["subfinder", "httpx", "katana", "gau", "ffuf", "nuclei", "nmap", "jq"]
    missing = [t for t in core if not shutil.which(t)]
    if missing:
        record("WARN", "Core binaries", f"missing: {', '.join(missing)}",
               "bash install_tools.sh   # repo checkout")
    else:
        record("PASS", "Core binaries", f"{len(core)}/{len(core)} on PATH")

    # 2. reconFTW checkout: RTW_HOME + pinned commit + executable bit.
    #    Gap fix (mission item 6): every delegated capability is OPTIONAL —
    #    capability_registry classifies them RTW_MISSING_DEPS ⇒ SKIPPED, never
    #    blocking, and the native stack runs fully without reconFTW. A missing
    #    (or broken) checkout therefore degrades 7 optional capabilities; it
    #    was doctor's only FAIL on an otherwise working system and made
    #    `rhodawk doctor` exit 1 for a healthy native install. WARN, not FAIL.
    rtw = check_rtw_repo()
    if not Path(rtw["rtw_home"]).is_dir():
        record("WARN", "reconFTW checkout",
               f"not found at {rtw['rtw_home']} (RTW_HOME) — 7 delegated capabilities disabled (native recon unaffected)",
               "bash install.sh   # repo checkout — clones reconFTW + persists rtw_home")
    elif not rtw["executable"]:
        record("WARN", "reconFTW checkout", f"{rtw['script']} is not executable — delegation disabled (native recon unaffected)",
               f'chmod +x "{rtw["script"]}"')
    elif rtw["commit_matches_pin"] is False:
        record("WARN", "reconFTW checkout",
               f"HEAD {str(rtw.get('head_commit', '?'))[:9]} != pinned snapshot",
               "bash install.sh   # repo checkout — re-clone at the pinned commit")
    elif rtw["commit_matches_pin"] is None:
        record("WARN", "reconFTW checkout",
               "not a git checkout — pinned commit unknown",
               "bash install.sh   # repo checkout — re-clone for the verified snapshot")
    else:
        record("PASS", "reconFTW checkout",
               f"{str(rtw.get('head_commit', '?'))[:9]} matches pin, +x ok")

    # 3. Single managed Chromium (optional — headless SPA crawling)
    chromium = _doctor_chromium_path()
    if not chromium:
        record("WARN", "Managed Chromium",
               "chromium_path unset — headless SPA crawling disabled (optional)",
               "bash install_tools.sh --browser   # repo checkout")
    elif not (Path(chromium).is_file() and os.access(chromium, os.X_OK)):
        record("WARN", "Managed Chromium",
               f"{chromium} recorded but not executable",
               "bash install_tools.sh --browser   # repo checkout")
    else:
        record("PASS", "Managed Chromium", chromium)

    # 4. API keys + saved LLM provider connectivity (READY)
    for var, purpose in (("PDCP_API_KEY", "ProjectDiscovery API (subfinder/httpx sources)"),
                         ("CHAOS_API_KEY", "Chaos public recon dataset"),
                         ("H1_API_TOKEN", "HackerOne scope sync")):
        if os.environ.get(var):
            record("PASS", var, "set")
        else:
            record("WARN", var, f"unset — {purpose} disabled (optional)",
                   f"export {var}=...")

    # 4b. Tool-to-credential vault status (Commit 1): READY / SKIPPED (blank)
    # / KEYLESS for HackerOne, Bugcrowd, Intigriti, YesWeHack, PDCP, Chaos,
    # the LLM keys, and the keyless tools (h1scope, bounty-targets-data).
    _status_rows = None
    try:
        from tools.credentials import status_rows as _status_rows  # noqa: PLC0415
    except ImportError:
        try:
            from credentials import status_rows as _status_rows  # noqa: PLC0415
        except ImportError:
            _status_rows = None
    if _status_rows is None:
        record("WARN", "Credential vault", "module missing (rhodawk/tools/credentials.py)",
               "git pull — rhodawk/tools/credentials.py")
    else:
        try:
            _cred_rows = _status_rows()
        except Exception as exc:
            _cred_rows = None
            record("WARN", "Credential vault", f"status failed: {exc}",
                   "python3 -m rhodawk.tools.credentials --verify")
        for _label, _status, _detail in (_cred_rows or []):
            record("PASS" if _status in ("READY", "KEYLESS") else "WARN",
                   _label, f"{_status}: {_detail}",
                   "python3 -m rhodawk.tools.credentials --setup"
                   if _status not in ("READY", "KEYLESS") else "")

    cfg = load_config()
    provider = (os.environ.get("BRAIN_PROVIDER") or cfg.get("provider") or "")
    if not provider:
        record("WARN", "LLM provider", "not configured — AI analysis disabled",
               "rhodawk setup")
    else:
        try:
            client = _get_client()
        except Exception as exc:
            client = None
            record("WARN", f"LLM provider {provider}", f"init failed: {exc}",
                   "rhodawk setup")
        if client is not None:
            if not getattr(client, "available", False):
                record("WARN", f"LLM provider {provider}",
                       "configured but unavailable (key/endpoint)",
                       "rhodawk setup")
            else:
                reply = ""
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                        fut = ex.submit(client.chat, None,
                                        "You are a health probe.",
                                        "Reply with the single word READY")
                        reply = (fut.result(timeout=4) or "").strip().upper()
                except Exception:
                    reply = ""
                if "READY" in reply:
                    record("PASS", f"LLM provider {provider}", "responded READY")
                else:
                    record("WARN", f"LLM provider {provider}",
                           "no READY within 4s (unreachable or slow)",
                           "rhodawk setup")

    # 5. MCP module import (rhodawk mcp doctor parity)
    mcp_cli = HERE / "mcp" / "rhodawk-mcp" / "cli.py"
    try:
        import importlib.util  # noqa: PLC0415
        spec = importlib.util.spec_from_file_location("abh_mcp_cli_doctor", mcp_cli)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        record("PASS", "MCP module", "cli.py imports cleanly")
    except Exception as exc:
        record("FAIL", "MCP module", f"import failed: {exc}",
               "rhodawk mcp doctor")

    header("Environment doctor (rhodawk doctor)")
    for status, label, detail, fix in results:
        color = {"PASS": GREEN, "WARN": YELLOW, "FAIL": RED}[status]
        print(f"{color}  [{status}]{NC} {label:<20} {detail}")
        if fix:
            print(f"        fix: {fix}")
    fails = sum(1 for r in results if r[0] == "FAIL")
    warns = sum(1 for r in results if r[0] == "WARN")
    print()
    if fails:
        print(f"{RED}  {fails} FAIL, {warns} WARN — fix the FAILs above{NC}")
        raise SystemExit(1)
    print(f"{GREEN}  0 FAIL, {warns} WARN — environment ready{NC}")
    raise SystemExit(0)


def cmd_mcp(args):
    """MCP serve / doctor / tools — delegates to mcp/rhodawk-mcp/cli.py."""
    mcp_dir = Path(__file__).resolve().parent / "mcp" / "rhodawk-mcp"
    if str(mcp_dir) not in sys.path:
        sys.path.insert(0, str(mcp_dir))
    from cli import main as mcp_main  # type: ignore
    sub = getattr(args, "mcp_command", "serve") or "serve"
    raise SystemExit(mcp_main([sub]))


def cmd_scope_compile(args):
    """Compile a program's scope into a typed, hashed manifest (Commit 2).

    Delegates to tools/scope_compiler.py: authenticated paginated H1 REST
    when the credential vault has HackerOne credentials, cursor-paginated
    public GraphQL (then bounty-targets-data) when keyless. Zero secret
    leakage — output carries counts, headers, RPS and paths only.
    """
    try:
        sys.path.insert(0, str(HERE))
        from tools import scope_compiler
    except ImportError:
        try:
            import scope_compiler  # type: ignore
        except ImportError:
            err("scope_compiler not found — expected rhodawk/tools/scope_compiler.py")
            sys.exit(1)

    try:
        handle = scope_compiler.normalize_handle(args.handle)
    except ValueError as exc:
        err(f"invalid program handle: {exc}")
        sys.exit(2)

    # Default output lives beside the recon dir for this program, so
    # 'rhodawk scope-compile X' + 'rhodawk recon ...' read the same tree.
    output = args.output or str(RECON / handle / "scope" / "compiled_scope.json")

    info(f"Compiling scope for '{handle}'...")
    try:
        summary = scope_compiler.compile_and_save(
            args.handle,
            output=output,
            h1scope_csv=args.h1scope_csv or None,
            huntdeck_db=args.huntdeck_db or None,
            bbscope_cache=args.bbscope_cache or None,
        )
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — surface a clean CLI error
        err(f"scope compile failed: {exc}")
        sys.exit(2)

    # v2.0.1: an authenticated-REST -> keyless_public fallback must never be
    # silent. The reason is pre-redacted in scope_compiler (HTTP status codes
    # and paths only — Authorization headers/tokens are never included).
    if summary.get("auth_fallback_reason"):
        warn(f"H1 authenticated REST unusable ({summary['auth_fallback_reason']}) "
             f"— compiled in keyless_public mode")

    header(f"Scope manifest: {summary['program_handle']} "
           f"({summary['auth_mode']})")
    ok(f"allow patterns: {summary['allow_patterns']}")
    ok(f"exclude patterns: {summary['exclude_patterns']}")
    if summary.get("excluded_classes"):
        info(f"excluded classes: {', '.join(summary['excluded_classes'])}")
    if summary.get("mandatory_headers"):
        info("mandatory headers: "
             + ", ".join(f"{k}: {v}".strip(": ")
                         for k, v in summary["mandatory_headers"].items()))
    info(f"max RPS: {summary['max_rps']}")
    info(f"sources: {'; '.join(summary['sources'])}")
    if summary.get("drift_count"):
        warn(f"drift audit entries: {summary['drift_count']} "
             "(see manifest drift_audit)")
    ok(f"manifest: {summary['manifest']}")
    info(f"mirror:   {summary['mirror']}")
    info(f"sha256:   {summary['manifest_sha256']}...")
    info("Next: rhodawk recon <target> uses scope_checker against these "
         "patterns; manifest integrity is verified on every load.")


# ── Utility ────────────────────────────────────────────────────────────────────

def _read_stdin_or_prompt(prompt_text: str) -> str:
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    print(prompt_text, end="", flush=True)
    lines = []
    try:
        while True:
            lines.append(input())
    except EOFError:
        pass
    return "\n".join(lines).strip()


def _print_banner():
    G1  = "\033[1;32m"   # bright green
    G2  = "\033[0;32m"   # normal green
    G3  = "\033[2;32m"   # dim green
    W   = "\033[1;37m"   # white bold
    LINES = [
        ("  ██████╗ ██╗  ██╗ ██████╗ ██████╗  █████╗ ██╗    ██╗██╗  ██╗", G1),
        ("  ██╔══██╗██║  ██║██╔═══██╗██╔══██╗██╔══██╗██║    ██║██║ ██╔╝", G2),
        ("  ██████╔╝███████║██║   ██║██║  ██║███████║██║ █╗ ██║█████╔╝", G1),
        ("  ██╔══██╗██╔══██║██║   ██║██║  ██║██╔══██║██║███╗██║██╔═██╗", G2),
        ("  ██║  ██║██║  ██║╚██████╔╝██████╔╝██║  ██║╚███╔███╔╝██║  ██╗", G1),
        ("  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝", G3),
    ]
    print()
    for line, color in LINES:
        print(f"{color}{line}{NC}")
    print()
    print(f"  {G3}by {W}RhodawkAI{NC}  {G3}·{NC}  {G2}rhodawkai.com{NC}")
    print(f"  {G3}github.com/{G2}Rhodawk-AI{G3}/rhodawk-bounty-hunter{NC}")
    print(f"  {G3}free · open · no subscription required{NC}")
    print()


# ── CLI entry point ────────────────────────────────────────────────────────────

def main():
    ensure_home_migrated()
    argv = _normalize_cli_argv(sys.argv[1:])
    parser = argparse.ArgumentParser(
        prog="rhodawk",
        description="Standalone RhodawkAI Bounty Hunter Engine — works without Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Free setup (zero subscription):
          curl -fsSL https://ollama.ai/install.sh | sh
          ollama pull qwen2.5:14b
          rhodawk setup
          rhodawk recon target.com

        Free cloud (Groq — very fast):
          export GROQ_API_KEY=gsk_...
          rhodawk recon target.com

        Switch providers anytime:
          rhodawk setup
        """),
    )
    parser.add_argument("--provider", "-p",
                        help="Force provider: ollama / gemini-oauth / antigravity / gemini / groq / deepseek / claude / openai / grok / openrouter / orcarouter / litellm / requesty / nvidia (NIM, aliases: nim, nvidia-nim)")
    parser.add_argument("--model", "-m", help="Force model for this invocation (for example qwen3:14b)")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_setup = sub.add_parser("setup", aliases=["init"], help="Configure and persist provider/model")
    p_setup.add_argument(
        "--provider", dest="setup_provider",
        choices=["ollama", "groq", "deepseek", "claude", "openai", "grok",
                 "openrouter", "orcarouter", "litellm", "requesty",
                 "nvidia", "nim", "nvidia-nim",
                 "gemini", "gemini-oauth", "google-oauth", "antigravity", "agy"],
        help="Provider to persist (skips the provider prompt)",
    )
    p_setup.add_argument(
        "--model", dest="setup_model",
        help="Model to persist; an Ollama model must already be installed",
    )

    p_login = sub.add_parser("login", aliases=["auth"], help="Login with Google OAuth (Gemini AI Pro)")
    p_login.add_argument("--no-browser", action="store_true", help="Use manual copy-paste authorization code instead of opening browser")
    p_login.add_argument("--status", action="store_true", help="Check current Google OAuth login status")
    p_login.add_argument("--logout", action="store_true", help="Remove saved Google OAuth credentials")
    sub.add_parser("providers", aliases=["p"], help="Show all providers + API key status")
    sub.add_parser("models",    aliases=["m"], help="List available models for active provider")
    sub.add_parser("status",    aliases=["s"], help="Show hunt pipeline status")
    sub.add_parser("doctor",    help="Fast environment diagnostic (PASS/WARN/FAIL + 1-line fixes)")
    sub.add_parser("chat",      aliases=["ask"], help="Interactive AI shell")

    p_recon = sub.add_parser("recon", aliases=["r"], help="Recon + AI surface analysis")
    p_recon.add_argument("target", help="Target domain or IP")
    # Step 1A: --provider/--model accepted after the subcommand too, so the
    # shorthand `rhodawk <target> -recon --provider X` forwards identically.
    p_recon.add_argument("--provider", dest="cmd_provider",
                         help="Force provider for this invocation (global -p/--provider)")
    p_recon.add_argument("--model", dest="cmd_model",
                         help="Force model for this invocation (global -m/--model)")
    _add_scope_args(p_recon)
    p_recon.add_argument("--js-crawl", action="store_true", dest="js_crawl",
                         help="Opt-in headless JS crawl (Phase 5.75, Playwright): capture "
                              "runtime XHR/fetch endpoints of SPA targets. Skips with a WARN "
                              "when Playwright/Chromium is unavailable.")

    p_hunt = sub.add_parser("hunt", aliases=["h"], help="Full hunt pipeline")
    p_hunt.add_argument("target", help="Target domain or IP")
    p_hunt.add_argument("--quick", action="store_true", help="Quick mode (fewer checks)")
    p_hunt.add_argument("--provider", dest="cmd_provider",
                        help="Force provider for this invocation (global -p/--provider)")
    p_hunt.add_argument("--model", dest="cmd_model",
                        help="Force model for this invocation (global -m/--model)")
    _add_scope_args(p_hunt)
    p_hunt.add_argument("--js-crawl", action="store_true", dest="js_crawl",
                        help="Opt-in headless JS crawl (Phase 5.75, Playwright): capture "
                             "runtime XHR/fetch endpoints of SPA targets. Skips with a WARN "
                             "when Playwright/Chromium is unavailable.")

    p_val = sub.add_parser("validate", aliases=["v"], help="7-Question Gate on a finding")
    p_val.add_argument("finding", nargs="?", default="", help="Finding description (or pipe via stdin)")

    p_triage = sub.add_parser("triage", aliases=["t"], help="Fast triage (alias for validate)")
    p_triage.add_argument("finding", nargs="?", default="", help="Finding description")

    p_rep = sub.add_parser("report", aliases=["rep"], help="Write submission-ready bug report")
    p_rep.add_argument("--findings-dir", default="", help="Path to findings/<target> directory")

    p_chain = sub.add_parser("chain", aliases=["c"], help="Build A->B->C exploit chain")
    p_chain.add_argument("--findings-dir", default="", help="Path to findings/<target> directory")
    p_chain.add_argument("finding", nargs="?", default="", help="Bug A description (or pipe via stdin)")

    p_scope_compile = sub.add_parser(
        "scope-compile", aliases=["sc"],
        help="Compile a program scope into a typed, hashed manifest "
             "(authenticated paginated REST / keyless GraphQL fallback)")
    p_scope_compile.add_argument(
        "handle",
        help="Program handle or full H1 program URL "
             "(e.g. cloudflare or https://hackerone.com/cloudflare?type=team)")
    p_scope_compile.add_argument(
        "--output", default="",
        help="Primary manifest path (default: <recon>/<handle>/scope/"
             "compiled_scope.json, honors RECON_OUT_DIR)")
    p_scope_compile.add_argument(
        "--h1scope-csv", dest="h1scope_csv", default="",
        help="h1scope CSV export to reconcile (allowlist intersection)")
    p_scope_compile.add_argument(
        "--huntdeck-db", dest="huntdeck_db", default="",
        help="HuntDeck SQLite DB (opened read-only) to reconcile")
    p_scope_compile.add_argument(
        "--bbscope-cache", dest="bbscope_cache", default="",
        help="bbscope '-o tu' cache to reconcile")

    p_mcp = sub.add_parser("mcp", help="MCP server / doctor / tool catalog")
    p_mcp.add_argument(
        "mcp_command",
        nargs="?",
        default="serve",
        choices=["serve", "doctor", "tools"],
        help="serve (stdio MCP), doctor, or tools",
    )

    args = parser.parse_args(argv)

    # Apply provider/model override — the global flags and the recon/hunt
    # subcommand-level duplicates (Step 1A) forward identically.
    provider_override = (getattr(args, "provider", None)
                         or getattr(args, "cmd_provider", None))
    model_override = getattr(args, "model", None) or getattr(args, "cmd_model", None)
    if provider_override:
        os.environ["BRAIN_PROVIDER"] = provider_override
    if model_override:
        os.environ["BRAIN_MODEL"] = model_override

    # ── Multi-platform credential vault (Commit 1) ─────────────────────────
    # Every subcommand gets the 4-tier credential loader (env ->
    # $RHODAWK_CREDENTIALS_FILE -> ~/.rhodawk/.env -> /root/.secrets/h1_api)
    # applied first, so platform tools (bbscope, HuntDeck, h1-brain, PDCP/
    # Chaos-backed recon) and LLM providers all see the same credentials.
    # Non-interactive here by design: the wizard runs via `rhodawk setup`
    # or `python3 -m rhodawk.tools.credentials --setup`. Blank KEY=""
    # entries are ignored, and file permissions are auto-tightened (dir 0700,
    # file 0600). A vault failure must never kill the CLI.
    try:
        sys.path.insert(0, str(HERE))
        from tools.credentials import load_credentials  # noqa: PLC0415
    except ImportError:
        try:
            from credentials import load_credentials  # noqa: PLC0415
        except ImportError:
            load_credentials = None
    if load_credentials is not None:
        try:
            load_credentials(interactive=False)
        except Exception as exc:
            warn(f"credential vault load failed: {exc}")

    # Load saved API keys into environment before any LLM call
    cfg = load_config()
    for env_var in ("GROQ_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY",
                    "OPENAI_API_KEY", "XAI_API_KEY", "OPENROUTER_API_KEY",
                    "ORCAROUTER_API_KEY", "REQUESTY_API_KEY",
                    "GEMINI_API_KEY"):
        if not os.environ.get(env_var) and cfg.get(env_var):
            os.environ[env_var] = cfg[env_var]

    quiet_cmds = {"status", "providers", "models", "mcp", "login", "auth",
                  "doctor", "scope-compile", "sc", None}
    if not getattr(args, "no_banner", False) and args.command not in quiet_cmds:
        _print_banner()

    dispatch = {
        "setup":     cmd_setup,
        "login":     cmd_login,
        "auth":      cmd_login,
        "providers": cmd_providers,
        "models":    cmd_models,
        "recon":     cmd_recon,
        "hunt":      cmd_hunt,
        "validate":  cmd_validate,
        "triage":    cmd_triage,
        "report":    cmd_report,
        "chain":     cmd_chain,
        "chat":      cmd_chat,
        "status":    cmd_status,
        "doctor":    cmd_doctor,
        "mcp":       cmd_mcp,
        "scope-compile": cmd_scope_compile,
        "sc":        cmd_scope_compile,
    }

    if not args.command:
        parser.print_help()
        print()
        _print_quick_help()
        return

    fn = dispatch.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
