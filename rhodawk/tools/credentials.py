#!/usr/bin/env python3
"""
credentials.py — multi-platform credential vault for RhodawkAI Bounty Hunter.

One manager for every platform/tool key the toolkit understands, with an
interactive bootstrap wizard, a 4-tier auto-loader, and a redacted verify
CLI. Zero secret leakage: raw token/password/key values are never printed,
logged, or embedded in summaries — only variable NAMES and statuses.

Managed key groups (CREDENTIAL_GROUPS):
  1. HackerOne      — Direct H1 REST API v1, h1-brain, bbscope h1, HuntDeck
                       (H1_USERNAME, H1_API_TOKEN; also parses H1_TOKEN=user:token)
  2. Bugcrowd       — bbscope bc, HuntDeck
                       (BUGCROWD_TOKEN cookie, or BUGCROWD_EMAIL +
                        BUGCROWD_PASSWORD + optional BUGCROWD_OTP_SECRET)
  3. Intigriti      — bbscope it, HuntDeck (INTIGRITI_TOKEN)
  4. YesWeHack      — bbscope ywh, HuntDeck
                       (YWH_TOKEN JWT bearer, or YWH_EMAIL + YWH_PASSWORD +
                        optional YWH_OTP_SECRET)
  5. Recon & Intel  — reconFTW CAP_ASN_ENUM, Chaos (PDCP_API_KEY, CHAOS_API_KEY)
  6. LLM Providers  — rhodawk brain, bbscope AI normalization
                       (OPENROUTER_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY,
                        GROQ_API_KEY, DEEPSEEK_API_KEY)

Keyless tools (zero credentials): h1scope, bounty-targets-data.

4-tier auto-loader (load_credentials):
  1. Already-exported os.environ values (non-empty) win.
  2. Credential files, in priority order (permissions auto-tightened to
     0o600; the vault directory to 0o700):
       $RHODAWK_CREDENTIALS_FILE (if set)
       -> ~/.rhodawk/.env
       -> /root/.secrets/h1_api (if readable)
  3. Only non-empty values are exported into os.environ — blank `KEY=""`
     entries are ignored, so downstream tools treat them as unconfigured.
  4. interactive=True + TTY + no ~/.rhodawk/.env yet -> run the bootstrap
     wizard. Otherwise auth_mode is "authenticated_rest" (H1 creds present)
     or "keyless_public".

CLI:
  python3 -m rhodawk.tools.credentials --setup    # interactive wizard
  python3 -m rhodawk.tools.credentials --verify   # redacted status JSON
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
try:
    from rhodawk._compat import get_env, ensure_home_migrated
except ImportError:  # flat / script execution — resolve package dir
    import os as _compat_os, sys as _compat_sys
    _compat_dir = _compat_os.path.abspath(__file__)
    for _ in range(2):
        _compat_dir = _compat_os.path.dirname(_compat_dir)
    if _compat_dir not in _compat_sys.path:
        _compat_sys.path.insert(0, _compat_dir)
    from _compat import get_env, ensure_home_migrated

__all__ = [
    "CREDENTIAL_GROUPS",
    "KEYLESS_TOOLS",
    "ALL_MANAGED_VARS",
    "run_interactive_onboarding",
    "load_credentials",
    "print_tool_credential_table",
    "print_redacted_summary",
    "status_rows",
    "write_env_file",
    "verify_h1_auth",
    "main",
]

# ── Managed key groups ────────────────────────────────────────────────────────
# paths: alternative credential "routes" per group. A group is READY when at
# least one route is fully populated (non-empty values for every var on it).

CREDENTIAL_GROUPS = [
    {
        "id": "hackerone",
        "name": "HackerOne",
        "tools": "Direct H1 REST API v1, h1-brain, bbscope h1, HuntDeck",
        "fields": [
            {"var": "H1_USERNAME", "secret": False,
             "desc": "HackerOne account username (REST API Basic auth)"},
            {"var": "H1_API_TOKEN", "secret": True,
             "desc": "HackerOne API token (Profile Settings > API tokens)"},
        ],
        "paths": [["H1_USERNAME", "H1_API_TOKEN"]],
        "blank_note": "H1 REST sync + platform data disabled (public sources only)",
    },
    {
        "id": "bugcrowd",
        "name": "Bugcrowd",
        "tools": "bbscope bc, HuntDeck",
        "fields": [
            {"var": "BUGCROWD_TOKEN", "secret": True,
             "desc": "_bugcrowd_session cookie value"},
            {"var": "BUGCROWD_EMAIL", "secret": False,
             "desc": "Bugcrowd login email"},
            {"var": "BUGCROWD_PASSWORD", "secret": True,
             "desc": "Bugcrowd login password"},
            {"var": "BUGCROWD_OTP_SECRET", "secret": True,
             "desc": "Bugcrowd TOTP secret (optional)"},
        ],
        "paths": [["BUGCROWD_TOKEN"], ["BUGCROWD_EMAIL", "BUGCROWD_PASSWORD"]],
        "blank_note": "private Bugcrowd programs invisible (public browsing only)",
    },
    {
        "id": "intigriti",
        "name": "Intigriti",
        "tools": "bbscope it, HuntDeck",
        "fields": [
            {"var": "INTIGRITI_TOKEN", "secret": True,
             "desc": "Intigriti API/session token"},
        ],
        "paths": [["INTIGRITI_TOKEN"]],
        "blank_note": "Intigriti program sync disabled (public browsing only)",
    },
    {
        "id": "yeswehack",
        "name": "YesWeHack",
        "tools": "bbscope ywh, HuntDeck",
        "fields": [
            {"var": "YWH_TOKEN", "secret": True,
             "desc": "YesWeHack JWT bearer token"},
            {"var": "YWH_EMAIL", "secret": False,
             "desc": "YesWeHack login email"},
            {"var": "YWH_PASSWORD", "secret": True,
             "desc": "YesWeHack login password"},
            {"var": "YWH_OTP_SECRET", "secret": True,
             "desc": "YesWeHack TOTP secret (optional)"},
        ],
        "paths": [["YWH_TOKEN"], ["YWH_EMAIL", "YWH_PASSWORD"]],
        "blank_note": "YesWeHack program sync disabled (public browsing only)",
    },
    {
        "id": "recon_intel",
        "name": "Recon & Intel",
        "tools": "reconFTW CAP_ASN_ENUM, Chaos",
        "fields": [
            {"var": "PDCP_API_KEY", "secret": True,
             "desc": "ProjectDiscovery Cloud API key (subfinder/httpx sources)"},
            {"var": "CHAOS_API_KEY", "secret": True,
             "desc": "Chaos public recon dataset key"},
        ],
        "paths": [["PDCP_API_KEY"], ["CHAOS_API_KEY"]],
        "blank_note": "premium subfinder sources + Chaos dataset off (CAP_ASN_ENUM degraded)",
    },
    {
        "id": "llm_providers",
        "name": "LLM Providers",
        "tools": "rhodawk brain, bbscope AI normalization",
        "fields": [
            {"var": "OPENROUTER_API_KEY", "secret": True,
             "desc": "OpenRouter multi-model gateway key"},
            {"var": "ANTHROPIC_API_KEY", "secret": True,
             "desc": "Anthropic Claude API key"},
            {"var": "OPENAI_API_KEY", "secret": True,
             "desc": "OpenAI API key"},
            {"var": "GROQ_API_KEY", "secret": True,
             "desc": "Groq free-tier API key"},
            {"var": "DEEPSEEK_API_KEY", "secret": True,
             "desc": "DeepSeek API key"},
        ],
        "paths": [["OPENROUTER_API_KEY"], ["ANTHROPIC_API_KEY"],
                  ["OPENAI_API_KEY"], ["GROQ_API_KEY"], ["DEEPSEEK_API_KEY"]],
        "blank_note": "AI analysis falls back to local ollama / rule-based mode",
    },
]

# Tools that deliberately need zero credentials.
KEYLESS_TOOLS = [
    {"name": "h1scope",
     "note": "reads scope straight from public HackerOne data — zero keys"},
    {"name": "bounty-targets-data",
     "note": "offline platform scope snapshot — zero keys"},
]

ALL_MANAGED_VARS = [f["var"] for g in CREDENTIAL_GROUPS for f in g["fields"]]
# H1_TOKEN is an input alias (H1_TOKEN=user:token), not a stored vault key.
_LOOKUP_VARS = ALL_MANAGED_VARS + ["H1_TOKEN"]

STATUS_READY = "READY"
STATUS_SKIPPED = "SKIPPED (blank)"
STATUS_KEYLESS = "KEYLESS"

ROOT_SECRETS_FILE = Path("/root/.secrets/h1_api")
H1_VERIFY_URL = "https://api.hackerone.com/v1/hackers/me/reports?page%5Bsize%5D=1"


# ── Paths / small helpers ─────────────────────────────────────────────────────

def vault_dir() -> Path:
    ensure_home_migrated()
    """~/.rhodawk (respects $HOME so tests can isolate it)."""
    return Path.home() / ".rhodawk"


def vault_env_file() -> Path:
    """The managed credential vault file: ~/.rhodawk/.env."""
    return vault_dir() / ".env"


def _stdin_isatty() -> bool:
    """TTY probe (isolated so tests can force the interactive branch)."""
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except Exception:
        return False


def parse_env_text(text: str) -> dict[str, str]:
    """Parse KEY=VALUE lines (comments, blanks, quotes tolerated)."""
    data: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        if key:
            data[key] = value
    return data


def _tighten_file_perms(path: Path) -> bool:
    """chmod 0o600 when the file is looser. Returns True when changed."""
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            os.chmod(path, 0o600)
            return True
    except OSError:
        pass
    return False


def _tighten_dir_perms(path: Path) -> bool:
    """chmod 0o700 when the directory is looser. Returns True when changed."""
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            os.chmod(path, 0o700)
            return True
    except OSError:
        pass
    return False


def candidate_files() -> list[Path]:
    """Tier-2 credential files, in strict priority order."""
    files: list[Path] = []
    override = get_env("RHODAWK_CREDENTIALS_FILE")
    if override:
        files.append(Path(override).expanduser())
    files.append(vault_env_file())
    files.append(ROOT_SECRETS_FILE)
    # De-dupe while preserving order (e.g. override == vault file).
    seen: set[str] = set()
    unique: list[Path] = []
    for path in files:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


# ── Resolution core ───────────────────────────────────────────────────────────

def _derive_h1_pair(values: dict[str, str]) -> None:
    """Parse H1_TOKEN=user:token into H1_USERNAME + H1_API_TOKEN (first win).

    A bare H1_TOKEN without a colon is treated as the API token alone."""
    combined = values.get("H1_TOKEN", "")
    if not combined:
        return
    user, sep, token = combined.partition(":")
    if sep:
        if user and not values.get("H1_USERNAME"):
            values["H1_USERNAME"] = user
        if token and not values.get("H1_API_TOKEN"):
            values["H1_API_TOKEN"] = token
    elif not values.get("H1_API_TOKEN"):
        values["H1_API_TOKEN"] = combined


def _same_path(a: Path, b: Path) -> bool:
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except OSError:
        return str(a) == str(b)


def _resolve_all() -> tuple[dict[str, str], list[str]]:
    """Tiers 1+2 without touching os.environ.

    Returns (resolved values by var name, source file paths actually read)."""
    values: dict[str, str] = {}
    sources: list[str] = []

    # Tier 1: already-exported environment values (non-empty only).
    for var in _LOOKUP_VARS:
        current = os.environ.get(var)
        if current:
            values[var] = current

    # Tier 2: credential files, first hit wins per variable.
    root_secrets = ROOT_SECRETS_FILE
    for path in candidate_files():
        try:
            if not path.is_file():
                continue
            _tighten_file_perms(path)
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        sources.append(str(path))
        parsed = parse_env_text(text)
        for key, value in parsed.items():
            if key in _LOOKUP_VARS and value and key not in values:
                values[key] = value
        # /root/.secrets/h1_api legacy form: a single bare "user:token" line.
        if (_same_path(path, root_secrets)
                and not any(key.startswith("H1_") for key in parsed)):
            raw = text.strip()
            if raw and "=" not in raw and "\n" not in raw and ":" in raw:
                user, _, token = raw.partition(":")
                if user and token:
                    values.setdefault("H1_USERNAME", user)
                    values.setdefault("H1_API_TOKEN", token)

    _derive_h1_pair(values)
    return values, sources


def _export_nonempty(values: dict[str, str]) -> None:
    """Tier 3: export only non-empty values; blanks are ignored, never
    overwriting an already-exported non-empty value."""
    for var, value in values.items():
        if value and not os.environ.get(var):
            os.environ[var] = value


def _enforce_vault_perms() -> None:
    """Enforce 0o700 on ~/.rhodawk and 0o600 on ~/.rhodawk/.env."""
    directory = vault_dir()
    if directory.is_dir():
        _tighten_dir_perms(directory)
    env_file = vault_env_file()
    if env_file.is_file():
        _tighten_file_perms(env_file)


# ── Status / summaries (redacted by construction) ─────────────────────────────

def group_status(group: dict, values: dict[str, str]) -> str:
    """READY when at least one credential route in the group is complete."""
    for route in group["paths"]:
        if all(values.get(var) for var in route):
            return STATUS_READY
    return STATUS_SKIPPED


def status_rows(values: dict[str, str] | None = None) -> list[tuple[str, str, str]]:
    """Redacted (label, status, detail) rows for `rhodawk doctor` and the
    --verify JSON. Details contain variable NAMES only — never values."""
    if values is None:
        values, _ = _resolve_all()
    rows: list[tuple[str, str, str]] = []
    for group in CREDENTIAL_GROUPS:
        status = group_status(group, values)
        set_vars = [f["var"] for f in group["fields"] if values.get(f["var"])]
        blank_vars = [f["var"] for f in group["fields"] if not values.get(f["var"])]
        if group["id"] == "recon_intel":
            # PDCP and Chaos are independent tools -> one doctor row each.
            details = {
                "PDCP_API_KEY": ("PDCP_API_KEY set",
                                 "PDCP_API_KEY blank — premium subfinder/httpx "
                                 "sources + CAP_ASN_ENUM off"),
                "CHAOS_API_KEY": ("CHAOS_API_KEY set",
                                  "CHAOS_API_KEY blank — Chaos public recon "
                                  "dataset off"),
            }
            for var in ("PDCP_API_KEY", "CHAOS_API_KEY"):
                ok_detail, blank_detail = details[var]
                rows.append((("PDCP" if var == "PDCP_API_KEY" else "Chaos"),
                             STATUS_READY if values.get(var) else STATUS_SKIPPED,
                             ok_detail if values.get(var) else blank_detail))
            continue
        if status == STATUS_READY:
            detail = "set: " + ", ".join(set_vars)
        else:
            detail = "blank: " + (", ".join(blank_vars) or "all keys")
        if group["id"] == "llm_providers":
            # Doctor-friendly sentence-case label (matches "LLM keys" wording).
            rows.append(("LLM providers", status, detail))
            continue
        rows.append((group["name"], status, detail))
    for tool in KEYLESS_TOOLS:
        rows.append((tool["name"], STATUS_KEYLESS, "no credentials required"))
    return rows


def print_tool_credential_table() -> None:
    """Tool-to-credential map: every tool/platform, the exact env vars it
    needs, and what happens when a key is left blank."""
    print("Tool-to-credential map — which tool needs which env vars")
    print()
    for idx, group in enumerate(CREDENTIAL_GROUPS, start=1):
        print(f"  [{idx}] {group['name']} — tools: {group['tools']}")
        keys = ", ".join(f["var"] + ("*" if f["secret"] else "")
                         for f in group["fields"])
        print(f"        keys     : {keys}")
        print(f"        if blank : {group['blank_note']}")
    print()
    print("  Keyless tools (zero keys required):")
    for tool in KEYLESS_TOOLS:
        print(f"        {tool['name']:<22} — {tool['note']}")
    print()
    print("  * = secret value (masked getpass input). Press Enter on any")
    print("  field to skip it; skipped keys are stored blank (KEY=\"\") so you")
    print("  can fill them in later by editing ~/.rhodawk/.env directly.")


def print_redacted_summary(values: dict[str, str]) -> None:
    """Post-wizard summary: which tools are READY vs SKIPPED (blank) vs
    KEYLESS. Redacted: statuses and variable names only, never values."""
    print()
    print("Credential status (redacted summary):")
    for group in CREDENTIAL_GROUPS:
        status = group_status(group, values)
        set_vars = [f["var"] for f in group["fields"] if values.get(f["var"])]
        blank_vars = [f["var"] for f in group["fields"] if not values.get(f["var"])]
        detail = ("set: " + ", ".join(set_vars) if status == STATUS_READY
                  else "blank: " + (", ".join(blank_vars) or "all keys"))
        print(f"  {group['name']:<26} {status:<15} {detail}")
    for tool in KEYLESS_TOOLS:
        print(f"  {tool['name']:<26} {STATUS_KEYLESS:<15} {tool['note']}")


# ── Vault file writer ─────────────────────────────────────────────────────────

def _env_quote(value: str) -> str:
    """Quote a value for the vault file; unquoted fallback when the value
    itself contains a double quote."""
    if '"' in value:
        return value
    return f'"{value}"'


def write_env_file(values: dict[str, str], path: Path | None = None) -> Path:
    """Write the vault with ALL managed keys, organized by commented tool
    sections. Populated when configured; blank (KEY="") when skipped.

    Enforces 0o700 on the directory and 0o600 on the file. The write is
    atomic: content lands in a freshly created 0600 temp file that is
    os.replace()d over the target, so a pre-existing loose-permission vault
    is never readable while partially rewritten, and the new file's 0600
    mode is guaranteed even if the old file was looser (release audit R-14).
    Values containing newlines are rejected outright — one injected CR/LF
    would smuggle an extra KEY=value line into the .env file (audit L-10)."""
    target = Path(path) if path is not None else vault_env_file()
    target.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(target.parent, 0o700)
    for field_group in CREDENTIAL_GROUPS:
        for field in field_group["fields"]:
            value = values.get(field["var"], "")
            if "\n" in value or "\r" in value:
                raise ValueError(
                    f"{field['var']}: credential values may not contain "
                    f"newline characters (they would inject extra keys into "
                    f"the .env file)")
    lines = [
        "# RhodawkAI Bounty Hunter credential vault — managed by rhodawk/tools/credentials.py",
        "# Perms: 0600 (auto-tightened) · directory ~/.rhodawk is 0700.",
        '# A blank value ("") means "not configured" — downstream tools treat',
        "# it as unset. Fill values in directly, or re-run:",
        "#   python3 -m rhodawk.tools.credentials --setup",
        "# NEVER commit this file or paste its values into chat/tickets/logs.",
        "",
    ]
    for group in CREDENTIAL_GROUPS:
        lines.append("# " + "=" * 66)
        lines.append(f"# {group['name']}")
        lines.append(f"# Tools: {group['tools']}")
        lines.append("# " + "=" * 66)
        for field in group["fields"]:
            value = values.get(field["var"], "")
            lines.append(f"{field['var']}={_env_quote(value)}")
        lines.append("")
    lines.append("# Keyless tools (no credentials needed): "
                 + ", ".join(t["name"] for t in KEYLESS_TOOLS))
    payload = "\n".join(lines) + "\n"
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent),
                                    prefix=".vault-", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
    except BaseException:
        try:
            os.close(fd)  # a failed fdopen already closed it — ignore EBADF
        except OSError:
            pass
        tmp_path.unlink(missing_ok=True)
        raise
    return target


# ── HackerOne live verification (zero secret leakage) ─────────────────────────

def _http_request(url: str, headers: dict[str, str], timeout: float) -> int:
    """One HTTP GET returning the status code (isolated for test mocking)."""
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return int(response.getcode())


def verify_h1_auth(username: str, token: str,
                   timeout: float = 10.0) -> tuple[int, str]:
    """Live-check H1 REST credentials with HTTP Basic auth.

    Returns (http_code, "VALID"|"INVALID"). HTTP 200 -> VALID, anything
    else -> INVALID. The Authorization header (which carries the secret) is
    never printed, logged, or included in error messages."""
    if not username or not token:
        return 0, "INVALID"
    auth = base64.b64encode(f"{username}:{token}".encode("utf-8")).decode("ascii")
    headers = {
        "Authorization": f"Basic {auth}",
        "Accept": "application/json",
        "User-Agent": "rhodawk-credentials/1.0",
    }
    try:
        code = _http_request(H1_VERIFY_URL, headers, timeout)
    except urllib.error.HTTPError as exc:
        code = int(exc.code)
    except Exception:
        # Network unreachable / timeout / DNS failure: no verdict possible.
        return 0, "INVALID"
    return code, ("VALID" if code == 200 else "INVALID")


def _print_h1_auth_line(values: dict[str, str]) -> str | None:
    """Print the one-line H1 verdict — `H1_AUTH: HTTP <code> (VALID|INVALID)`
    — and return it, only when both H1 credential parts are configured."""
    username = values.get("H1_USERNAME", "")
    token = values.get("H1_API_TOKEN", "")
    if not (username and token):
        return None
    code, label = verify_h1_auth(username, token)
    line = f"H1_AUTH: HTTP {code} ({label})"
    print(line)
    return line


# ── Interactive bootstrap wizard ──────────────────────────────────────────────

def _prompt_field(field: dict, current: str,
                  input_fn, getpass_fn) -> str:
    """Prompt once for a field. Enter skips cleanly (keeps any current
    value, otherwise blank). EOF (piped/closed stdin) counts as skip."""
    var, secret = field["var"], field["secret"]
    if current:
        shown = " <set>" if secret else current
        mode = f" [current: {shown}, Enter=keep]"
    else:
        mode = " [Enter=skip]"
    prompt = f"  {var}{mode} — {field['desc']}: "
    try:
        raw = getpass_fn(prompt) if secret else input_fn(prompt)
    except EOFError:
        return ""
    raw = (raw or "").strip()
    return raw or current


def run_interactive_onboarding(input_fn=None, getpass_fn=None) -> dict[str, str]:
    """Group-by-group credential bootstrap wizard.

    1. Prints the tool-to-credential table.
    2. Prompts per group: non-secret fields via input(), secret fields via
       getpass (masked). Enter skips a field cleanly.
    3. Writes ~/.rhodawk/.env (0600, dir 0700) with ALL managed keys —
       populated if configured, blank (KEY="") if skipped — organized by
       commented tool sections.
    4. Live-checks H1 credentials when both parts were provided, printing
       only `H1_AUTH: HTTP <code> (VALID|INVALID)`.
    5. Prints the redacted READY / SKIPPED (blank) / KEYLESS summary.

    Returns the final values dict (secrets included — callers must not
    print it)."""
    input_fn = input_fn if input_fn is not None else input
    getpass_fn = getpass_fn if getpass_fn is not None else getpass.getpass

    print()
    print("══════════════════════════════════════════════════════════")
    print("  RhodawkAI Bounty Hunter credential bootstrap")
    print("══════════════════════════════════════════════════════════")
    print_tool_credential_table()

    # Existing values (environment or an older vault) can be kept with Enter.
    current, _ = _resolve_all()

    values: dict[str, str] = {}
    for group in CREDENTIAL_GROUPS:
        print(f"\n── {group['name']} ── ({group['tools']})")
        for field in group["fields"]:
            values[field["var"]] = _prompt_field(
                field, current.get(field["var"], ""), input_fn, getpass_fn)

    path = write_env_file(values)
    print(f"\n[+] vault written: {path} (0600)")

    _print_h1_auth_line(values)
    print_redacted_summary(values)
    return values


# ── 4-tier auto-loader ────────────────────────────────────────────────────────

def load_credentials(interactive: bool = False,
                     verify_live: bool = False) -> dict:
    """Load platform credentials into os.environ (non-empty only).

    Tiers: (1) already-exported os.environ values, (2) credential files in
    order $RHODAWK_CREDENTIALS_FILE -> ~/.rhodawk/.env ->
    /root/.secrets/h1_api with permissions auto-tightened to 0o600,
    (3) only non-empty values exported (blank KEY="" ignored), (4) optional
    interactive onboarding on TTY when no vault exists yet.

    Returns a redacted result dict: auth_mode ("authenticated_rest" when H1
    credentials are present, else "keyless_public"), vault path, source
    files, per-group status, configured/blank variable names. When
    verify_live=True and H1 credentials are present, adds "h1_auth":
    "HTTP <code> (VALID|INVALID)".
    """
    values, sources = _resolve_all()
    _export_nonempty(values)
    _enforce_vault_perms()

    auth_mode = ("authenticated_rest"
                 if values.get("H1_USERNAME") and values.get("H1_API_TOKEN")
                 else "keyless_public")

    # Tier 4: first-run interactive onboarding (TTY only, no vault yet).
    if interactive and not vault_env_file().exists() and _stdin_isatty():
        wizard_values = run_interactive_onboarding()
        for var, value in wizard_values.items():
            if value and not values.get(var):
                values[var] = value
                os.environ[var] = value
        auth_mode = ("authenticated_rest"
                     if values.get("H1_USERNAME") and values.get("H1_API_TOKEN")
                     else "keyless_public")

    result: dict = {
        "auth_mode": auth_mode,
        "vault_file": str(vault_env_file()),
        "vault_present": vault_env_file().exists(),
        "sources": sources,
        "status": {g["name"]: group_status(g, values) for g in CREDENTIAL_GROUPS},
        "configured": [v for v in ALL_MANAGED_VARS if values.get(v)],
        "blank": [v for v in ALL_MANAGED_VARS if not values.get(v)],
    }
    if verify_live and auth_mode == "authenticated_rest":
        code, label = verify_h1_auth(values["H1_USERNAME"], values["H1_API_TOKEN"])
        result["h1_auth"] = f"HTTP {code} ({label})"
    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="credentials.py",
        description="RhodawkAI Bounty Hunter multi-platform credential vault "
                    "(setup / verify; zero secret leakage — statuses only)",
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--setup", action="store_true",
                       help="run the interactive bootstrap wizard "
                            "(writes ~/.rhodawk/.env, chmod 600)")
    modes.add_argument("--verify", action="store_true",
                       help="print a redacted credential status JSON "
                            "(never prints values)")
    args = parser.parse_args(argv)

    if args.setup:
        run_interactive_onboarding()
        return 0
    if args.verify:
        result = load_credentials(interactive=False, verify_live=True)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
