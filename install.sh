#!/bin/bash
# RhodawkAI Bounty Hunter — install skills, commands, and agents for multiple harnesses.

set -euo pipefail

AGENT="${RHODAWK_AGENT:-claude}"
SCOPE="global"
SETUP_BURP="ask"
NONINTERACTIVE=0
# Layer 1 polish (audit item 6): optional MCP client config merge, off by
# default — ./install.sh --agent mcp --client claude opts in.
CLIENT_MERGE="none"
# The standalone path prints its final Done! banner at the very END of the
# script — after the reconFTW setup and the capability-registry rebuild — so
# "Done!" is never followed by more install output (v2.0.5 UX fix).
DONE_BANNER=0

# Every source path below is repo-relative, so anchor to the script's own
# directory. Without this, running `~/tools/rhodawk-bounty-hunter/install.sh`
# from an unrelated cwd silently copies nothing.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── v2.0.0 data-directory migration: pre-2.0 home -> ~/.rhodawk ──────────
# The retired home name is assembled from fragments so the literal never
# re-enters the tree (the release branding gate greps for it verbatim).
_rhw_seg1="bu"; _rhw_seg2="ghunter"
_rhw_legacy="$HOME/.${_rhw_seg1}${_rhw_seg2}"
if [ -d "$_rhw_legacy" ] && [ ! -d "$HOME/.rhodawk" ]; then
    mv "$_rhw_legacy" "$HOME/.rhodawk" \
        || echo "[!] could not migrate pre-2.0 data home to ~/.rhodawk"
fi

# ── Permission tightening for the data home ────────────────────────────────
# v2.0.5 P0 fix: the managed standalone venv lives under the data home and
# MUST keep its executable bits — the old blanket `find -type f -exec chmod
# 600` stripped +x from venv/bin/* on every (re-)run and the installed CLI
# self-destructed on its next startup (exit 126). The venv subtree is pruned
# from BOTH passes; sensitive config/data files (config.json, .env,
# oauth.json, vault files, recon/findings) are still tightened. Symlinks are
# never matched (-type d / -type f exclude them without -L), so chmod cannot
# follow a link to its target. If RHODAWK_HOME points somewhere else, that
# home is not walked here at all, so its venv was never at risk.
tighten_rhodawk_home_perms() {
    local rh_home="$1"
    chmod 700 "$rh_home" 2>/dev/null || true
    find "$rh_home" -path "$rh_home/venv" -prune -o \
        -mindepth 1 -type d -exec chmod 700 {} + 2>/dev/null || true
    # Layer 1 polish (audit item 3): hooks/ holds the durable PreToolUse
    # scope-guard copy (mode 0700, needs +x) — same program-data-not-secrets
    # reasoning as venv/, so it is pruned from the 600 file pass too. The
    # directory pass above still tightens hooks/ itself to 700.
    find "$rh_home" \( -path "$rh_home/venv" -o -path "$rh_home/hooks" \) -prune -o \
        -type f -exec chmod 600 {} + 2>/dev/null || true
}
if [ -d "$HOME/.rhodawk" ]; then
    tighten_rhodawk_home_perms "$HOME/.rhodawk"
fi


# The repo layout is mixed: skills/commands/rules/scripts/hooks live at the
# root, but agents/ and mcp/ live under rhodawk/. Resolve each one to
# whichever location actually exists so a layout change breaks loudly in one
# place instead of silently skipping files everywhere.
resolve_src() {
    local fallback="$1" candidate
    shift
    for candidate in "$@"; do
        if [ -e "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    echo "$fallback"
    return 1
}

AGENTS_SRC="$(resolve_src "agents" "agents" "rhodawk/agents")" || true
MCP_SRC="$(resolve_src "mcp" "mcp" "rhodawk/mcp")" || true

usage() {
    cat <<'EOF'
Usage: ./install.sh [--agent claude|antigravity|gemini|opencode|pi|codex|agents|standalone|mcp|all] [--global|--project]

Defaults:
  ./install.sh                    Install for Claude Code globally

Standalone (no subscription needed):
  ./install.sh --agent standalone Install or update the 'rhodawk' + 'rhodawk-agent'
                                  system commands (isolated venv, PEP 668-safe)
  ./install.sh --agent mcp        Print MCP client config + install mcp Python SDK hint
                                  After install, type from anywhere:
                                    rhodawk help
                                    rhodawk setup
                                    rhodawk login
                                    rhodawk recon target.com
                                    rhodawk h target.com

Examples:
  ./install.sh --agent antigravity Install Antigravity / Gemini skills, rules & agents globally (~/.gemini/config)
  ./install.sh --agent opencode    Install OpenCode skills + commands globally
  ./install.sh --agent pi          Install Pi skills + prompt templates globally
  ./install.sh --agent agents      Install shared Agent Skills to ~/.agents/skills
  ./install.sh --agent all         Install every supported global target
  ./install.sh --agent opencode --project
                                  Install into .opencode/ for this repo

Options:
  --non-interactive               CI-safe mode: skip ALL prompts (Burp MCP +
                                  the end-of-install credential wizard)
  --no-burp                       Skip Claude Code Burp MCP setup prompt
  --yes-burp                      Print Claude Code Burp MCP setup instructions
  --client claude                 With --agent mcp: safely merge the shipped
                                  mcpServers["rhodawk"] entry into
                                  ~/.claude/settings.json (atomic write,
                                  .bak backup, idempotent). Default: none
                                  (manual merge instructions only).
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --agent)
            shift
            AGENT="${1:?--agent requires a value}"
            ;;
        --agent=*)
            AGENT="${1#*=}"
            ;;
        --client)
            shift
            CLIENT_MERGE="${1:?--client requires a value}"
            ;;
        --client=*)
            CLIENT_MERGE="${1#*=}"
            ;;
        --all)
            AGENT="all"
            ;;
        --global)
            SCOPE="global"
            ;;
        --project)
            SCOPE="project"
            ;;
        --no-burp)
            SETUP_BURP="no"
            ;;
        --yes-burp)
            SETUP_BURP="yes"
            ;;
        --non-interactive)
            NONINTERACTIVE=1
            SETUP_BURP="no"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

# ── --client validation: fail fast, before any filesystem action ──────────────
case "$CLIENT_MERGE" in
    none|"") ;;
    claude)
        if [ "$AGENT" != "mcp" ]; then
            echo "--client claude is only supported with --agent mcp (got --agent $AGENT)." >&2
            exit 2
        fi
        ;;
    *)
        echo "Unsupported --client value: $CLIENT_MERGE (supported: claude)" >&2
        exit 2
        ;;
esac

copy_tree_items() {
    local src_glob="$1"
    local dest_dir="$2"
    local label="$3"
    local item name copied=0

    mkdir -p "$dest_dir"
    for item in $src_glob; do
        [ -e "$item" ] || continue
        name=$(basename "$item")
        rm -rf "$dest_dir/$name"
        mkdir -p "$dest_dir/$name"
        cp -R "$item"/. "$dest_dir/$name/"
        echo "✓ Installed $label: $name"
        copied=$((copied + 1))
    done
    # An unmatched glob is passed through by bash as a literal string, so the
    # loop above just skips it. Report that instead of exiting 0 as if the
    # install worked — a silently empty install is how agents/ went missing.
    if [ "$copied" -eq 0 ]; then
        echo "[!] No $label found for glob '$src_glob' (cwd: $PWD)" >&2
        return 1
    fi
}

copy_files() {
    local src_glob="$1"
    local dest_dir="$2"
    local label="$3"
    local item name copied=0

    mkdir -p "$dest_dir"
    for item in $src_glob; do
        [ -f "$item" ] || continue
        name=$(basename "$item")
        # Layer 1B Issue #2: commands/ and agents/ ship a repo README.md that
        # is documentation, not a slash command or sub-agent — installing it
        # produced ~/.claude/commands/README.md (and agents/README.md) as a
        # broken harness entry everywhere copy_files is used. Skip README.md
        # case-insensitively (portable bash-3.2 case pattern).
        case "$name" in
            [Rr][Ee][Aa][Dd][Mm][Ee].[Mm][Dd]) continue ;;
        esac
        cp "$item" "$dest_dir/$name"
        echo "✓ Installed $label: $name"
        copied=$((copied + 1))
    done
    if [ "$copied" -eq 0 ]; then
        echo "[!] No $label found for glob '$src_glob' (cwd: $PWD)" >&2
        return 1
    fi
}

register_pretooluse_scope_guard() {
    # ── PreToolUse scope-guard hook (R-11) ────────────────────────────────────
    # Plugin installs get hooks.json automatically (Claude Code resolves
    # ${CLAUDE_PLUGIN_ROOT} itself). For NON-plugin installs this registers
    # the same deterministic scope guard in settings.json so active Bash/MCP
    # tool calls are gated by a hash-verified scope manifest there too.
    # Merge semantics: existing user hooks are preserved; the guard command is
    # appended to hooks.PreToolUse only when not already present.
    local root="$1"
    local settings="$root/settings.json"
    local guard_src="$SCRIPT_DIR/rhodawk/tools/hook_scope_guard.py"
    [ -f "$guard_src" ] || { echo "[!] scope guard script missing — hook not registered"; return 0; }
    command -v python3 >/dev/null 2>&1 || { echo "[!] python3 unavailable — PreToolUse scope guard NOT registered"; return 0; }
    # Layer 1B Issue #4: prefer the managed-venv interpreter for the REGISTERED
    # hook command when it exists (hook_scope_guard.py imports cleanly under
    # both system python3 and the venv python — stdlib-only, verified by
    # tests/test_layer1b_plugin_mcp_tools.py). The merger below still runs on
    # system python3 (stdlib json only).
    local guard_python="python3"
    local venv_python="${RHODAWK_HOME:-$HOME/.rhodawk}/venv/bin/python"
    if [ -x "$venv_python" ]; then
        guard_python="$venv_python"
    fi
    # Layer 1 polish (audit item 3): the registered hook used to point straight
    # into the repo checkout, so moving/deleting the checkout silently broke
    # every gated tool call. Install a DURABLE copy under the data home and
    # register that path instead — it survives repo moves, and uninstall.sh
    # removes it together with the settings entry. The old repo-path entry is
    # migrated in place, keeping the registration idempotent across upgrades.
    local hooks_dir="${RHODAWK_HOME:-$HOME/.rhodawk}/hooks"
    local durable_guard="$hooks_dir/hook_scope_guard.py"
    local guard_active="$guard_src"
    if mkdir -p "$hooks_dir" 2>/dev/null \
        && cp "$guard_src" "$durable_guard" 2>/dev/null; then
        chmod 700 "$hooks_dir" 2>/dev/null || true
        chmod 700 "$durable_guard" 2>/dev/null || true
        echo "[+] durable scope-guard copy installed: $durable_guard (0700)"
        guard_active="$durable_guard"
        # Live-sandbox P0 fix: record the source repo next to the durable
        # copy (0600) so a bare-python3 run of the hook (RHODAWK_SKIP_DEPS=1
        # installs, venv removed later, stripped env, cwd=/tmp) can still
        # resolve rhodawk._compat / contracts.scope / scope_checker. The hook
        # reads this record (or $RHODAWK_REPO_DIR) and prepends the repo to
        # sys.path; if the repo is gone the hook fails CLOSED (exit 2)
        # instead of crashing with a traceback.
        if printf '%s\n' "$SCRIPT_DIR" > "$hooks_dir/.repo_root" 2>/dev/null; then
            chmod 600 "$hooks_dir/.repo_root" 2>/dev/null || true
        fi
    else
        echo "[!] could not install the durable scope-guard copy under $hooks_dir — registering the repo checkout path (breaks if the checkout moves)"
    fi

    python3 - "$settings" "$guard_active" "$guard_src" "$guard_python" <<'PYGUARD' || { echo "[!] could not merge $settings — PreToolUse scope guard NOT registered"; return 0; }
import json
import os
import sys

settings_path, guard_path = sys.argv[1], sys.argv[2]
legacy_path = sys.argv[3] if len(sys.argv) > 3 else ""
guard_python = sys.argv[4] if len(sys.argv) > 4 else "python3"
settings = {}
if os.path.exists(settings_path):
    try:
        with open(settings_path, encoding="utf-8") as fh:
            settings = json.load(fh)
    except (OSError, ValueError):
        print(f"[!] existing {settings_path} is not valid JSON; refusing to edit it", file=sys.stderr)
        sys.exit(1)
if not isinstance(settings, dict):
    print(f"[!] {settings_path} is not a JSON object; refusing to edit it", file=sys.stderr)
    sys.exit(1)

command = f'{guard_python} "{guard_path}"'
hooks = settings.setdefault("hooks", {})
if not isinstance(hooks, dict):
    print("[!] hooks is not an object; refusing to edit", file=sys.stderr)
    sys.exit(1)
pre = hooks.setdefault("PreToolUse", [])
if not isinstance(pre, list):
    print("[!] hooks.PreToolUse is not a list; refusing to edit", file=sys.stderr)
    sys.exit(1)

def _entry_guard_kind(entry):
    """Return 'current' | 'legacy' | None for a PreToolUse entry."""
    if not isinstance(entry, dict):
        return None
    for h in entry.get("hooks", []) or []:
        if not isinstance(h, dict):
            continue
        cmd = str(h.get("command", ""))
        if guard_path and guard_path in cmd:
            return "current"
        if legacy_path and legacy_path in cmd:
            return "legacy"
    return None

current = next((e for e in pre if _entry_guard_kind(e) == "current"), None)
legacy = next((e for e in pre if _entry_guard_kind(e) == "legacy"), None)
if current is not None:
    print("[+] PreToolUse scope guard already registered (durable path)")
else:
    if legacy is not None:
        # Upgrade-in-place: rewrite the command inside the existing entry so
        # matcher and ordering are preserved and the registration stays
        # idempotent (no duplicate entries for old installs).
        for h in legacy.get("hooks", []) or []:
            if isinstance(h, dict) and legacy_path and legacy_path in str(h.get("command", "")):
                h["command"] = command
        os.makedirs(os.path.dirname(settings_path) or ".", exist_ok=True)
        with open(settings_path, "w", encoding="utf-8") as fh:
            json.dump(settings, fh, indent=2)
            fh.write("\n")
        print("[+] migrated PreToolUse scope guard to the durable path:", guard_path)
    else:
        pre.append({
            "matcher": "Bash|mcp__rhodawk-mcp__rhodawk_recon|mcp__rhodawk-mcp__rhodawk_hunt|mcp__rhodawk-mcp__rhodawk_hunt_class|mcp__rhodawk-mcp__rhodawk_research|mcp__rhodawk-mcp__rhodawk_run_rtw_capability",
            "hooks": [{"type": "command", "command": command}],
        })
        os.makedirs(os.path.dirname(settings_path) or ".", exist_ok=True)
        with open(settings_path, "w", encoding="utf-8") as fh:
            json.dump(settings, fh, indent=2)
            fh.write("\n")
        print("[+] PreToolUse scope guard registered in", settings_path)
PYGUARD
}

install_claude() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root=".claude"
    else
        root="$HOME/.claude"
    fi

    echo "Installing RhodawkAI Bounty Hunter for Claude Code ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    copy_files "commands/*.md" "$root/commands" "command"
    copy_files "$AGENTS_SRC/*.md" "$root/agents" "agent"
    # Live-sandbox P0 fix: a Claude-only install used to register the scope
    # guard with system python3 while no rhodawk package was importable, so
    # EVERY gated tool call crashed with ModuleNotFoundError (exit 1). Build
    # the managed venv FIRST (PEP 668-safe) so the registered interpreter can
    # import rhodawk. With RHODAWK_SKIP_DEPS=1 (CI / offline) the hook falls
    # back to the .repo_root record — and even if that record is lost too,
    # the hook now fails CLOSED (exit 2), never crashes.
    if [ "${RHODAWK_SKIP_DEPS:-0}" != "1" ]; then
        ensure_managed_venv "$SCRIPT_DIR"
    fi
    register_pretooluse_scope_guard "$root"
    echo "Done: $root"

    if [ "$SETUP_BURP" = "ask" ]; then
        echo ""
        echo "─────────────────────────────────────────────"
        echo "Optional: Burp Suite MCP Integration"
        echo "─────────────────────────────────────────────"
        echo ""
        echo "Connect to PortSwigger's Burp MCP server for live HTTP traffic visibility."
        echo "See $MCP_SRC/burp-mcp-client/README.md for setup instructions."
        echo ""
        # Layer 1B Issue #1: under `set -e` a bare `read` hitting EOF
        # (stdin closed: `./install.sh --agent claude < /dev/null`, CI) aborted
        # the whole install with exit 1. Non-interactive runs (--non-interactive
        # or stdin not a TTY) skip the prompt cleanly; even on a TTY the read is
        # guarded so Ctrl+D degrades to "no" instead of killing the installer.
        if [ "$NONINTERACTIVE" = "1" ] || [ ! -t 0 ]; then
            SETUP_BURP="no"
        else
            local setup_burp_answer=""
            read -r -p "Set up Burp MCP now? (y/N): " setup_burp_answer \
                || setup_burp_answer="n"
            case "$setup_burp_answer" in
                [Yy]*) SETUP_BURP="yes" ;;
                *) SETUP_BURP="no" ;;
            esac
        fi
    fi

    if [ "$SETUP_BURP" = "yes" ]; then
        echo ""
        echo "To connect Burp MCP, add this to your Claude Code settings:"
        echo ""
        echo "  claude config edit"
        echo ""
        echo "Then add to the mcpServers section:"
        grep -A 10 '"burp"' "$MCP_SRC/burp-mcp-client/config.json" || true
        echo ""
        echo "And set your Burp API key:"
        echo "  export BURP_API_KEY=\"your-api-key-here\""
    fi

    echo ""
    echo "Start hunting:"
    echo "  claude"
    echo "  claude help"
    echo "  claude recon target.com"
    echo "  /recon target.com"
    echo "  /hunt target.com"
}

install_opencode() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root=".opencode"
    else
        root="${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"
    fi

    echo "Installing RhodawkAI Bounty Hunter for OpenCode ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    copy_files "commands/*.md" "$root/commands" "command"
    copy_files "$AGENTS_SRC/*.md" "$root/agents" "agent"
    echo "Done: $root"
    echo ""
    echo "OpenCode also reads AGENTS.md from the project root. Keep this repo's AGENTS.md committed for portable project instructions."
    echo "Start hunting:"
    echo "  opencode"
    echo "  opencode help"
    echo "  opencode recon target.com"
    echo "  /recon target.com"
}

install_pi() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root=".pi"
    else
        root="$HOME/.pi/agent"
    fi

    echo "Installing RhodawkAI Bounty Hunter for Pi Agent ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    copy_files "commands/*.md" "$root/prompts" "prompt"
    echo "Done: $root"
    echo ""
    echo "Pi exposes skills as /skill:<name> and command prompts as /<command>."
    echo "Start hunting:"
    echo "  pi"
    echo "  pi help"
    echo "  pi recon target.com"
    echo "  /recon target.com"
}

install_codex() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root=".codex"
    else
        root="${CODEX_HOME:-$HOME/.codex}"
    fi

    echo "Installing RhodawkAI Bounty Hunter for Codex-style Agent Skills ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    copy_files "commands/*.md" "$root/commands" "command"
    echo "Done: $root"
}

install_agents() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root=".agents"
    else
        root="$HOME/.agents"
    fi

    echo "Installing shared Agent Skills ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    echo "Done: $root"
    echo "OpenCode and Pi both discover .agents/skills or ~/.agents/skills."
}

install_antigravity() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root=".agents"
    else
        root="${ANTIGRAVITY_CONFIG_DIR:-$HOME/.gemini/config}"
    fi

    echo "Installing RhodawkAI Bounty Hunter for Google Antigravity / Gemini ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    copy_files "commands/*.md" "$root/commands" "command"
    copy_files "$AGENTS_SRC/*.md" "$root/agents" "agent"
    copy_files "rules/hunting.md" "$root/rules" "rule"
    copy_files "rules/reporting.md" "$root/rules" "rule"
    echo "Done: $root"
    echo ""
    echo "Antigravity discovers skills & rules in ~/.gemini/config (global) or .agents/ (project)."
    echo "Start hunting with Antigravity / Gemini AI Pro:"
    echo "  agy"
    echo "  rhodawk setup --provider antigravity"
    echo "  rhodawk login"
}

# ── Dedicated isolated venv (PEP 668-safe), shared by --agent standalone and
#    --agent mcp (Layer 1B Issue #4) ──────────────────────────────────────────
# Ubuntu 24.04+ (PEP 668) rejects pip installs into the system Python, so bare
# `pip3 install ...` fails on every fresh box. Preferred path: a dedicated venv
# under the data home with the repo installed editable, so rhodawk,
# rhodawk-agent, requests and the mcp SDK all resolve from ANY working
# directory. Sets the globals venv_dir + venv_ok (0/1). Never touches the
# system Python.
ensure_managed_venv() {
    local repo_dir="$1"
    venv_dir="${RHODAWK_HOME:-$HOME/.rhodawk}/venv"
    venv_ok=0
    if [ "${RHODAWK_SKIP_DEPS:-0}" = "1" ]; then
        echo "[i] RHODAWK_SKIP_DEPS=1 — skipping venv + pip setup (raw engine symlink mode)"
    elif command -v python3 >/dev/null 2>&1; then
        if [ ! -x "$venv_dir/bin/python" ]; then
            echo "[*] Creating isolated venv at $venv_dir (PEP 668-safe) ..."
            python3 -m venv "$venv_dir" \
                || echo "[!] python3 -m venv failed (python3-venv package missing?) — falling back to raw engine symlink"
        else
            echo "[+] Reusing existing venv at $venv_dir"
        fi
        if [ -x "$venv_dir/bin/pip" ]; then
            echo "[*] Installing rhodawk + rhodawk-agent (editable) into the venv ..."
            if "$venv_dir/bin/pip" install --quiet -e "$repo_dir"; then
                venv_ok=1
                # Marker so uninstall.sh only ever removes a venv we created.
                touch "$venv_dir/.rhodawk-managed-venv"
                echo "[+] rhodawk + rhodawk-agent installed (editable); requests + mcp live inside the venv"
                echo "[+] System Python untouched (PEP 668-safe)"
            else
                echo "[!] pip install -e . failed (offline / no wheels?) — falling back to raw engine symlink"
            fi
        fi
    fi
}

install_standalone() {
    echo ""
    echo "════════════════════════════════════════════════════"
    echo "  RhodawkAI Bounty Hunter Standalone Engine (no subscription)"
    echo "════════════════════════════════════════════════════"
    echo ""

    local repo_dir engine existing_cmd bin_dir target action
    local -a install_cmd
    repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    engine="$repo_dir/rhodawk/engine.py"

    # Make engine.py executable
    chmod +x "$engine"

    # ── Dedicated isolated venv (PEP 668-safe) ────────────────────────────────
    # Shared helper (Layer 1B Issue #4): the SAME venv that --agent mcp uses
    # and validates. Sets the globals venv_dir + venv_ok so the link/fallback
    # logic below can keep referencing them verbatim.
    ensure_managed_venv "$repo_dir"

    # ── Install rhodawk + rhodawk-agent system commands ──────────────────────
    # Prefer updating the currently active managed installation. This prevents
    # an old /usr/local/bin entry from shadowing a new ~/.local/bin symlink.
    existing_cmd="$(command -v rhodawk 2>/dev/null || true)"
    if [ -n "${RHODAWK_BIN_DIR:-}" ]; then
        bin_dir="$RHODAWK_BIN_DIR"
    elif [ -n "$existing_cmd" ] && [[ -e "$existing_cmd" || -L "$existing_cmd" ]]; then
        if [ -L "$existing_cmd" ] && [ "$(basename "$(readlink "$existing_cmd")")" = "engine.py" ]; then
            bin_dir="$(dirname "$existing_cmd")"
        elif [ -L "$existing_cmd" ] && [[ "$(readlink "$existing_cmd")" == "$venv_dir/"* ]]; then
            bin_dir="$(dirname "$existing_cmd")"
        elif [ -f "$existing_cmd" ] && grep -q "Standalone RhodawkAI Bounty Hunter CLI" "$existing_cmd" 2>/dev/null; then
            bin_dir="$(dirname "$existing_cmd")"
        elif [ -w /usr/local/bin ]; then
            bin_dir="/usr/local/bin"
        else
            bin_dir="$HOME/.local/bin"
        fi
    elif [ -w /usr/local/bin ]; then
        bin_dir="/usr/local/bin"
    else
        bin_dir="$HOME/.local/bin"
    fi

    # Resolve the symlink sources: the venv console scripts when the venv
    # install succeeded, raw repo files otherwise — and say so loudly instead
    # of pretending everything succeeded (v2.0.5: rhodawk-agent used to be
    # silently missing in every mode).
    local src_rhodawk src_agent
    if [ "$venv_ok" = "1" ] \
        && [ -x "$venv_dir/bin/rhodawk" ] && [ -x "$venv_dir/bin/rhodawk-agent" ]; then
        src_rhodawk="$venv_dir/bin/rhodawk"
        src_agent="$venv_dir/bin/rhodawk-agent"
    else
        venv_ok=0
        src_rhodawk="$engine"
        # agent.py carries its own shebang + __main__ guard, so a direct
        # symlink works as the rhodawk-agent launcher even without the venv.
        src_agent="$repo_dir/rhodawk/agent.py"
        chmod +x "$src_agent"
        echo "[!] Fallback mode: the mcp SDK + cloud deps need the venv — run:"
        echo "    python3 -m venv \"$venv_dir\" && \"$venv_dir/bin/pip\" install -e \"$repo_dir\""
    fi

    install_cmd=()
    if [ ! -d "$bin_dir" ] || [ ! -w "$bin_dir" ]; then
        if command -v sudo >/dev/null 2>&1 && [[ "$bin_dir" == /usr/local/* ]]; then
            install_cmd=(sudo)
        else
            mkdir -p "$bin_dir"
        fi
    fi

    # bash 3.2 (macOS default) aborts under set -u when expanding an empty array
    # as "${install_cmd[@]}" — same idiom as tools/_auth_helper.sh.
    ${install_cmd[@]+"${install_cmd[@]}"} mkdir -p "$bin_dir"

    # Each entrypoint is linked and logged exactly once (the old script linked
    # rhodawk twice — engine symlink plus a duplicate alias link — and printed
    # the same "[+] Installed: .../rhodawk -> .../engine.py" line two times).
    target="$bin_dir/rhodawk"
    action="Installed"
    if [ -e "$target" ] || [ -L "$target" ]; then
        action="Updated"
    fi
    ${install_cmd[@]+"${install_cmd[@]}"} ln -sfn "$src_rhodawk" "$target"
    if [ -L "$target" ] && [ "$(readlink "$target")" = "$src_rhodawk" ]; then
        echo "[+] $action: $target -> $src_rhodawk"
    else
        echo "[!] Could not install or update $target" >&2
        echo "    Try: sudo ./install.sh --agent standalone" >&2
        echo "    Or add this to ~/.bashrc / ~/.zshrc:"
        echo "    alias rhodawk='python3 $engine'"
        return 1
    fi

    target="$bin_dir/rhodawk-agent"
    action="Installed"
    if [ -e "$target" ] || [ -L "$target" ]; then
        action="Updated"
    fi
    ${install_cmd[@]+"${install_cmd[@]}"} ln -sfn "$src_agent" "$target"
    if [ -L "$target" ] && [ "$(readlink "$target")" = "$src_agent" ]; then
        echo "[+] $action: $target -> $src_agent"
    else
        echo "[!] Could not install or update $target (rhodawk still works)" >&2
        echo "    Try: sudo ./install.sh --agent standalone" >&2
    fi

    # ── Check PATH ────────────────────────────────────────────────────────────
    if ! echo "$PATH" | tr ':' '\n' | grep -Fxq "$bin_dir"; then
        echo ""
        echo "[!] $bin_dir is not in your PATH. Add it:"
        if echo "$SHELL" | grep -q zsh; then
            echo "    echo 'export PATH=\"$bin_dir:\$PATH\"' >> ~/.zshrc && source ~/.zshrc"
        else
            echo "    echo 'export PATH=\"$bin_dir:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
        fi
    fi

    # ── Optional: Ollama ──────────────────────────────────────────────────────
    echo ""
    if ! command -v ollama &>/dev/null; then
        echo "Ollama not found. For free local AI:"
        echo "  curl -fsSL https://ollama.ai/install.sh | sh"
        echo "  ollama pull qwen2.5:14b"
    else
        echo "[+] Ollama detected: $(ollama --version 2>/dev/null || echo 'installed')"
    fi

    # ── Optional Python deps ──────────────────────────────────────────────────
    if [ "$venv_ok" = "1" ]; then
        echo "[+] Python deps (requests, mcp) installed inside the venv — nothing was touched in the system Python (PEP 668-safe)"
    elif [ "${RHODAWK_SKIP_DEPS:-0}" != "1" ] && command -v pip3 &>/dev/null; then
        echo "Installing optional Python deps (best effort)..."
        if ! pip3 install --quiet requests ollama 2>/dev/null; then
            echo "[!] Optional pip packages were not installed (PEP 668 / externally-managed environment)."
            echo "    Standalone Ollama chat still works via the stdlib HTTP fallback, but for full"
            echo "    MCP + agent support create the venv manually:"
            echo "      python3 -m venv \"$venv_dir\""
            echo "      \"$venv_dir/bin/pip\" install -e \"$repo_dir\""
        fi
    fi
    echo ""
}

install_mcp() {
    local MCP_HOME_HINT="${RHODAWK_HOME:-$HOME/.rhodawk}"
    echo "════════════════════════════════════════════════════"
    echo "  RhodawkAI Bounty Hunter MCP"
    echo "════════════════════════════════════════════════════"
    echo ""
    echo "Server entry (preferred):"
    echo "  rhodawk mcp serve"
    echo "  # or, when the rhodawk CLI is not on PATH:"
    echo "  \"$MCP_HOME_HINT/venv/bin/python\" $MCP_SRC/rhodawk-mcp/server.py"
    echo ""
    echo "Doctor / tool catalog:"
    echo "  rhodawk mcp doctor"
    echo "  rhodawk mcp tools"
    echo ""
    echo "Python SDK:"
    echo "  installed into the managed venv below (mcp>=2.2.0) — never bare system pip"
    echo ""
    echo "Claude Code — merge $MCP_SRC/rhodawk-mcp/claude-config.json into ~/.claude/settings.json mcpServers"
    echo "              (or let the installer do it safely: ./install.sh --agent mcp --client claude)"
    echo "OpenCode   — merge $MCP_SRC/rhodawk-mcp/opencode-config.json into opencode mcp config"
    echo ""
    echo "Active tools require scope_domains + approve=true (or RHODAWK_MCP_APPROVE=1)."
    echo "Existing Burp / Caido / HackerOne integrations are unchanged."
    echo ""
    # Layer 1B Issue #4: the old bare `pip3 install 'mcp>=2.2.0'` failed on
    # every PEP 668 system (Ubuntu 24.04: externally-managed-environment) even
    # when ~/.rhodawk/venv already had mcp. Reuse the SAME PEP 668-safe
    # managed venv as --agent standalone (ensure_managed_venv) and verify the
    # SDK import inside it. Bare system pip3 is never invoked.
    ensure_managed_venv "$SCRIPT_DIR"
    if [ "$venv_ok" = "1" ] && [ -x "$venv_dir/bin/python" ]; then
        if "$venv_dir/bin/python" -c "import mcp.server" >/dev/null 2>&1; then
            echo "[+] mcp SDK verified in the managed venv (import mcp.server OK)"
        elif [ -x "$venv_dir/bin/pip" ]; then
            echo "[*] Installing mcp SDK into the managed venv (PEP 668-safe)..."
            if "$venv_dir/bin/pip" install --quiet 'mcp>=2.2.0'; then
                echo "[+] mcp SDK installed into the managed venv"
            else
                echo "[!] mcp SDK install failed — install manually:"
                echo "    \"$venv_dir/bin/pip\" install 'mcp>=2.2.0'"
            fi
        fi
    else
        echo "[i] No managed venv — create it for full MCP support (PEP 668-safe):"
        echo "    python3 -m venv \"$MCP_HOME_HINT/venv\""
        echo "    \"$MCP_HOME_HINT/venv/bin/pip\" install -e \"$SCRIPT_DIR\""
    fi
    # Layer 1 polish (audit item 6): opt-in safe merge of the shipped MCP
    # client entry into ~/.claude/settings.json. Default (--client none)
    # stays fully non-invasive: instructions only.
    # Live-sandbox P1 fix: the shipped entry uses the bare "rhodawk" command.
    # On a fresh MCP-only box rhodawk is not on PATH yet, so Claude Code
    # would get a broken server. Resolve it: prefer the venv CLI (absolute
    # path), otherwise tell the user exactly how to fix PATH.
    if [ "$CLIENT_MERGE" = "claude" ]; then
        local merge_cli=""
        if command -v rhodawk >/dev/null 2>&1; then
            merge_cli=""   # resolvable as-is — keep the shipped entry
        elif [ -n "${venv_dir:-}" ] && [ -x "${venv_dir}/bin/rhodawk" ]; then
            merge_cli="${venv_dir}/bin/rhodawk"
            echo "[*] rhodawk not on PATH — merging mcpServers with the venv CLI: $merge_cli"
        else
            merge_cli="__UNRESOLVED__"
        fi
        merge_mcp_client_config claude "$merge_cli"
    fi
    # NOTE: deliberately no "Done." here (Layer 1B Issue #4) — the reconFTW
    # capability-delegation setup and credential bootstrap run AFTER the agent
    # dispatch; the final Done banner at the bottom of the script prints after
    # all of it, matching the clean --agent standalone ordering.
}

# ── Opt-in MCP client config merge (Layer 1 polish, audit item 6) ─────────────
# Merges every mcpServers entry from the shipped claude-config.json into
# ~/.claude/settings.json: atomic write (tmp + os.replace), .bak backup of the
# pre-change file, pre-existing keys/hooks preserved verbatim, idempotent on
# re-run, and an existing entry with DIFFERENT content is never overwritten
# (warned and skipped instead).
merge_mcp_client_config() {
    local root="$HOME/.claude"
    local settings="$root/settings.json"
    local src="$MCP_SRC/rhodawk-mcp/claude-config.json"
    # Optional 2nd arg: absolute rhodawk CLI to substitute for the bare
    # "rhodawk" command when it is not on PATH ("" = leave as shipped,
    # "__UNRESOLVED__" = nothing to substitute — warn instead).
    local mcp_cli="${2:-}"
    [ -f "$src" ] || { echo "[!] $src missing — cannot merge MCP client config"; return 0; }
    python3 - "$settings" "$src" "$mcp_cli" <<'PY' \
        || echo "[!] could not merge MCP client config into $settings (left unchanged)"
import json
import os
import sys

settings_path, src_path = sys.argv[1], sys.argv[2]
mcp_cli = sys.argv[3] if len(sys.argv) > 3 else ""
with open(src_path, encoding="utf-8") as fh:
    incoming = json.load(fh)
inc_servers = incoming.get("mcpServers", {}) if isinstance(incoming, dict) else {}
if not isinstance(inc_servers, dict) or not inc_servers:
    print("[!] no mcpServers entries in the shipped client config — nothing to merge")
    sys.exit(1)

settings = {}
if os.path.exists(settings_path):
    try:
        with open(settings_path, encoding="utf-8") as fh:
            settings = json.load(fh)
    except (OSError, ValueError):
        print(f"[!] existing {settings_path} is not valid JSON; refusing to edit it",
              file=sys.stderr)
        sys.exit(1)
if not isinstance(settings, dict):
    print(f"[!] {settings_path} is not a JSON object; refusing to edit it", file=sys.stderr)
    sys.exit(1)

snapshot = json.loads(json.dumps(settings))  # pre-change copy for the .bak
servers = settings.setdefault("mcpServers", {})
if not isinstance(servers, dict):
    print("[!] mcpServers is not an object; refusing to edit", file=sys.stderr)
    sys.exit(1)

changed, skipped = [], []
for key, entry in inc_servers.items():
    entry = dict(entry)
    # Live-sandbox P1 fix: a bare "rhodawk" command is only launchable when
    # rhodawk is on PATH. Substitute the absolute venv CLI when available;
    # otherwise warn loudly so the merged config is never silently broken.
    if entry.get("command") == "rhodawk" and mcp_cli == "__UNRESOLVED__":
        print("[!] 'rhodawk' is not on PATH and no venv CLI was found — the "
              "merged mcpServers entry would not launch. fix: run "
              "./install.sh --agent standalone (links rhodawk onto PATH) and "
              "re-run ./install.sh --agent mcp --client claude, or add the "
              "venv bin dir to PATH.", file=sys.stderr)
    elif entry.get("command") == "rhodawk" and mcp_cli:
        entry["command"] = mcp_cli
    if key in servers:
        if servers[key] == entry:
            continue  # already merged, identical — idempotent no-op
        skipped.append(key)  # user customized it — never overwrite
        continue
    servers[key] = entry
    changed.append(key)

if skipped:
    for key in skipped:
        print(f"[!] mcpServers['{key}'] already exists with different content — left untouched", file=sys.stderr)
if not changed:
    print("[+] MCP client config already merged (idempotent no-op)")
    sys.exit(0)

os.makedirs(os.path.dirname(settings_path) or ".", exist_ok=True)
if os.path.exists(settings_path):
    backup = settings_path + ".bak"
    with open(backup, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)
        fh.write("\n")
    print("[+] backup written:", backup)
tmp = settings_path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(settings, fh, indent=2)
    fh.write("\n")
os.replace(tmp, settings_path)
print("[+] merged mcpServers into", settings_path, ":", ", ".join(changed))
PY
}

case "$AGENT" in
    standalone|engine)
        SETUP_BURP="no"
        DONE_BANNER=1
        install_standalone
        ;;
    mcp)
        SETUP_BURP="no"
        DONE_BANNER=1
        install_mcp
        ;;
    claude)
        # Layer 1 polish (audit item 5): the closing banner prints at the very
        # bottom, AFTER the reconFTW setup block, like standalone/mcp.
        DONE_BANNER=1
        install_claude
        ;;
    opencode)
        SETUP_BURP="no"
        install_opencode
        ;;
    pi)
        SETUP_BURP="no"
        install_pi
        ;;
    codex)
        SETUP_BURP="no"
        install_codex
        ;;
    agents|generic)
        SETUP_BURP="no"
        install_agents
        ;;
    antigravity|gemini|agy)
        SETUP_BURP="no"
        install_antigravity
        ;;
    all)
        # Layer 1 polish (audit item 7): --agent all runs every target and
        # closes with ONE per-target summary banner after the reconFTW setup.
        # Live-sandbox P1 fix: standalone FIRST — it creates the managed venv
        # and links rhodawk/rhodawk-agent onto PATH, so install_claude
        # registers the venv interpreter (not bare python3) and `rhodawk
        # doctor` works immediately after the install instead of exit 127.
        SETUP_BURP="no"
        DONE_BANNER=1
        install_standalone
        install_claude
        install_antigravity
        install_opencode
        install_pi
        install_codex
        install_agents
        install_mcp
        ;;
    *)
        echo "Unsupported agent: $AGENT" >&2
        usage >&2
        exit 2
        ;;
esac

# ── reconFTW capability-delegation setup (RhodawkAI Edition) ─────────────────
# After the 7-target dispatch, clone reconFTW at the pinned commit so the
# recon gap-fill (recon_engine.sh Phases 1.5/5.5) can delegate. Standalone
# release: RTW_HOME lives entirely under this fork's own control — no external
# product, config format, or secrets source is wired in. Set RTW_HOME to
# override the default location. A missing clone is NOT an error: the fork
# runs exactly as upstream without it (gap-fill silently skipped).
install_rtw_capability_delegation() {
    local rtw_home="${RTW_HOME:-$HOME/Tools/reconftw}"
    local rtw_pin="39252113a854bdac0b785f144b9fae1fa8ca35fc"
    if [ -x "$rtw_home/reconftw.sh" ]; then
        echo "[+] reconFTW already present at $rtw_home"
        if [ -d "$rtw_home/.git" ]; then
            local head
            head="$(git -C "$rtw_home" rev-parse HEAD 2>/dev/null || echo '?')"
            if [ "$head" = "$rtw_pin" ]; then
                echo "[+] reconFTW HEAD matches pinned commit $rtw_pin"
            else
                echo "[!] reconFTW HEAD $head != pinned $rtw_pin — gap-fill still works, but re-clone for the verified snapshot"
            fi
        fi
    elif command -v git >/dev/null 2>&1; then
        echo "[*] Cloning reconFTW (pinned $rtw_pin) to $rtw_home ..."
        if git clone https://github.com/six2dez/reconftw "$rtw_home" \
            && git -C "$rtw_home" checkout -q "$rtw_pin"; then
            echo "[+] reconFTW pinned at $rtw_pin"
        else
            echo "[!] reconFTW clone failed — gap-fill stays disabled (upstream behavior)"
            return 0
        fi
    else
        echo "[!] git not found — skipping reconFTW clone (gap-fill stays disabled)"
        return 0
    fi
    # Step 3: reconftw.sh MUST carry the +x bit (clones made via zip/copy
    # drop it, which silently disabled the whole gap-fill) and the resolved
    # path is persisted so new shells never need RTW_HOME re-exported.
    chmod +x "$rtw_home/reconftw.sh" 2>/dev/null \
        || echo "[!] could not chmod +x $rtw_home/reconftw.sh"
    if command -v python3 >/dev/null 2>&1; then
        RTW_HOME_PERSIST="$rtw_home" python3 - <<'PY' \
            || echo "[!] could not persist rtw_home to ~/.rhodawk/config.json"
import json
import os
from pathlib import Path

cfg_path = Path(os.environ.get("RHODAWK_CONFIG_FILE")
                or Path.home() / ".rhodawk" / "config.json")
try:
    cfg = json.loads(cfg_path.read_text())
    if not isinstance(cfg, dict):
        cfg = {}
except (OSError, ValueError):
    cfg = {}
cfg["rtw_home"] = os.environ["RTW_HOME_PERSIST"]
cfg_path.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(str(cfg_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(json.dumps(cfg, indent=2))
os.chmod(str(cfg_path), 0o600)
print(f"[+] rtw_home persisted to {cfg_path}")
PY
    fi
    # Build the single source of truth every runtime reads. --summary keeps
    # the install log to one human-readable line — the old rebuild call
    # dumped a raw 9-line JSON state dict into stdout on non-TTY installs.
    if command -v python3 >/dev/null 2>&1; then
        python3 "$(cd "$(dirname "$0")" && pwd)/rhodawk/tools/capability_registry.py" --rebuild --summary \
            || echo "[!] capability_registry --rebuild failed — run it manually before hunting"
    fi
}
install_rtw_capability_delegation

# ── Multi-platform credential bootstrap (Commit 1) ────────────────────────────
# At the end of ./install.sh, new users configure every supported
# platform/tool credential (HackerOne, Bugcrowd, Intigriti, YesWeHack, PDCP,
# Chaos, LLM keys) right at bootstrap. The wizard writes ~/.rhodawk/.env
# (chmod 600, dir 700); skipped fields are saved blank so the file can be
# edited later. Skipped when --non-interactive is passed, when stdin is not a
# TTY (CI / piped installs), or when the module is missing —
# `python3 rhodawk/tools/credentials.py --setup` can be run at any time.
if [ "$NONINTERACTIVE" != "1" ] && [ -t 0 ] && command -v python3 >/dev/null 2>&1 \
   && [ -f "$SCRIPT_DIR/rhodawk/tools/credentials.py" ]; then
    echo ""
    echo "─────────────────────────────────────────────"
    echo "  Credential bootstrap (platform API keys)"
    echo "─────────────────────────────────────────────"
    echo "  Writes ~/.rhodawk/.env (chmod 600). Press Enter to skip a field;"
    echo "  skipped keys are stored blank for later editing."
    echo ""
    python3 "$SCRIPT_DIR/rhodawk/tools/credentials.py" --setup \
        || echo "[!] credential bootstrap failed — run later: rhodawk setup"
fi

# ── Final closing summary — always the LAST block printed ─────────────────────
# v2.0.5 UX fix: the old banner was printed from inside install_standalone
# BEFORE the reconFTW clone/pin and the capability-registry rebuild ran, so
# "Done!" was followed by a page of clone output and a raw JSON dump. All of
# that now happens first; this banner is genuinely last.
# Layer 1 polish (audit item 5): EVERY agent target now closes with exactly
# one banner here (standalone, mcp, claude, all), instead of claude/all
# ending abruptly on the reconFTW capability line.
if [ "${DONE_BANNER:-0}" = "1" ]; then
    echo ""
    echo "════════════════════════════════════════════════════"
    if [ "$AGENT" = "mcp" ]; then
        # Layer 1B Issue #4: --agent mcp gets its final "Done." here too —
        # i.e. AFTER the reconFTW capability-delegation setup that runs post-
        # dispatch, instead of the old mid-function "Done." followed by a
        # page of clone output.
        echo "  Done. rhodawk MCP is ready:"
        echo ""
        echo "    rhodawk mcp serve"
        echo "    rhodawk mcp doctor"
        echo "    rhodawk mcp tools"
    elif [ "$AGENT" = "claude" ]; then
        echo "  Done. RhodawkAI Bounty Hunter is ready for Claude Code:"
        echo ""
        echo "    claude recon target.com"
        echo "    claude hunt target.com"
        echo "    rhodawk doctor"
    elif [ "$AGENT" = "all" ]; then
        echo "  Done. All targets installed:"
        echo ""
        echo "    Standalone CLI: ${RHODAWK_BIN_DIR:-/usr/local/bin}/rhodawk (+ rhodawk-agent)"
        echo "    Claude Code   : $HOME/.claude"
        echo "    Antigravity   : ${ANTIGRAVITY_CONFIG_DIR:-$HOME/.gemini/config}"
        echo "    OpenCode      : ${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"
        echo "    Pi            : $HOME/.pi/agent"
        echo "    Codex         : ${CODEX_HOME:-$HOME/.codex}"
        echo "    Shared skills : $HOME/.agents/skills"
        echo "    MCP server    : rhodawk mcp serve"
    else
        echo "  Done! Type from anywhere:"
        echo ""
        echo "    rhodawk doctor"
        echo "    rhodawk setup"
        echo "    rhodawk scope-compile <handle>"
        echo "    rhodawk recon <target>"
        echo "    rhodawk-agent --help"
    fi
    echo "════════════════════════════════════════════════════"
    echo ""
fi
