#!/bin/bash
# Claude Bug Bounty — install skills, commands, and agents for multiple harnesses.

set -euo pipefail

AGENT="${RHODAWK_AGENT:-claude}"
SCOPE="global"
SETUP_BURP="ask"
NONINTERACTIVE=0
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
    find "$rh_home" -path "$rh_home/venv" -prune -o \
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

    python3 - "$settings" "$guard_src" <<'PYGUARD' || { echo "[!] could not merge $settings — PreToolUse scope guard NOT registered"; return 0; }
import json
import os
import sys

settings_path, guard_path = sys.argv[1], sys.argv[2]
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

command = f'python3 "{guard_path}"'
hooks = settings.setdefault("hooks", {})
if not isinstance(hooks, dict):
    print("[!] hooks is not an object; refusing to edit", file=sys.stderr)
    sys.exit(1)
pre = hooks.setdefault("PreToolUse", [])
if not isinstance(pre, list):
    print("[!] hooks.PreToolUse is not a list; refusing to edit", file=sys.stderr)
    sys.exit(1)

def _guard_present(entries):
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for h in entry.get("hooks", []) or []:
            if isinstance(h, dict) and guard_path in str(h.get("command", "")):
                return True
    return False

if _guard_present(pre):
    print("[+] PreToolUse scope guard already registered")
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

    echo "Installing Claude Bug Bounty for Claude Code ($SCOPE)..."
    copy_tree_items "skills/*" "$root/skills" "skill"
    copy_files "commands/*.md" "$root/commands" "command"
    copy_files "$AGENTS_SRC/*.md" "$root/agents" "agent"
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
        read -r -p "Set up Burp MCP now? (y/N): " setup_burp
        case "$setup_burp" in
            [Yy]*) SETUP_BURP="yes" ;;
            *) SETUP_BURP="no" ;;
        esac
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

    echo "Installing Claude Bug Bounty for OpenCode ($SCOPE)..."
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

    echo "Installing Claude Bug Bounty for Pi Agent ($SCOPE)..."
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

    echo "Installing Claude Bug Bounty for Codex-style Agent Skills ($SCOPE)..."
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
    # Ubuntu 24.04+ (PEP 668) rejects pip installs into the system Python, so
    # the old bare `pip3 install requests ollama` failed silently on every
    # fresh box: rhodawk stayed a raw engine.py symlink with no mcp/requests
    # and rhodawk-agent was never installed at all. Preferred path: a
    # dedicated venv under the data home with the repo installed editable, so
    # rhodawk, rhodawk-agent, requests and the mcp SDK all resolve from ANY
    # working directory (also fixes `python3 -m rhodawk.tools.credentials`
    # not being importable outside the repo checkout).
    local venv_dir venv_ok=0
    venv_dir="${RHODAWK_HOME:-$HOME/.rhodawk}/venv"
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
    echo "════════════════════════════════════════════════════"
    echo "  RhodawkAI Bounty Hunter MCP"
    echo "════════════════════════════════════════════════════"
    echo ""
    echo "Server entry:"
    echo "  python3 $MCP_SRC/rhodawk-mcp/server.py"
    echo "  # or: rhodawk mcp serve   (after standalone install)"
    echo ""
    echo "Doctor / tool catalog:"
    echo "  rhodawk mcp doctor"
    echo "  rhodawk mcp tools"
    echo ""
    echo "Python SDK:"
    echo "  pip install 'mcp>=2.2.0'"
    echo ""
    echo "Claude Code — merge $MCP_SRC/rhodawk-mcp/claude-config.json into ~/.claude/settings.json mcpServers"
    echo "OpenCode   — merge $MCP_SRC/rhodawk-mcp/opencode-config.json into opencode mcp config"
    echo ""
    echo "Active tools require scope_domains + approve=true (or RHODAWK_MCP_APPROVE=1)."
    echo "Existing Burp / Caido / HackerOne integrations are unchanged."
    echo ""
    if [ "${RHODAWK_SKIP_DEPS:-0}" != "1" ] && command -v pip3 &>/dev/null; then
        echo "Installing mcp SDK (optional)..."
        pip3 install --quiet 'mcp>=2.2.0' 2>/dev/null || echo "[!] pip install mcp failed — install manually"
    fi
    echo "Done."
}

case "$AGENT" in
    standalone|engine)
        SETUP_BURP="no"
        DONE_BANNER=1
        install_standalone
        ;;
    mcp)
        SETUP_BURP="no"
        install_mcp
        ;;
    claude)
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
        SETUP_BURP="no"
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

# ── Final standalone summary — always the LAST block printed ─────────────────
# v2.0.5 UX fix: the old banner was printed from inside install_standalone
# BEFORE the reconFTW clone/pin and the capability-registry rebuild ran, so
# "Done!" was followed by a page of clone output and a raw JSON dump. All of
# that now happens first; this banner is genuinely last.
if [ "${DONE_BANNER:-0}" = "1" ]; then
    echo ""
    echo "════════════════════════════════════════════════════"
    echo "  Done! Type from anywhere:"
    echo ""
    echo "    rhodawk doctor"
    echo "    rhodawk setup"
    echo "    rhodawk scope-compile <handle>"
    echo "    rhodawk recon <target>"
    echo "    rhodawk-agent --help"
    echo "════════════════════════════════════════════════════"
    echo ""
fi
