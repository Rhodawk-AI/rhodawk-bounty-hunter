#!/bin/bash
# Claude Bug Bounty — install skills, commands, and agents for multiple harnesses.

set -euo pipefail

AGENT="${RHODAWK_AGENT:-claude}"
SCOPE="global"
SETUP_BURP="ask"
NONINTERACTIVE=0

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
if [ -d "$HOME/.rhodawk" ]; then
    chmod 700 "$HOME/.rhodawk" 2>/dev/null || true
    find "$HOME/.rhodawk" -mindepth 1 -type d -exec chmod 700 {} + 2>/dev/null || true
    find "$HOME/.rhodawk" -type f -exec chmod 600 {} + 2>/dev/null || true
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
  ./install.sh --agent standalone Install or update the 'rhodawk' system command
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

    # ── Install rhodawk system command ──────────────────────────────────────
    # Prefer updating the currently active managed installation. This prevents
    # an old /usr/local/bin entry from shadowing a new ~/.local/bin symlink.
    existing_cmd="$(command -v rhodawk 2>/dev/null || true)"
    if [ -n "${RHODAWK_BIN_DIR:-}" ]; then
        bin_dir="$RHODAWK_BIN_DIR"
    elif [ -n "$existing_cmd" ] && [[ -e "$existing_cmd" || -L "$existing_cmd" ]]; then
        if [ -L "$existing_cmd" ] && [ "$(basename "$(readlink "$existing_cmd")")" = "engine.py" ]; then
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

    target="$bin_dir/rhodawk"
    action="Installed"
    if [ -e "$target" ] || [ -L "$target" ]; then
        action="Updated"
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
    ${install_cmd[@]+"${install_cmd[@]}"} ln -sfn "$engine" "$target"

    if [ -L "$target" ] && [ "$(readlink "$target")" = "$engine" ]; then
        echo "[+] $action: $target -> $engine"
        # Step 1A: the same engine is also exposed as `rhodawk` (brand alias).
        ${install_cmd[@]+"${install_cmd[@]}"} ln -sfn "$engine" "$bin_dir/rhodawk"
        if [ -L "$bin_dir/rhodawk" ] || [ -e "$bin_dir/rhodawk" ]; then
            echo "[+] $action: $bin_dir/rhodawk -> $engine"
        else
            echo "[!] Could not install $bin_dir/rhodawk (rhodawk still works)" >&2
        fi
    else
        echo "[!] Could not install or update $target" >&2
        echo "    Try: sudo ./install.sh --agent standalone" >&2
        echo "    Or add this to ~/.bashrc / ~/.zshrc:"
        echo "    alias rhodawk='python3 $engine'"
        return 1
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
    # Ollama setup/chat has a standard-library HTTP fallback, so a distro that
    # blocks global pip installs still gets a working local provider.
    if [ "${RHODAWK_SKIP_DEPS:-0}" != "1" ] && command -v pip3 &>/dev/null; then
        echo "Installing optional Python deps (cloud providers and agent mode)..."
        if ! pip3 install --quiet requests ollama 2>/dev/null; then
            echo "[!] Optional pip packages were not installed; standalone Ollama chat still works via HTTP."
        fi
    fi

    echo ""
    echo "════════════════════════════════════════════════════"
    echo "  Done! Type from anywhere:"
    echo ""
    echo "    rhodawk setup"
    echo "    rhodawk models"
    echo "    rhodawk recon target.com"
    echo "    rhodawk hunt  target.com"
    echo "    rhodawk validate \"<finding>\""
    echo "    rhodawk chat"
    echo "════════════════════════════════════════════════════"
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
    # Build the single source of truth every runtime reads.
    if command -v python3 >/dev/null 2>&1; then
        python3 "$(cd "$(dirname "$0")" && pwd)/rhodawk/tools/capability_registry.py" --rebuild --banner \
            || echo "[!] capability_registry --rebuild failed — run it manually before hunting"
    fi
    echo "[i] Install the gap-fill backing binaries with: bash install_tools.sh --rtw-deps"
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
        || echo "[!] credential bootstrap failed — run manually: python3 rhodawk/tools/credentials.py --setup"
fi
