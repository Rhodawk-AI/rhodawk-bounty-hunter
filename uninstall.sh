#!/bin/bash
# RhodawkAI Bounty Hunter — remove installed skills, commands, agents, and standalone launcher.

set -euo pipefail

AGENT="${RHODAWK_AGENT:-claude}"
SCOPE="global"
ASSUME_YES="no"
PURGE_CONFIG="no"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage: ./uninstall.sh [--agent claude|opencode|pi|codex|agents|standalone|all] [--global|--project] [options]

Examples:
  ./uninstall.sh --agent standalone
  ./uninstall.sh --agent codex --global
  ./uninstall.sh --agent all --yes
  ./uninstall.sh --agent standalone --purge-config

Standalone uninstall removes the rhodawk AND rhodawk-agent commands plus the
rhodawk-managed venv (~/.rhodawk/venv, marker-guarded). ~/.rhodawk/.env,
config.json and all recon/findings/report data are preserved unless
--purge-config is supplied (which still only removes config.json).

Options:
  --global          Remove global installation (default)
  --project         Remove project-local installation
  --purge-config    Also remove ~/.rhodawk/config.json
  -y, --yes         Skip confirmation
  -h, --help        Show this help

The RhodawkAI Bounty Hunter configuration is preserved unless --purge-config is supplied.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --agent)
            shift
            AGENT="${1:?--agent requires a value}"
            ;;
        --agent=*) AGENT="${1#*=}" ;;
        --all) AGENT="all" ;;
        --claude) AGENT="claude" ;;
        --opencode) AGENT="opencode" ;;
        --both) AGENT="claude-opencode" ;;
        --global) SCOPE="global" ;;
        --project) SCOPE="project" ;;
        --purge-config) PURGE_CONFIG="yes" ;;
        -y|--yes) ASSUME_YES="yes" ;;
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

case "$AGENT" in
    claude|antigravity|gemini|agy|opencode|claude-opencode|pi|codex|agents|generic|standalone|engine|all) ;;
    *)
        echo "Unsupported agent: $AGENT" >&2
        usage >&2
        exit 2
        ;;
esac

if [ "$SCOPE" = "project" ] && [[ "$AGENT" == "standalone" || "$AGENT" == "engine" ]]; then
    echo "Standalone RhodawkAI Bounty Hunter is a global command; --project is not applicable." >&2
    exit 2
fi

if [ "$ASSUME_YES" != "yes" ]; then
    # Layer 1 polish (audit item 2): with closed stdin (CI, piped installs)
    # the old `read -r -p "Continue?"` hit EOF and — under `set -e` — aborted
    # the script with exit 1 and no explanation, having modified nothing.
    # Fail LOUDLY with the actionable fix instead, and never touch files.
    if [ ! -t 0 ]; then
        echo "Non-interactive stdin detected: pass --agent <target> --yes (or run from an interactive terminal)." >&2
        exit 2
    fi
    echo "This will uninstall RhodawkAI Bounty Hunter components for: $AGENT ($SCOPE)."
    if [ "$PURGE_CONFIG" = "yes" ]; then
        echo "The saved provider/model configuration will also be removed."
    else
        echo "The saved provider/model configuration will be preserved."
    fi
    read -r -p "Continue? (y/N): " answer
    case "$answer" in
        [Yy]|[Yy][Ee][Ss]) ;;
        *) echo "Cancelled."; exit 0 ;;
    esac
fi

removed=0

remove_path() {
    local path="$1"
    local label="$2"
    if [ -e "$path" ] || [ -L "$path" ]; then
        rm -rf -- "$path"
        echo "✓ Removed $label: $path"
        removed=$((removed + 1))
    fi
}

remove_tree_items() {
    local src_glob="$1"
    local dest_dir="$2"
    local label="$3"
    local item name
    for item in $src_glob; do
        [ -e "$item" ] || continue
        name="$(basename "$item")"
        remove_path "$dest_dir/$name" "$label"
    done
}

remove_files() {
    local src_glob="$1"
    local dest_dir="$2"
    local label="$3"
    local item name
    for item in $src_glob; do
        [ -f "$item" ] || continue
        name="$(basename "$item")"
        remove_path "$dest_dir/$name" "$label"
    done
}

uninstall_claude() {
    local root="${1:-}"
    if [ -z "$root" ]; then
        if [ "$SCOPE" = "project" ]; then root="$SCRIPT_DIR/.claude"; else root="$HOME/.claude"; fi
    fi
    remove_tree_items "$SCRIPT_DIR/skills/*" "$root/skills" "Claude skill"
    remove_files "$SCRIPT_DIR/commands/*.md" "$root/commands" "Claude command"
    # Live-sandbox P2 fix: agents live in rhodawk/agents/ (the repo layout is
    # mixed — install.sh resolves this via resolve_src), so the old root-level
    # agents/*.md glob matched nothing and ~/.claude/agents/*.md survived
    # every uninstall. Resolve exactly like install.sh; remove_files only
    # ever deletes names that exist in the SOURCE dir, so unrelated user
    # agents are preserved.
    local agents_src
    if [ -d "$SCRIPT_DIR/rhodawk/agents" ]; then
        agents_src="$SCRIPT_DIR/rhodawk/agents"
    elif [ -d "$SCRIPT_DIR/agents" ]; then
        agents_src="$SCRIPT_DIR/agents"
    else
        agents_src=""
    fi
    if [ -n "$agents_src" ]; then
        remove_files "$agents_src/*.md" "$root/agents" "Claude agent"
    fi
    remove_claude_scope_guard "$root"
}

# Layer 1 polish (audit item 3): the PreToolUse scope guard lives in
# ~/.claude/settings.json (registered by install.sh --agent claude) and its
# durable copy lives in ~/.rhodawk/hooks/hook_scope_guard.py. Removing the
# plugin files without removing BOTH leaves a hook pointing at a script that
# no longer exists (fail-closed block on every Bash call, or hook errors).
remove_claude_scope_guard() {
    local root="${1:-$HOME/.claude}"
    local settings="$root/settings.json"
    if [ -f "$settings" ] && command -v python3 >/dev/null 2>&1; then
        python3 - "$settings" <<'PY' \
            || echo "[!] could not update $settings — PreToolUse scope guard entry left in place" >&2
import json
import os
import sys

settings_path = sys.argv[1]
try:
    with open(settings_path, encoding="utf-8") as fh:
        settings = json.load(fh)
except (OSError, ValueError):
    sys.exit(0)  # nothing registered in a readable file — nothing to remove
hooks = settings.get("hooks") if isinstance(settings, dict) else None
pre = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
if not isinstance(pre, list):
    sys.exit(0)

def _is_guard_entry(entry):
    if not isinstance(entry, dict):
        return False
    for h in entry.get("hooks", []) or []:
        if isinstance(h, dict) and "hook_scope_guard.py" in str(h.get("command", "")):
            return True
    return False

kept = [e for e in pre if not _is_guard_entry(e)]
if len(kept) == len(pre):
    sys.exit(0)  # no rhodawk scope-guard entry registered
hooks["PreToolUse"] = kept
tmp = settings_path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(settings, fh, indent=2)
    fh.write("\n")
os.replace(tmp, settings_path)
print("+ Removed PreToolUse scope guard entry: %s" % settings_path)
PY
    fi
    local durable_dir="${RHODAWK_HOME:-$HOME/.rhodawk}/hooks"
    remove_path "$durable_dir/hook_scope_guard.py" "durable PreToolUse scope guard copy"
    # Live-sandbox P0 fix companion: drop the repo-root record the hook uses
    # to resolve rhodawk imports (install.sh writes it as 0600).
    remove_path "$durable_dir/.repo_root" "durable scope-guard repo-root record"
    # drop the hooks/ dir itself when nothing else lives there
    if [ -d "$durable_dir" ] \
       && [ -z "$(find "$durable_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
        rmdir "$durable_dir" 2>/dev/null || true
    fi
}

uninstall_opencode() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root="$SCRIPT_DIR/.opencode"
    else
        root="${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"
    fi
    remove_tree_items "$SCRIPT_DIR/skills/*" "$root/skills" "OpenCode skill"
    remove_files "$SCRIPT_DIR/commands/*.md" "$root/commands" "OpenCode command"
    remove_files "$SCRIPT_DIR/agents/*.md" "$root/agents" "OpenCode agent"
}

uninstall_pi() {
    local root
    if [ "$SCOPE" = "project" ]; then root="$SCRIPT_DIR/.pi"; else root="$HOME/.pi/agent"; fi
    remove_tree_items "$SCRIPT_DIR/skills/*" "$root/skills" "Pi skill"
    remove_files "$SCRIPT_DIR/commands/*.md" "$root/prompts" "Pi prompt"
}

uninstall_codex() {
    local root
    if [ "$SCOPE" = "project" ]; then root="$SCRIPT_DIR/.codex"; else root="${CODEX_HOME:-$HOME/.codex}"; fi
    remove_tree_items "$SCRIPT_DIR/skills/*" "$root/skills" "Codex skill"
    remove_files "$SCRIPT_DIR/commands/*.md" "$root/commands" "Codex command"
}

uninstall_agents() {
    local root
    if [ "$SCOPE" = "project" ]; then root="$SCRIPT_DIR/.agents"; else root="$HOME/.agents"; fi
    remove_tree_items "$SCRIPT_DIR/skills/*" "$root/skills" "shared skill"
}

uninstall_antigravity() {
    local root
    if [ "$SCOPE" = "project" ]; then
        root="$SCRIPT_DIR/.agents"
    else
        root="${ANTIGRAVITY_CONFIG_DIR:-$HOME/.gemini/config}"
    fi
    remove_tree_items "$SCRIPT_DIR/skills/*" "$root/skills" "Antigravity skill"
    remove_files "$SCRIPT_DIR/commands/*.md" "$root/commands" "Antigravity command"
    remove_files "$SCRIPT_DIR/rhodawk/agents/*.md" "$root/agents" "Antigravity agent"
    remove_path "$root/rules/hunting.md" "Antigravity rule"
    remove_path "$root/rules/reporting.md" "Antigravity rule"
}

rhodawk_venv_dir() {
    echo "${RHODAWK_HOME:-$HOME/.rhodawk}/venv"
}

is_managed_bughunter() {
    local path="$1" link realpath_target venv_dir
    venv_dir="$(rhodawk_venv_dir)"
    if [ -L "$path" ]; then
        link="$(readlink "$path")"
        if [ "$(basename "$link")" = "engine.py" ]; then
            return 0
        fi
        # v2.0.5: standalone venv installs symlink to the venv console scripts
        # (.../venv/bin/rhodawk) — ours too, including dangling links whose
        # target already vanished (so check the link string, not just realpath).
        case "$link" in
            "$venv_dir"/*) return 0 ;;
        esac
        realpath_target="$(realpath "$path" 2>/dev/null || echo "")"
        case "$realpath_target" in
            "$venv_dir"/*) return 0 ;;
        esac
        return 1
    elif [ -f "$path" ]; then
        grep -q "Standalone RhodawkAI Bounty Hunter CLI" "$path" 2>/dev/null
    else
        return 1
    fi
}

remove_standalone_path() {
    local target="$1"
    local -a remove_cmd=()
    [ -e "$target" ] || [ -L "$target" ] || return 0

    if ! is_managed_bughunter "$target"; then
        echo "! Preserved unrelated command: $target"
        return 0
    fi

    if [ ! -w "$(dirname "$target")" ]; then
        if command -v sudo >/dev/null 2>&1 && [[ "$target" == /usr/local/* ]]; then
            remove_cmd=(sudo)
        else
            echo "! Cannot remove $target (directory is not writable)" >&2
            return 1
        fi
    fi

    # bash 3.2 (macOS default) aborts under set -u when expanding an empty array
    # as "${remove_cmd[@]}" — same idiom as tools/_auth_helper.sh.
    ${remove_cmd[@]+"${remove_cmd[@]}"} rm -f -- "$target"
    echo "✓ Removed standalone command: $target"
    removed=$((removed + 1))
}

uninstall_standalone() {
    local active candidate
    local -a candidates=()
    if [ -n "${RHODAWK_BIN_DIR:-}" ]; then
        # Explicit override is intentionally exclusive, which also makes
        # packaging/integration tests unable to touch a real installation.
        candidates+=("$RHODAWK_BIN_DIR/rhodawk" "$RHODAWK_BIN_DIR/rhodawk-agent")
    else
        active="$(command -v rhodawk 2>/dev/null || true)"
        [ -n "$active" ] && candidates+=("$active")
        candidates+=("/usr/local/bin/rhodawk" "$HOME/.local/bin/rhodawk")
        # v2.0.5: the agent entrypoint is now installed alongside rhodawk.
        active="$(command -v rhodawk-agent 2>/dev/null || true)"
        [ -n "$active" ] && candidates+=("$active")
        candidates+=("/usr/local/bin/rhodawk-agent" "$HOME/.local/bin/rhodawk-agent")
    fi

    for candidate in "${candidates[@]}"; do
        # Skip duplicate paths without requiring associative arrays (bash 3.2).
        case " ${seen_standalone_paths:-} " in
            *" $candidate "*) continue ;;
        esac
        seen_standalone_paths="${seen_standalone_paths:-} $candidate"
        remove_standalone_path "$candidate"
    done

    # ── Standalone venv cleanup (installed by install.sh --agent standalone) ──
    # Removes ONLY a rhodawk-managed venv (marker-guarded). ~/.rhodawk/.env,
    # config.json and all recon/findings/report data are never touched here.
    local venv_dir
    venv_dir="$(rhodawk_venv_dir)"
    if [ -f "$venv_dir/.rhodawk-managed-venv" ]; then
        remove_path "$venv_dir" "standalone venv"
        echo "  (user data preserved: ~/.rhodawk/.env, config.json, recon/, findings/, reports/)"
        # Layer 1 polish (audit item 3): a Claude-plugin install registers the
        # scope guard with the venv interpreter when the venv exists. Removing
        # the venv leaves that registered command pointing at a dead
        # interpreter — warn loudly with both remediation paths instead of
        # letting the user discover it as a broken hook later.
        local claude_settings="$HOME/.claude/settings.json"
        if [ -f "$claude_settings" ] \
           && grep -q "hook_scope_guard.py" "$claude_settings" 2>/dev/null \
           && grep -q "$venv_dir" "$claude_settings" 2>/dev/null; then
            echo "[!] warning: ~/.claude/settings.json registers hook_scope_guard.py"
            echo "    with the venv interpreter that was just removed ($venv_dir/bin/python)."
            echo "    fix: ./install.sh --agent claude   # re-registers the hook (durable ~/.rhodawk/hooks copy, system python3 if no venv)"
            echo "    or: ./install.sh --agent standalone   # recreates the managed venv"
        fi
    elif [ -d "$venv_dir" ]; then
        echo "! $venv_dir has no rhodawk-managed marker — left in place"
    fi
}

case "$AGENT" in
    claude) uninstall_claude ;;
    opencode) uninstall_opencode ;;
    claude-opencode) uninstall_claude; uninstall_opencode ;;
    pi) uninstall_pi ;;
    codex) uninstall_codex ;;
    agents|generic) uninstall_agents ;;
    antigravity|gemini|agy) uninstall_antigravity ;;
    standalone|engine) uninstall_standalone ;;
    all)
        uninstall_claude
        uninstall_antigravity
        uninstall_opencode
        uninstall_pi
        uninstall_codex
        uninstall_agents
        uninstall_standalone
        ;;
esac

if [ "$PURGE_CONFIG" = "yes" ]; then
    remove_path "$HOME/.rhodawk/config.json" "RhodawkAI Bounty Hunter configuration"
    if [ -d "$HOME/.rhodawk" ] && [ -z "$(find "$HOME/.rhodawk" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        rmdir "$HOME/.rhodawk"
    fi
else
    echo "Preserved configuration: $HOME/.rhodawk/config.json"
fi

if [ "$removed" -eq 0 ]; then
    echo "No managed RhodawkAI Bounty Hunter installation found for the selected target."
else
    echo "Done. Removed $removed managed item(s)."
fi
