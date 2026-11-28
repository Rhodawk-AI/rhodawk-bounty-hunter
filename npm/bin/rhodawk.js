#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const PKG = "rhodawk-bounty-hunter";
const args = process.argv.slice(2);
const SELF_RESOLVED = path.resolve(__filename);
const SELF_REAL = fs.realpathSync(__filename);

if (process.env.RHODAWK_NPM_WRAPPER === "1") {
  console.error("[rhodawk] Aborting recursive wrapper invocation.");
  process.exit(1);
}

function isExecutable(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return false;
    if (process.platform === "win32") return true;
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

const EXTS = process.platform === "win32" ? [".exe", ".cmd", ".bat", ""] : [""];

// Directories this wrapper itself lives in (Layer 1C, live-sandbox finding):
// under `npx -y @rhodawkai/bounty-hunter` the temp install's
// node_modules/.bin/rhodawk IS this wrapper, so that PATH entry must never
// reach child processes — otherwise pipx/uvx see "rhodawk" already on PATH
// (the wrapper, not the Python CLI) and print a confusing
// "⚠️ rhodawk is already on your PATH ... Downloading and running anyway."
// warning on every invocation of a blank machine.
function wrapperDirs() {
  const dirs = new Set();
  const add = (d) => {
    if (d) {
      try {
        dirs.add(path.resolve(d));
      } catch {
        /* ignore unresolvable dir */
      }
    }
  };
  try {
    add(path.dirname(process.argv[1]));
  } catch {
    /* argv[1] may be odd under embedded runners */
  }
  add(path.dirname(SELF_RESOLVED));
  add(path.dirname(SELF_REAL));
  // plus any PATH entry whose `rhodawk` resolves to this wrapper itself
  const pathDirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  for (const dir of pathDirs) {
    for (const ext of EXTS) {
      const candidate = path.join(dir, "rhodawk" + ext);
      if (!isExecutable(candidate)) continue;
      let real;
      try {
        real = fs.realpathSync(candidate);
      } catch {
        continue;
      }
      if (real === SELF_REAL || real === SELF_RESOLVED) {
        add(dir);
        break;
      }
    }
  }
  return dirs;
}

function sanitizedPath() {
  const skip = wrapperDirs();
  return (process.env.PATH || "")
    .split(path.delimiter)
    .filter(Boolean)
    .filter((dir) => !skip.has(path.resolve(dir)))
    .join(path.delimiter);
}

function findExternalCmd(cmd) {
  const pathDirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);

  for (const dir of pathDirs) {
    for (const ext of EXTS) {
      const candidate = path.join(dir, cmd + ext);
      if (!isExecutable(candidate)) continue;
      let real;
      try {
        real = fs.realpathSync(candidate);
      } catch {
        continue;
      }
      if (real === SELF_REAL || real === SELF_RESOLVED) continue;
      return candidate;
    }
  }
  return null;
}

// Every child gets the sanitized PATH: both the chained Python rhodawk
// (so a real binary never re-discovers wrapper copies) and the fallback
// runners (so pipx/uvx never see node_modules/.bin/rhodawk and never emit
// the "already on your PATH" warning).
function run(cmdPath, cmdArgs) {
  const res = spawnSync(cmdPath, cmdArgs, {
    stdio: "inherit",
    env: {
      ...process.env,
      PATH: sanitizedPath(),
      RHODAWK_NPM_WRAPPER: "1",
    },
  });
  if (res.error) {
    console.error(`[rhodawk] Failed to run ${cmdPath}: ${res.error.message}`);
    process.exit(1);
  }
  process.exit(res.status ?? 0);
}

const rhodawkBin = findExternalCmd("rhodawk");
if (rhodawkBin) {
  run(rhodawkBin, args);
}

// Blank box, no Python rhodawk: prefer uvx (fast, silent, PEP 668-safe),
// then pipx run. If neither runner exists, print a concise install hint.
const uvxBin = findExternalCmd("uvx");
if (uvxBin) {
  run(uvxBin, ["--from", PKG, "rhodawk", ...args]);
}

const pipxBin = findExternalCmd("pipx");
if (pipxBin) {
  run(pipxBin, ["run", "--spec", PKG, "rhodawk", ...args]);
}

console.error(
  `[rhodawk] Python CLI not found on PATH, and neither uvx nor pipx is installed.\n` +
    `Install the core package with one of:\n` +
    `  uv tool install ${PKG}      # then run: rhodawk <command>\n` +
    `  pipx install ${PKG}         # then run: rhodawk <command>\n` +
    `  pip install ${PKG}          # or inside a virtualenv\n`
);
process.exit(1);
