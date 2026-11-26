#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const PKG = "rhodawk-bounty-hunter";
const args = process.argv.slice(2);
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

function findExternalCmd(cmd) {
  const pathDirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  const exts = process.platform === "win32" ? [".exe", ".cmd", ".bat", ""] : [""];

  for (const dir of pathDirs) {
    for (const ext of exts) {
      const candidate = path.join(dir, cmd + ext);
      if (!isExecutable(candidate)) continue;
      let real;
      try {
        real = fs.realpathSync(candidate);
      } catch {
        continue;
      }
      if (real === SELF_REAL) continue;
      return candidate;
    }
  }
  return null;
}

function run(cmdPath, cmdArgs) {
  const res = spawnSync(cmdPath, cmdArgs, {
    stdio: "inherit",
    env: { ...process.env, RHODAWK_NPM_WRAPPER: "1" },
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
} else {
  const pipxBin = findExternalCmd("pipx");
  if (pipxBin) {
    run(pipxBin, ["run", "--spec", PKG, "rhodawk", ...args]);
  }
}

console.error(
  `[rhodawk] Python CLI not found on PATH.\n` +
    `Install the core package first:\n` +
    `  pipx install ${PKG}\n` +
    `  # or inside a virtualenv:\n` +
    `  pip install ${PKG}\n`
);
process.exit(1);
