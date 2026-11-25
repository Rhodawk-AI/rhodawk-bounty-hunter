#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");

const PKG = "rhodawk-bounty-hunter";
const args = process.argv.slice(2);

function hasCmd(cmd) {
  const probe = spawnSync(process.platform === "win32" ? "where" : "which", [cmd], {
    stdio: "ignore",
  });
  return probe.status === 0;
}

function run(cmd, cmdArgs) {
  const res = spawnSync(cmd, cmdArgs, { stdio: "inherit" });
  if (res.error) {
    console.error(`[rhodawk] Failed to run ${cmd}: ${res.error.message}`);
    process.exit(1);
  }
  process.exit(res.status ?? 0);
}

if (hasCmd("rhodawk")) {
  run("rhodawk", args);
} else if (hasCmd("pipx")) {
  run("pipx", ["run", "--spec", PKG, "rhodawk", ...args]);
} else {
  console.error(
    `[rhodawk] Python CLI not found on PATH.\n` +
      `Install the core package first:\n` +
      `  pipx install ${PKG}\n` +
      `  # or inside a virtualenv:\n` +
      `  pip install ${PKG}\n`
  );
  process.exit(1);
}
