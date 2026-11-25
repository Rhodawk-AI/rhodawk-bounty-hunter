// Canonical Go module path for this repository (matches GitHub's go-import
// meta tag so the Go module proxy and the dependency graph resolve here).
//
// This repository ships no Go code; the reconFTW capability-delegation layer
// lives in Python (rhodawk/tools/capability_registry.py + rtw_adapter.py).
// The path is pinned here so `go list -m` and GitHub's dependency graph agree.
module github.com/Rhodawk-AI/rhodawk-bounty-hunter

go 1.22
