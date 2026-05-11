# Carpe fork notice

This repository is a security-reviewed fork of [`Softeria/ms-365-mcp-server`](https://github.com/Softeria/ms-365-mcp-server) maintained as part of the [Carpe](https://carpe.work) connector catalog.

## What's different from upstream

Upstream code lives in this fork unchanged. The Carpe-specific additions are confined to:

- [`carpe-fork/`](carpe-fork/) — launcher (`run.cmd`), build script (`build.ps1`), bundled Carpe scanners
- [`.github/workflows/security-and-build.yml`](.github/workflows/security-and-build.yml) — security gates (OSV-Scanner on `package-lock.json` production deps, semgrep for JS/TS SAST, TruffleHog, Cisco MCP Scanner, Carpe Unicode-norm, Carpe tool-surface-snapshot) and the release pipeline
- This file

Everything else — `src/`, `bin/`, `package.json`, `package-lock.json`, the upstream's tests and docs — is upstream code at the pinned commit noted below.

## Pinned upstream

| Field | Value |
|---|---|
| Upstream repo | `Softeria/ms-365-mcp-server` |
| Upstream package | `@softeria/ms-365-mcp-server@0.107.1` |
| Forked at commit | `fc532afb2de17dbb070ff58777478b7b7168c059` |
| Last reviewed | 2026-05-11 (preliminary; final sign-off pending Carpe Entra app reg) |

## Required runtime configuration

The catalog version of this connector ships with stdio transport only. The HTTP transport is disabled because it loads `hono`, which has an open HIGH advisory ([GHSA-hm8q-7f3q-5f36](https://github.com/advisories/GHSA-hm8q-7f3q-5f36)). Carpe's catalog publish CI rejects entries whose launch args include `--http`.

### Required env vars at launch

| Var | Purpose |
|---|---|
| `MS365_MCP_CLIENT_ID` | Carpe-owned multi-tenant Entra ID app client id |
| `MS365_MCP_TENANT_ID` | `organizations` (work/school accounts) |
| `MS365_MCP_TOKEN_CACHE_PATH` | Local token cache path inside the connector dir |

### Required launch args

| Arg | Why |
|---|---|
| `--org-mode` | Exposes the full 311-tool surface (Teams, SharePoint, shared mailbox). SMB-operator audience uses work accounts. |

### Forbidden launch args

| Arg | Why |
|---|---|
| `--http` | Loads `hono`. Open HIGH advisory. |
| `--http <port>` | Same. |

## Distribution

Releases on this fork (`v*` tags) are picked up by Carpe's catalog system via signed `catalog.json`. The SHA-256 of each release artifact is captured at build time and embedded in `catalog.json`; the desktop app verifies bytes before running the connector.

## Reporting issues

For **security issues** in this fork's additions or in the build pipeline: open a security advisory on this repo.

For **issues in the underlying ms-365-mcp-server code**: report upstream at [`Softeria/ms-365-mcp-server`](https://github.com/Softeria/ms-365-mcp-server). We track upstream and pull fixes through deliberate PRs.

For **how the connector behaves in Carpe** (UI, approval gates, scoping): report at [`EasyCCapp/EasyCC`](https://github.com/EasyCCapp/EasyCC).

## License

Inherits the upstream project's license (MIT). The Carpe-specific additions in `carpe-fork/` and `.github/workflows/security-and-build.yml` are released under the same license unless otherwise noted.
