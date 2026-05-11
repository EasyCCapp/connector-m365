@echo off
rem -----------------------------------------------------------------
rem Microsoft 365 MCP connector launcher (stdio only)
rem
rem Carpe spawns this from connector.json's distribution.launch.command.
rem  - %~dp0 is the unzipped connector dir
rem  - We invoke the bundled node.exe (or the system Node if not bundled)
rem    against dist/index.js with --org-mode for the full 311-tool surface
rem  - stdio carries MCP protocol traffic. stderr is for logs only.
rem
rem NEVER add --http here — that loads `hono` which has an open HIGH
rem advisory (GHSA-hm8q-7f3q-5f36). Catalog publish CI enforces this.
rem -----------------------------------------------------------------

setlocal
set "CONNECTOR_DIR=%~dp0"

rem Prefer bundled Node if present
set "NODE_EXE=%CONNECTOR_DIR%node\node.exe"
if not exist "%NODE_EXE%" (
    rem Fall back to system Node — connector.json's install step
    rem verifies Node is available before unpacking
    set "NODE_EXE=node"
)

set "SERVER_JS=%CONNECTOR_DIR%dist\index.js"
if not exist "%SERVER_JS%" (
    echo [m365-mcp] dist\index.js not found at %SERVER_JS% 1>&2
    exit /b 1
)

rem Carpe sets MS365_MCP_CLIENT_ID, MS365_MCP_TENANT_ID, MS365_MCP_TOKEN_CACHE_PATH
rem in the env before invoking us. Don't override here.

"%NODE_EXE%" "%SERVER_JS%" --org-mode
exit /b %ERRORLEVEL%
