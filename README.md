# opencode-pwsh-sanity

A small OpenCode plugin for Windows + PowerShell that stops LLM shell calls from burning turns on quote, backslash, JSON, and nested-interpreter escaping failures.

The plugin deliberately **does not try to auto-fix quoting**. Instead it removes quoting layers where possible and blocks a few high-confidence failure patterns before they reach PowerShell.

## What it does

- **Scriptifies risky PowerShell commands.** Multiline / quote-heavy / JSON-heavy commands are written to a temporary UTF-8 BOM `.ps1` file and executed with `pwsh.exe -File`, instead of being shoved through another inline command-string layer.
- **Blocks obvious Bash/POSIX leakage.** High-confidence patterns such as `export FOO=bar`, `<<EOF`, `/dev/null`, `[[ ... ]]`, `$((...))`, and `${VAR:-default}` are rejected with a model-facing correction message.
- **Blocks complex `python -c` / `node -e` payloads.** The model is told to use OpenCode's write/edit tool to create a temporary source file instead of playing escape-character roulette.
- **Leaves simple commands alone.** `git status`, `npm test`, `Get-ChildItem`, and other low-risk calls stay fast.
- **Cleans up after itself.** Generated scripts live under the system temp directory and are removed after the tool call.
- **Gets out of the way for Git Bash/WSL.** In `auto` mode it disables itself when OpenCode is explicitly configured with a POSIX shell or `OPENCODE_GIT_BASH_PATH` is set.

## Why

A command like this has several parsers between the model and the code it actually wants to run:

```text
LLM output -> PowerShell parser -> native argv parser -> Python/Node parser -> JSON/regex/string parser
```

Every inline layer is another place where quotes and backslashes can be reinterpreted. `opencode-pwsh-sanity` attacks the problem structurally: source code goes in source files, and non-trivial PowerShell goes in `.ps1` files.

## Requirements

- Windows
- PowerShell 7 (`pwsh.exe`) on `PATH`
- OpenCode with plugin support

OpenCode supports selecting PowerShell explicitly:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "shell": "pwsh"
}
```

## Install now from GitHub

Until the package is published to npm, install the single-file plugin globally:

```powershell
$pluginDir = Join-Path $HOME ".config\opencode\plugins"
New-Item -ItemType Directory -Force $pluginDir | Out-Null
Invoke-WebRequest `
  "https://raw.githubusercontent.com/Ce-daros/opencode-pwsh-sanity/main/index.ts" `
  -OutFile (Join-Path $pluginDir "pwsh-sanity.ts")
```

Restart OpenCode after installing or updating the file.

For project-only use, put `index.ts` at:

```text
<project>/.opencode/plugins/pwsh-sanity.ts
```

## npm install (after publication)

Once `opencode-pwsh-sanity` is published to npm, add it to OpenCode configuration:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-pwsh-sanity"]
}
```

OpenCode installs npm plugins with Bun automatically at startup.

## Example

Given a quote-heavy command such as:

```powershell
$data = Get-Content "package.json" | ConvertFrom-Json; $data.scripts | ConvertTo-Json -Depth 8; Write-Output "$($data.name)"
```

the plugin writes the original text as a temporary `.ps1` and replaces the tool command with a boring launcher similar to:

```powershell
pwsh.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Users\you\AppData\Local\Temp\opencode-pwsh-sanity\...\call.ps1"
```

The original PowerShell source no longer has to survive an extra inline command-string boundary.

If the model generates:

```bash
export NODE_ENV=production; npm test 2>/dev/null
```

the plugin rejects it before PowerShell sees it and tells the model to regenerate native PowerShell or explicitly invoke Bash/WSL if POSIX semantics were intentional.

## Configuration

Configuration is intentionally tiny and uses environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `OPENCODE_PWSH_SANITY_MODE` | `auto` | `auto`, `force`, or `off` |
| `OPENCODE_PWSH_SANITY_BLOCK_POSIX` | `true` | Block high-confidence Bash/POSIX syntax leaks |
| `OPENCODE_PWSH_SANITY_BLOCK_INLINE` | `true` | Block complex `python -c` / `node -e` style payloads |
| `OPENCODE_PWSH_SANITY_MIN_RISK` | `2` | Risk score required before a command is scriptified |
| `OPENCODE_PWSH_SANITY_EXE` | `pwsh.exe` | PowerShell executable name; must be PATH-resolvable and contain no spaces |
| `OPENCODE_PWSH_SANITY_KEEP_SCRIPTS` | `false` | Keep generated `.ps1` files for debugging |

Example:

```powershell
$env:OPENCODE_PWSH_SANITY_KEEP_SCRIPTS = "true"
$env:OPENCODE_PWSH_SANITY_MIN_RISK = "1"
opencode
```

`force` is useful for development/testing or unusual shell setups. `auto` is the recommended mode.

## What it intentionally does not do

It does not rewrite arbitrary PowerShell syntax, parse and re-escape nested languages, or silently turn Bash into PowerShell. Those approaches are clever until they mutate a valid command into a subtly different one.

The plugin prefers deterministic transformations:

```text
risky PowerShell -> temporary .ps1 -> pwsh -File
```

and deterministic rejection:

```text
obvious Bash leak / complex inline source -> fail early -> model gets corrective guidance
```

## Development

```powershell
git clone https://github.com/Ce-daros/opencode-pwsh-sanity.git
cd opencode-pwsh-sanity
npm install
npm test
```

The test suite covers risk classification, POSIX leak detection, shell auto-detection, inline interpreter detection, and launcher generation. CI runs on Windows and Linux.

## Compatibility

This plugin targets OpenCode's stable plugin API and uses `tool.execute.before` to mutate `output.args.command`, plus `tool.execute.after` for cleanup. It does not depend on the beta V2 plugin API.

## License

MIT

> Independent community project. Not built by or affiliated with the OpenCode team.
