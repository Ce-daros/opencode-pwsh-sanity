import type { Plugin } from "@opencode-ai/plugin"
import { mkdir, rm, writeFile } from "node:fs/promises"
import { randomUUID } from "node:crypto"
import os from "node:os"
import path from "node:path"

export type PwshSanityMode = "auto" | "force" | "off"

export type Finding = {
  code: string
  message: string
}

export type CommandAnalysis = {
  riskScore: number
  scriptify: boolean
  explicitForeignShell: boolean
  posixLeaks: Finding[]
  complexInlineInterpreter: boolean
  reasons: string[]
}

type RuntimeSettings = {
  mode: PwshSanityMode
  blockPosix: boolean
  blockComplexInline: boolean
  minRiskScore: number
  pwshExecutable: string
  keepScripts: boolean
}

const TRUTHY = new Set(["1", "true", "yes", "on"])
const FALSY = new Set(["0", "false", "no", "off"])

function boolEnv(value: string | undefined, fallback: boolean) {
  if (value === undefined) return fallback
  const normalized = value.trim().toLowerCase()
  if (TRUTHY.has(normalized)) return true
  if (FALSY.has(normalized)) return false
  return fallback
}

function intEnv(value: string | undefined, fallback: number) {
  const parsed = Number.parseInt(value ?? "", 10)
  return Number.isFinite(parsed) ? parsed : fallback
}

function modeEnv(value: string | undefined): PwshSanityMode {
  if (value === "force" || value === "off" || value === "auto") return value
  return "auto"
}

function loadSettings(env: NodeJS.ProcessEnv): RuntimeSettings {
  return {
    mode: modeEnv(env.OPENCODE_PWSH_SANITY_MODE),
    blockPosix: boolEnv(env.OPENCODE_PWSH_SANITY_BLOCK_POSIX, true),
    blockComplexInline: boolEnv(env.OPENCODE_PWSH_SANITY_BLOCK_INLINE, true),
    minRiskScore: Math.max(1, intEnv(env.OPENCODE_PWSH_SANITY_MIN_RISK, 2)),
    pwshExecutable: env.OPENCODE_PWSH_SANITY_EXE?.trim() || "pwsh.exe",
    keepScripts: boolEnv(env.OPENCODE_PWSH_SANITY_KEEP_SCRIPTS, false),
  }
}

function quoteCount(command: string) {
  return (command.match(/["']/g) ?? []).length
}

function semicolonCount(command: string) {
  return (command.match(/;/g) ?? []).length
}

export function isExplicitForeignShell(command: string) {
  const trimmed = command.trimStart()
  return /^(?:bash|sh|zsh|fish)(?:\.exe)?\b/i.test(trimmed) || /^(?:wsl|wsl\.exe)\b/i.test(trimmed) || /^(?:cmd|cmd\.exe)\s+\/(?:c|k)\b/i.test(trimmed)
}

export function detectPosixLeaks(command: string): Finding[] {
  if (isExplicitForeignShell(command)) return []

  const rules: Array<[string, string, RegExp]> = [
    ["export-assignment", "POSIX `export NAME=value` syntax", /(?:^|[;&|]\s*)export\s+[A-Za-z_][A-Za-z0-9_]*=/m],
    ["prefix-assignment", "POSIX `NAME=value command` prefix assignment", /(?:^|[;&|]\s*)[A-Za-z_][A-Za-z0-9_]*=[^\s;&|]+\s+[A-Za-z0-9_.\/-]+/m],
    ["heredoc", "POSIX here-doc (`<<EOF`) syntax", /<<-?\s*['"]?[A-Za-z_][A-Za-z0-9_]*['"]?/],
    ["dev-null", "POSIX `/dev/null` redirection", /(?:^|\s)\d*>?\/?dev\/null\b/],
    ["test-brackets", "POSIX `[[ ... ]]` test syntax", /\[\[\s[\s\S]*?\s\]\]/],
    ["test-command", "POSIX `[ ... ]` conditional syntax", /(?:^|[;&|]\s*)(?:if\s+)?\[\s+[^\r\n]+?\s+\]/m],
    ["arithmetic-expansion", "POSIX arithmetic expansion (`$((...))`)", /\$\(\(/],
    ["parameter-expansion", "POSIX parameter expansion (`${VAR:-default}` and related forms)", /\$\{[A-Za-z_][A-Za-z0-9_]*(?::[-+=?]|[#%]{1,2})/],
    ["process-substitution", "POSIX process substitution (`<(...)` or `>(...)`)", /(?:<|>)\([^\r\n)]*\)/],
    ["backslash-continuation", "POSIX backslash line continuation", /\\\r?\n/],
  ]

  return rules.flatMap(([code, message, pattern]) => (pattern.test(command) ? [{ code, message }] : []))
}

function inlineInterpreter(command: string) {
  return /\b(?:python(?:3(?:\.\d+)?)?|py)(?:\.exe)?\s+(?:-[A-Za-z]+\s+)*-c\s+/i.test(command) ||
    /\b(?:node|bun)(?:\.exe)?\s+(?:-[A-Za-z]+\s+)*-(?:e|p|eval|print)\b/i.test(command)
}

export function analyzeCommand(command: string, minRiskScore = 2): CommandAnalysis {
  const reasons: string[] = []
  let riskScore = 0
  const explicitForeignShell = isExplicitForeignShell(command)
  const posixLeaks = detectPosixLeaks(command)
  const hasInlineInterpreter = inlineInterpreter(command)

  if (/\r?\n/.test(command)) {
    riskScore += 3
    reasons.push("multiline command")
  }
  if (command.length >= 240) {
    riskScore += 1
    reasons.push("long command")
  }
  if (quoteCount(command) >= 6) {
    riskScore += 1
    reasons.push("many nested quotes")
  }
  if (semicolonCount(command) >= 3) {
    riskScore += 1
    reasons.push("many statements")
  }
  if (/[`]["'$\\]/.test(command)) {
    riskScore += 2
    reasons.push("PowerShell escape sequences")
  }
  if (/\bConvert(?:To|From)-Json\b|@\{|@['"]|['"]@/.test(command)) {
    riskScore += 2
    reasons.push("PowerShell structured/string literal syntax")
  }
  if (/\$_\b|\$\([^\r\n)]*\)|\b(?:ForEach-Object|Where-Object)\b/.test(command)) {
    riskScore += 1
    reasons.push("PowerShell interpolation/scriptblock syntax")
  }
  if (hasInlineInterpreter) {
    riskScore += 1
    reasons.push("inline interpreter payload")
  }

  const complexInlineInterpreter = hasInlineInterpreter && (
    command.length >= 180 ||
    quoteCount(command) >= 6 ||
    /[{}\[\]]/.test(command) ||
    /\\["'\\nrt]/.test(command) ||
    /\r?\n/.test(command)
  )

  return {
    riskScore,
    scriptify: !explicitForeignShell && riskScore >= minRiskScore,
    explicitForeignShell,
    posixLeaks,
    complexInlineInterpreter,
    reasons,
  }
}

function shellBaseName(shell: string) {
  return shell.split(/[\\/]/).pop()?.toLowerCase() ?? shell.toLowerCase()
}

function shellLooksPosix(shell: string | undefined) {
  if (!shell) return false
  const base = shellBaseName(shell)
  return /^(?:bash|sh|zsh|fish)(?:\.exe)?$/.test(base) || /git-bash\.exe$/.test(base)
}

function shellLooksPowerShell(shell: string | undefined) {
  if (!shell) return false
  return /^(?:pwsh|powershell)(?:\.exe)?$/.test(shellBaseName(shell))
}

export function shouldActivate(options: {
  platform?: NodeJS.Platform
  mode?: PwshSanityMode
  configuredShell?: string
  gitBashPath?: string
}) {
  const platform = options.platform ?? process.platform
  const mode = options.mode ?? "auto"

  if (mode === "off") return false
  if (mode === "force") return true
  if (platform !== "win32") return false
  if (shellLooksPowerShell(options.configuredShell)) return true
  if (shellLooksPosix(options.configuredShell)) return false
  if (options.gitBashPath) return false
  return true
}

function safeSegment(value: string) {
  return value.replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 80) || "unknown"
}

export function buildLauncher(scriptPath: string, executable = "pwsh.exe") {
  if (/\r|\n/.test(executable)) throw new Error("OPENCODE_PWSH_SANITY_EXE must be a single-line executable name")
  if (/\s/.test(executable)) {
    throw new Error("OPENCODE_PWSH_SANITY_EXE must be a PATH-resolvable command without spaces (for example `pwsh.exe`)")
  }
  const quotedPath = `"${scriptPath.replaceAll('"', '""')}"`
  return `${executable} -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ${quotedPath}`
}

function blockMessage(kind: "posix" | "inline", detail: string) {
  if (kind === "posix") {
    return [
      "opencode-pwsh-sanity blocked a Bash/POSIX-shaped command before PowerShell parsed it.",
      detail,
      "Regenerate this command as native PowerShell, or explicitly invoke `bash -lc ...` / `wsl ...` if POSIX shell semantics are intentional.",
      "Do not spend another tool call trying alternate quote/backslash combinations.",
    ].join("\n")
  }
  return [
    "opencode-pwsh-sanity blocked a complex inline interpreter payload (`python -c`, `node -e`, etc.).",
    "Inline source code inside PowerShell command arguments creates multiple quoting layers and is a frequent LLM failure mode.",
    "Write the source to a temporary .py/.js/.ts file with OpenCode's write/edit tool, execute that file, then remove it if appropriate.",
    "Do not retry the same payload with different escaping.",
  ].join("\n")
}

export const PwshSanity: Plugin = async () => {
  const settings = loadSettings(process.env)
  const scripts = new Map<string, string>()
  let configuredShell: string | undefined

  return {
    config: async (config) => {
      const shell = (config as unknown as { shell?: unknown }).shell
      configuredShell = typeof shell === "string" ? shell : undefined
    },

    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash") return
      const command = output.args?.command
      if (typeof command !== "string" || command.trim().length === 0) return

      const active = shouldActivate({
        mode: settings.mode,
        configuredShell,
        gitBashPath: process.env.OPENCODE_GIT_BASH_PATH,
      })
      if (!active) return

      const analysis = analyzeCommand(command, settings.minRiskScore)

      if (settings.blockPosix && analysis.posixLeaks.length > 0) {
        const detail = analysis.posixLeaks.map((finding) => `- ${finding.message}`).join("\n")
        throw new Error(blockMessage("posix", detail))
      }

      if (settings.blockComplexInline && analysis.complexInlineInterpreter) {
        throw new Error(blockMessage("inline", ""))
      }

      if (!analysis.scriptify) return

      const directory = path.join(os.tmpdir(), "opencode-pwsh-sanity", safeSegment(input.sessionID))
      await mkdir(directory, { recursive: true })
      const scriptPath = path.join(directory, `${safeSegment(input.callID)}-${randomUUID().slice(0, 8)}.ps1`)
      const source = `\uFEFF# Generated by opencode-pwsh-sanity.\r\n${command}${command.endsWith("\n") ? "" : "\r\n"}`
      await writeFile(scriptPath, source, "utf8")
      scripts.set(input.callID, scriptPath)
      output.args.command = buildLauncher(scriptPath, settings.pwshExecutable)
    },

    "tool.execute.after": async (input) => {
      const scriptPath = scripts.get(input.callID)
      if (!scriptPath) return
      scripts.delete(input.callID)
      if (settings.keepScripts) return
      await rm(scriptPath, { force: true }).catch(() => undefined)
    },

    dispose: async () => {
      if (settings.keepScripts) return
      const pending = [...scripts.values()]
      scripts.clear()
      await Promise.all(pending.map((scriptPath) => rm(scriptPath, { force: true }).catch(() => undefined)))
    },
  }
}
