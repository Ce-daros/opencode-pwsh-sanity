import test from "node:test"
import assert from "node:assert/strict"
import { analyzeCommand, buildLauncher, detectPosixLeaks, isExplicitForeignShell, shouldActivate } from "../dist/index.js"

test("leaves simple commands alone", () => {
  const result = analyzeCommand("git status")
  assert.equal(result.scriptify, false)
  assert.equal(result.posixLeaks.length, 0)
})

test("scriptifies PowerShell JSON-heavy commands", () => {
  const command = `$data = Get-Content "package.json" | ConvertFrom-Json; $data.scripts | ConvertTo-Json -Depth 8; Write-Output "$($data.name)"`
  const result = analyzeCommand(command)
  assert.equal(result.scriptify, true)
  assert.ok(result.riskScore >= 2)
})

test("scriptifies multiline commands", () => {
  const result = analyzeCommand("$x = 1\nWrite-Output $x")
  assert.equal(result.scriptify, true)
})

test("detects strong POSIX leaks", () => {
  const findings = detectPosixLeaks("export NODE_ENV=production; npm test 2>/dev/null")
  assert.ok(findings.some((finding) => finding.code === "export-assignment"))
  assert.ok(findings.some((finding) => finding.code === "dev-null"))
})

test("does not flag an explicitly requested bash shell", () => {
  assert.equal(isExplicitForeignShell("bash -lc 'export FOO=bar; echo $FOO'"), true)
  assert.deepEqual(detectPosixLeaks("bash -lc 'export FOO=bar; echo $FOO'"), [])
})

test("flags complex inline interpreter payloads", () => {
  const command = `python -c "import json; x=json.loads('{\\"foo\\": [1,2,3]}'); print(x['foo'][0])"`
  assert.equal(analyzeCommand(command).complexInlineInterpreter, true)
})

test("auto mode disables itself for configured Git Bash", () => {
  assert.equal(shouldActivate({ platform: "win32", mode: "auto", configuredShell: "C:\\Program Files\\Git\\bin\\bash.exe" }), false)
})

test("auto mode activates for pwsh on Windows", () => {
  assert.equal(shouldActivate({ platform: "win32", mode: "auto", configuredShell: "pwsh" }), true)
})

test("force mode can be used for testing on non-Windows hosts", () => {
  assert.equal(shouldActivate({ platform: "linux", mode: "force" }), true)
})

test("launcher is deliberately boring", () => {
  assert.equal(
    buildLauncher("C:\\Temp\\opencode-pwsh-sanity\\a.ps1"),
    'pwsh.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\\Temp\\opencode-pwsh-sanity\\a.ps1"',
  )
})
