[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'scripts\report-common.ps1')
. (Join-Path $repositoryRoot 'scripts\process-runner.ps1')
function Assert-True { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }
function Assert-Equal { param($Expected, $Actual, [string]$Message) if ($Expected -ne $Actual) { throw "$Message Expected=$Expected Actual=$Actual" } }
function Get-ScriptAst {
    param([string]$RelativePath)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repositoryRoot $RelativePath), [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count "$RelativePath did not parse."
    return $ast
}

$powerShellPath = (Get-Process -Id $PID).Path

# A single failed module must set the exit code: Windows PowerShell 5.1 has no .Count on one pscustomobject.
$entrypointAst = Get-ScriptAst 'Invoke-WindowsDiagnostics.ps1'
$exitCodeAst = $entrypointAst.Find({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$exitCode' }, $true)
$results = New-Object System.Collections.Generic.List[object]
$results.Add([pscustomobject]@{ ExitCode = 1 })
$results.Add([pscustomobject]@{ ExitCode = 0 })
. ([scriptblock]::Create($exitCodeAst.Extent.Text))
Assert-Equal 1 $exitCode 'One failed module must produce exit code 1.'

# Privacy Mode.
$context = New-WdtRedactionContext -ComputerName 'ALICE-PC' -UserName 'alice' -UserDomain 'CORP' -UserProfile 'C:\Users\alice'
foreach ($option in @('--api-key=fixture-value', '--access-token fixture-value', '--client-secret "fixture-value"', '--pwd=fixture-value')) {
    Assert-True (-not (Protect-WdtText -Text "tool.exe $option" -Context $context).Contains('fixture-value')) "Secret option was not redacted: $option"
}
$accountSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
foreach ($taskName in @("OneDrive Reporting Task-$accountSid", "GoogleUpdateTaskUser$($accountSid)Core")) {
    Assert-True (-not (Protect-WdtText -Text $taskName -Context $context).Contains($accountSid)) "Glued SID was not redacted: $taskName"
}
Assert-Equal 'BUS-1-5-21' (Protect-WdtText -Text 'BUS-1-5-21' -Context $context) 'A short identifier must not be treated as a glued SID.'
$restart = Protect-WdtText -Text 'The process svchost.exe has initiated the restart of computer ALICE-PC on behalf of user alice' -Context $context
Assert-True ($restart.Contains('svchost.exe')) 'The process name must stay readable.'
Assert-True (-not $restart.Contains('ALICE-PC') -and $restart -notmatch '\balice\b') 'Names after a process name must be redacted.'
Assert-Equal 'Process alice.exe failed' (Protect-WdtText -Text 'Process alice.exe failed' -Context $context) 'A diagnostic file name must stay readable.'
$email = Protect-WdtText -Text 'Contact alice.smith@acme-secret.com now' -Context $context
Assert-True (-not $email.Contains('smith') -and -not $email.Contains('acme-secret')) 'An email address must be fully redacted.'
foreach ($line in @('DNS suffix      : corp.acme-secret.example', 'DNS search list : corp.acme-secret.example, acme-secret.example', 'Proxy server   : proxy.acme-secret.example:8080', 'Auto config URL: https://wpad.acme-secret.example/proxy.pac', '    Proxy Server(s) :  proxy.acme-secret.example:8080')) {
    Assert-True (-not (Protect-WdtText -Text $line -Context $context).Contains('acme-secret')) "Network name was not redacted: $line"
}
Assert-Equal 'Proxy server   : None' (Protect-WdtText -Text 'Proxy server   : None' -Context $context) 'An empty proxy value must stay readable.'

# A typographic apostrophe in a path or argument must not end the generated string literal.
$fixtureRoot = Join-Path $env:TEMP ('wdt-audit-' + [guid]::NewGuid().ToString('N'))
try {
    $apostrophe = [string][char]0x2019
    $scriptDirectory = Join-Path $fixtureRoot "O$($apostrophe)Brien"
    [void](New-Item -ItemType Directory -Path $scriptDirectory -Force)
    $scriptPath = Join-Path $scriptDirectory 'fixture.ps1'
    Set-Content -LiteralPath $scriptPath -Value 'param([string]$Value) Write-Output ("value=" + $Value.Length)' -Encoding ASCII
    $argument = "a$($apostrophe)b"
    $launch = Invoke-DiagnosticScript -Title 'Fixture' -ScriptPath $scriptPath -PowerShellPath $powerShellPath -RepositoryRoot $fixtureRoot -TimeoutSeconds 60 -ScriptArguments @('-Value', $argument)
    Assert-Equal 0 $launch.ExitCode ('The fixture did not start. ' + ($launch.ErrorLines -join ' '))
    Assert-True (($launch.OutputLines -join ' ').Contains('value=3')) 'The argument did not arrive unchanged.'

    # With every storage source failing, the Disk module must report that instead of an empty success.
    $diskWrapper = Join-Path $fixtureRoot 'disk-wrapper.ps1'
    Set-Content -LiteralPath $diskWrapper -Encoding ASCII -Value @"
function global:Get-PhysicalDisk { throw 'fixture' }
function global:Get-Volume { throw 'fixture' }
function global:Get-CimInstance { throw 'fixture' }
& '$(Join-Path $repositoryRoot 'modules\disk\diagnostic.ps1')'
"@
    $env:WDT_FINDING_PROTOCOL = '1'
    $env:WDT_FINDING_NONCE = [guid]::NewGuid().ToString('N')
    $diskOutput = (& $powerShellPath -NoProfile -ExecutionPolicy Bypass -File $diskWrapper 2>&1 | ForEach-Object { [string]$_ }) -join "`n"
    foreach ($code in @('DISK_DATA_UNAVAILABLE', 'VOLUME_DATA_UNAVAILABLE')) {
        Assert-True ($diskOutput.Contains($code)) "Disk module did not emit $code."
    }
}
finally {
    Remove-Item Env:\WDT_FINDING_PROTOCOL, Env:\WDT_FINDING_NONCE -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
}
$global:LASTEXITCODE = 0

# A component reported as a full path must not stop the Crashes module.
$crashesAst = Get-ScriptAst 'modules\crashes\diagnostic.ps1'
$crashRecordAst = $crashesAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertTo-CrashRecord' }, $true)
. ([scriptblock]::Create($crashRecordAst.Extent.Text))
$crash = ConvertTo-CrashRecord ([pscustomobject]@{ ProviderName = 'Application Error'; Id = 1000; TimeCreated = Get-Date; Component = 'C:\Program Files\App\app.exe' }) EventLog
Assert-Equal 'app.exe' $crash.Component 'A path component must reduce to its file name.'

# An empty process list must reach the message written for it.
$performanceAst = Get-ScriptAst 'modules\performance\diagnostic.ps1'
$processListAst = $performanceAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Write-ProcessList' }, $true)
. ([scriptblock]::Create($processListAst.Extent.Text))
Write-ProcessList -Processes @() -Metric 'WorkingSet' -Limit 1

Write-Host 'Audit regression tests passed.'
