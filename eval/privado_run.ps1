# Runs the Privado CLI on the 12 evaluation repositories at their annotated commits
# and copies each result to eval\results\privado\<owner>__<repo>.json.
#
# Prerequisites: Git, Docker Desktop running, and the Privado CLI on PATH
# (see eval\BASELINES.md, "Privado").
#
# Usage (from the project root, in PowerShell):
#   .\eval\privado_run.ps1                 # all 12 repositories
#   .\eval\privado_run.ps1 -Only medplum   # one repository (substring match)
param(
  [string]$WorkDir = "C:\work\privado",
  [string]$Only = ""
)
$ErrorActionPreference = "Stop"

# Same repositories and commits as the human reference sets.
$Repos = @(
  @{ name = "urbanclap-engg/smart-docs-parser";     sha = "427c7bdf35c99e571e461bfa1056d35006325d1f"; set = "dev" },
  @{ name = "surepassio/mrz-surepass";              sha = "a9ccccb369abf0b2a6555b64242d41c70aaca397"; set = "dev" },
  @{ name = "Sunbird-Ed/SunbirdEd-portal";          sha = "9efc8b5819c6417bed695716bffc2d3cd231471e"; set = "dev" },
  @{ name = "Sunbird-Ed/SunbirdEd-mobile-app";      sha = "9de5e085d0c73e18df5f995427b05bf4d0ec712d"; set = "dev" },
  @{ name = "Sunbird-Ed/sunbird-client-services";   sha = "495367d8e85cd806a7411344dde11ca9705990a1"; set = "dev" },
  @{ name = "razorpay/razorpay-python";             sha = "8960507a29854c8a484d130139179c2429c2f45c"; set = "dev" },
  @{ name = "razorpay/razorpay-node";               sha = "b9e8527225a7322ba2671a3bc0b848fd019d2d8c"; set = "dev" },
  @{ name = "zerodha/pykiteconnect";                sha = "2f67c46ead6864425744abe5ec386979ee39c69f"; set = "dev" },
  @{ name = "zerodha/kiteconnectjs";                sha = "795128916c5e48118b781fe8535b58b872fdc45a"; set = "dev" },
  @{ name = "element-hq/element-web";               sha = "fed99dbbd07ef5ccb988bc752a9c9f44a5ec0391"; set = "heldout" },
  @{ name = "medplum/medplum";                      sha = "baed14789fc1207484633731ad36c4bccbd6a69d"; set = "heldout" },
  @{ name = "supabase/supabase";                    sha = "7f7ebf527b1edf5c133ea13ad95d68ecddd01828"; set = "heldout" }
)

$OutDir = Join-Path $PSScriptRoot "results\privado"
New-Item -ItemType Directory -Force $WorkDir, $OutDir | Out-Null
$Log = Join-Path $OutDir "run_log.csv"
if (-not (Test-Path $Log)) { "repo,set,commit,status,seconds,privado_version" | Out-File $Log -Encoding utf8 }
$ver = (& privado version 2>&1 | Out-String).Trim() -replace "[\r\n,]+", " "

foreach ($r in $Repos) {
  if ($Only -and ($r.name -notlike "*$Only*")) { continue }
  $dir = Join-Path $WorkDir ($r.name -replace "/", "__")
  Write-Host "`n=== $($r.name) @ $($r.sha.Substring(0,8)) ===" -ForegroundColor Cyan

  # Check out exactly the annotated commit (shallow: no history is needed).
  if (-not (Test-Path (Join-Path $dir ".git"))) {
    New-Item -ItemType Directory -Force $dir | Out-Null
    git -C $dir init -q
    git -C $dir remote add origin "https://github.com/$($r.name).git"
  }
  git -C $dir fetch -q --depth 1 origin $r.sha
  git -C $dir checkout -q --force FETCH_HEAD
  $head = (git -C $dir rev-parse HEAD).Trim()
  if ($head -ne $r.sha) { throw "Checked out $head, expected $($r.sha)" }

  # Scan locally only: --skip-upload keeps results off Privado's cloud dashboard.
  $t0 = Get-Date
  $status = "ok"
  try {
    & privado scan $dir --skip-upload --overwrite
    if ($LASTEXITCODE -ne 0) { $status = "exit $LASTEXITCODE" }
  } catch { $status = "error: $($_.Exception.Message -replace ',', ';')" }
  $secs = [int]((Get-Date) - $t0).TotalSeconds

  $json = Join-Path $dir ".privado\privado.json"
  if (Test-Path $json) {
    Copy-Item $json (Join-Path $OutDir (($r.name -replace "/", "__") + ".json")) -Force
  } elseif ($status -eq "ok") { $status = "no privado.json" }
  "$($r.name),$($r.set),$($r.sha),$status,$secs,$ver" | Out-File $Log -Append -Encoding utf8
  Write-Host "-> $status in $secs s" -ForegroundColor Yellow
}
Write-Host "`nResults in $OutDir" -ForegroundColor Green
