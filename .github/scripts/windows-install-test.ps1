<#
  Zkouška instalátoru H&H AntiShield na čistém Windows.

  Projde stejnou cestu jako uživatel, jen bez klikání:
    1. tichá instalace pro aktuálního uživatele (instalátor nežádá práva správce),
    2. soubory, záznam v Aplikacích (odinstalace), zástupci ve Startu a na ploše,
    3. spuštění aplikace: okno, obsah okna (UI Automation čte text z WebView2),
       načtený engine, spuštění po přihlášení, snímek obrazovky,
    4. ukončení a tichá odinstalace s kontrolou, že po aplikaci nic nezůstalo.

  Výsledek jde do souhrnu běhu a jako anotace (ty se dají přečíst přes API
  i tam, kde se log stáhnout nedá). Při chybě skript skončí kódem 1.
#>
param(
  [Parameter(Mandatory = $true)] [string] $Installer,
  [Parameter(Mandatory = $true)] [string] $Version,
  [string] $OutDir = $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() })
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$Product   = 'H&H AntiShield'
$InstDir   = Join-Path $env:LOCALAPPDATA $Product
$AppExe    = Join-Path $InstDir 'antishield-app.exe'
$Uninst    = Join-Path $InstDir 'uninstall.exe'
$UninstKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$Product"
# Spuštění po přihlášení: plugin autostart zkusí nejdřív celý počítač (HKLM,
# jen když aplikace běží jako správce), jinak aktuálního uživatele (HKCU).
$RunKeys   = [ordered]@{
  'HKCU' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
  'HKLM' = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
}
$StartLnk  = Join-Path ([Environment]::GetFolderPath('Programs')) "$Product.lnk"
$DeskLnk   = Join-Path ([Environment]::GetFolderPath('Desktop')) "$Product.lnk"
$DataDir   = Join-Path $env:APPDATA 'cz.hh.antishield'
$Shot      = Join-Path $OutDir 'antishield-okno.png'
$Stop      = 'ZASTAVENO: '

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string] $Check, [string] $State, [string] $Detail) {
  $results.Add([pscustomobject]@{ Check = $Check; State = $State; Detail = $Detail })
  $tag = @{ ok = 'OK'; warn = 'POZOR'; fail = 'CHYBA' }[$State]
  Write-Host "[$tag] $Check – $Detail"
}

# Chyba, po které nemá smysl pokračovat (úklid ve finally proběhne).
function Stop-Test([string] $Check, [string] $Detail) {
  Add-Result $Check 'fail' $Detail
  throw "$Stop$Detail"
}

function Escape-Data([string] $s) { $s.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A') }

# Hodnota z registru, nebo $null (klíč či hodnota chybí).
function Get-RegValue([string] $Key, [string] $Name) {
  try { return (Get-Item -LiteralPath $Key -ErrorAction Stop).GetValue($Name) } catch { return $null }
}

# Spustí program přímo (bez Průzkumníka) a počká na konec; vrátí kód, nebo $null po vypršení.
function Invoke-Exe([string] $File, [string] $Arguments, [int] $TimeoutSec) {
  $psi = [Diagnostics.ProcessStartInfo]::new($File, $Arguments)
  $psi.UseShellExecute = $false
  $p = [Diagnostics.Process]::Start($psi)
  if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    try { $p.Kill($true) } catch { }
    return $null
  }
  return $p.ExitCode
}

function Wait-Until([scriptblock] $Condition, [int] $TimeoutSec, [int] $StepMs = 500) {
  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
  while ([DateTime]::UtcNow -lt $deadline) {
    if (& $Condition) { return $true }
    Start-Sleep -Milliseconds $StepMs
  }
  return [bool](& $Condition)
}

# Záznamy „spuštění po přihlášení“ aplikace: @{ Hive; Value }.
function Get-Autostart {
  foreach ($hive in $RunKeys.Keys) {
    $v = Get-RegValue $RunKeys[$hive] $Product
    if ($null -ne $v) { [pscustomobject]@{ Hive = $hive; Value = [string] $v } }
  }
}

# Hlavní okno aplikace (podle titulku) přes UI Automation, nebo $null.
# Process.MainWindowHandle nestačí: proces má i neviditelné pomocné okno
# pluginu single-instance („cz.hh.antishield-siw“).
function Find-AppWindow([int] $ProcessId) {
  $A = [System.Windows.Automation.AutomationElement]
  $cond = [System.Windows.Automation.PropertyCondition]::new($A::ProcessIdProperty, $ProcessId)
  $want = $Product.Replace('&', '')
  foreach ($w in $A::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children, $cond)) {
    # Win32 okno má v UI Automation „&“ vypuštěné (značka klávesové zkratky).
    if ("$($w.Current.Name)".Replace('&', '') -eq $want) { return $w }
  }
  return $null
}

# Texty z okna aplikace přes UI Automation (WebView2 zpřístupňuje obsah stránky).
function Get-WindowTexts($win) {
  $all = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
  $names = foreach ($e in $all) {
    $n = $null
    try { $n = $e.Current.Name } catch { }
    if ($n) { $n.Trim() }
  }
  return @($names | Where-Object { $_ } | Select-Object -Unique)
}

$app = $null
$installed = $false
$texts = @()
try {
  # ── 1. Instalátor ────────────────────────────────────────────────
  $item = Get-Item -LiteralPath $Installer
  $hash = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant()
  Add-Result 'Instalátor' 'ok' ('{0}, {1:N1} MB, SHA-256 {2}' -f $item.Name, ($item.Length / 1MB), $hash)
  $sig = Get-AuthenticodeSignature -LiteralPath $Installer
  if ($sig.Status -eq 'Valid') {
    Add-Result 'Podpis' 'ok' $sig.SignerCertificate.Subject
  } else {
    Add-Result 'Podpis' 'warn' "Bez digitálního podpisu ($($sig.Status)): prohlížeč i Windows při stažení varují"
  }
  if (Test-Path -LiteralPath $InstDir) { Stop-Test 'Čistý systém' "Složka $InstDir už existuje" }

  # ── 2. Tichá instalace ───────────────────────────────────────────
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $installed = $true
  $code = Invoke-Exe $Installer '/S' 300
  if ($null -eq $code) { Stop-Test 'Instalace' 'Nedoběhla do 5 minut' }
  if ($code -ne 0) { Stop-Test 'Instalace' "Instalátor skončil s kódem $code" }
  Add-Result 'Instalace' 'ok' ('Pro aktuálního uživatele, bez práv správce, {0:N1} s' -f $sw.Elapsed.TotalSeconds)

  if (-not (Test-Path -LiteralPath $AppExe)) { Stop-Test 'Soubory' "Chybí $AppExe" }
  if (-not (Test-Path -LiteralPath $Uninst)) { Stop-Test 'Soubory' "Chybí $Uninst" }
  $fileVer = (Get-Item -LiteralPath $AppExe).VersionInfo.ProductVersion
  Add-Result 'Soubory' 'ok' "$InstDir (aplikace verze $fileVer, odinstalátor)"

  $shownVer = Get-RegValue $UninstKey 'DisplayVersion'
  if ($null -eq $shownVer) { Stop-Test 'Aplikace ve Windows' 'Chybí záznam pro odinstalaci' }
  if ($shownVer -ne $Version) { Stop-Test 'Aplikace ve Windows' "Verze $shownVer, čekala se $Version" }
  Add-Result 'Aplikace ve Windows' 'ok' "$(Get-RegValue $UninstKey 'DisplayName') $shownVer (Nastavení → Aplikace)"

  $missing = @(@($StartLnk, $DeskLnk) | Where-Object { -not (Test-Path -LiteralPath $_) })
  if ($missing.Count) { Add-Result 'Zástupci' 'warn' ('Chybí: ' + ($missing -join ', ')) }
  else { Add-Result 'Zástupci' 'ok' 'Nabídka Start i plocha' }

  # ── 3. Spuštění ──────────────────────────────────────────────────
  $uia = $true
  try { Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes } catch {
    $uia = $false
    Add-Result 'UI Automation' 'warn' "Není k dispozici, okno se ověří jen podle procesu: $($_.Exception.Message)"
  }
  $sw.Restart()
  $psi = [Diagnostics.ProcessStartInfo]::new($AppExe)
  $psi.UseShellExecute = $false
  $psi.WorkingDirectory = $InstDir
  $app = [Diagnostics.Process]::Start($psi)
  $win = $null
  $shown = Wait-Until {
    $app.Refresh()
    if ($app.HasExited) { return $true }
    if (-not $uia) { return $app.MainWindowHandle -ne [IntPtr]::Zero }
    $script:win = Find-AppWindow $app.Id
    $null -ne $script:win
  } 90
  if ($app.HasExited) { Stop-Test 'Spuštění' "Aplikace hned skončila (kód $($app.ExitCode))" }
  # Pozor: PowerShell bere „ a “ jako uvozovky – české uvozovky jen v '…' řetězcích.
  if (-not $shown) { Stop-Test 'Spuštění' ('Okno „{0}“ se do 90 s neukázalo' -f $Product) }
  if ($uia) {
    $r = $win.Current.BoundingRectangle
    $vidi = -not $win.Current.IsOffscreen
    Add-Result 'Spuštění' $(if ($vidi) { 'ok' } else { 'warn' }) ('Okno „{0}“ {1:N0}×{2:N0} px{3} za {4:N1} s' -f $Product, $r.Width, $r.Height, $(if ($vidi) { '' } else { ' (mimo obrazovku)' }), $sw.Elapsed.TotalSeconds)
  } else {
    Add-Result 'Spuštění' 'ok' ('Proces běží a má okno, za {0:N1} s' -f $sw.Elapsed.TotalSeconds)
  }

  # Obsah: rozhraní je vykreslené, když je v postranním panelu vidět
  # „Verze <verze>“ (úvodní animace ho první ~3 s skrývá). Engine je
  # načtený, když stav dole v panelu přestane hlásit „Načítám stav…“.
  if ($uia) {
    $rendered = Wait-Until {
      $app.Refresh()
      if ($app.HasExited) { return $true }
      $script:texts = @(Get-WindowTexts $win)
      $joined = $script:texts -join ' '
      $joined.Contains('Verze') -and $joined.Contains($Version)
    } 90 2000
    if ($app.HasExited) { Stop-Test 'Obsah okna' "Aplikace během načítání skončila (kód $($app.ExitCode))" }
    $sample = @($texts | Select-Object -First 30) -join ' · '
    if (-not $rendered) { Stop-Test 'Obsah okna' "Rozhraní se do 90 s nevykreslilo. Vidět je: $sample" }
    Add-Result 'Obsah okna' 'ok' ('Rozhraní vykreslené za {0:N1} s: {1}' -f $sw.Elapsed.TotalSeconds, $sample)

    $engine = Wait-Until {
      $app.Refresh()
      if ($app.HasExited) { return $true }
      $script:texts = @(Get-WindowTexts $win)
      -not (($script:texts -join ' ').Contains('Načítám stav'))
    } 120 2000
    if ($app.HasExited) { Stop-Test 'Engine' "Aplikace při načítání enginu skončila (kód $($app.ExitCode))" }
    if ($engine) { Add-Result 'Engine' 'ok' ('Stav ochrany načtený za {0:N1} s od spuštění' -f $sw.Elapsed.TotalSeconds) }
    else { Add-Result 'Engine' 'warn' 'Stav ochrany se do 120 s nenačetl („Načítám stav…“)' }
  }

  # Spuštění po přihlášení (výchozí nastavení: zapnuto).
  $auto = @(Get-Autostart)
  if (-not $auto.Count) {
    Add-Result 'Spuštění po přihlášení' 'warn' 'Aplikace se nezapsala do spouštění po přihlášení (HKCU ani HKLM)'
  } else {
    foreach ($a in $auto) {
      $kde = @{ HKCU = 'pro uživatele (HKCU)'; HKLM = 'pro všechny uživatele (HKLM, aplikace běží jako správce)' }[$a.Hive]
      Add-Result 'Spuštění po přihlášení' 'ok' "$kde`: $($a.Value)"
      # Cesta s mezerou bez uvozovek: Windows ji dohledá, ale je to vzor,
      # který bezpečnostní kontroly hlásí (unquoted path).
      if ($a.Value -notmatch '^"' -and $a.Value -match '^[^"]* [^"]*\.exe') {
        Add-Result 'Cesta ve spouštění' 'warn' "Cesta s mezerou není v uvozovkách: $($a.Value)"
      }
    }
  }

  if (Test-Path -LiteralPath $DataDir) {
    $files = @(Get-ChildItem -LiteralPath $DataDir -Force | ForEach-Object Name)
    Add-Result 'Data aplikace' 'ok' "${DataDir}: $($files -join ', ')"
  } else {
    Add-Result 'Data aplikace' 'warn' "Složka $DataDir nevznikla"
  }

  # Snímek obrazovky pro kontrolu očima (artefakt běhu).
  try {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = [System.Drawing.Bitmap]::new($b.Width, $b.Height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $bmp.Save($Shot, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Snímek obrazovky: $Shot"
  } catch {
    Add-Result 'Snímek obrazovky' 'warn' $_.Exception.Message
  }

  # Ještě chvíli běží (ochrana, pravidla, plánovač) – nesmí spadnout.
  Start-Sleep -Seconds 15
  $app.Refresh()
  if ($app.HasExited) { Stop-Test 'Běh' "Aplikace po spuštění spadla (kód $($app.ExitCode))" }
  Add-Result 'Běh' 'ok' ('Běží {0:N0} s bez pádu' -f $sw.Elapsed.TotalSeconds)
} catch {
  # Zastavení přes Stop-Test má výsledek už zapsaný.
  if (-not "$($_.Exception.Message)".StartsWith($Stop)) { Add-Result 'Zkouška' 'fail' $_.Exception.Message }
} finally {
  # ── 4. Ukončení a odinstalace ────────────────────────────────────
  if ($app -and -not $app.HasExited) {
    try { $app.Kill($true); $null = $app.WaitForExit(15000) } catch { }
  }
  if ($installed -and (Test-Path -LiteralPath $Uninst)) {
    try {
      # _?= spustí odinstalátor na místě a synchronně (jinak se zkopíruje
      # do dočasné složky a vrátí se hned); musí být poslední a bez uvozovek.
      $code = Invoke-Exe $Uninst "/S _?=$InstDir" 180
      $left = @(@($AppExe, $StartLnk, $DeskLnk) | Where-Object { Test-Path -LiteralPath $_ })
      if ($null -ne (Get-RegValue $UninstKey 'DisplayName')) { $left += 'záznam v Aplikacích' }
      $autoLeft = @(Get-Autostart)
      if (@($autoLeft | Where-Object Hive -eq 'HKCU').Count) { $left += 'spouštění po přihlášení (HKCU)' }
      if ($code -ne 0) { Add-Result 'Odinstalace' 'fail' "Odinstalátor skončil s kódem $code" }
      elseif ($left.Count) { Add-Result 'Odinstalace' 'fail' ('Zůstalo: ' + ($left -join ', ')) }
      else { Add-Result 'Odinstalace' 'ok' 'Aplikace, zástupci, záznam v Aplikacích i spouštění po přihlášení (HKCU) odstraněny' }
      # Odinstalátor maže jen HKCU; záznam v HKLM (aplikace běžela jako
      # správce) by po odinstalaci zůstal – nahlásit a uklidit.
      if (@($autoLeft | Where-Object Hive -eq 'HKLM').Count) {
        Add-Result 'Odinstalace' 'warn' 'Zůstalo spouštění po přihlášení pro všechny uživatele (HKLM) – odinstalátor maže jen HKCU; uklizeno skriptem'
        Remove-ItemProperty -LiteralPath $RunKeys['HKLM'] -Name $Product -ErrorAction SilentlyContinue
      }
    } catch {
      Add-Result 'Odinstalace' 'fail' $_.Exception.Message
    }
    # Při _?= zůstane jen samotný odinstalátor a prázdná složka.
    Remove-Item -LiteralPath $InstDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# ── Souhrn ─────────────────────────────────────────────────────────
$failed = @($results | Where-Object State -eq 'fail')
$warned = @($results | Where-Object State -eq 'warn')
$okRows = @($results | Where-Object State -eq 'ok' | ForEach-Object { "✓ $($_.Check): $($_.Detail)" })
if ($okRows.Count) {
  Write-Host ("::notice title=Instalace na Windows ($Version)::" + (Escape-Data ($okRows -join "`n")))
}
foreach ($r in $warned) { Write-Host ("::warning title=$($r.Check)::" + (Escape-Data $r.Detail)) }
foreach ($r in $failed) { Write-Host ("::error title=$($r.Check)::" + (Escape-Data $r.Detail)) }

if ($env:GITHUB_STEP_SUMMARY) {
  $icon = @{ ok = '✅'; warn = '⚠️'; fail = '❌' }
  $md = @("### Instalace H&H AntiShield $Version na Windows", '', '| | Kontrola | Výsledek |', '|---|---|---|')
  $md += @($results | ForEach-Object { "| $($icon[$_.State]) | $($_.Check) | $($_.Detail.Replace('|', '/')) |" })
  ($md -join "`n") + "`n" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
}
if ($failed.Count) { exit 1 }
