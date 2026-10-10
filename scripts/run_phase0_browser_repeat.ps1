param(
    [Parameter(Mandatory=$true)][string]$TargetRoot,
    [Parameter(Mandatory=$true)][string]$CorpusRoot,
    [Parameter(Mandatory=$true)][string]$WorkRoot,
    [Parameter(Mandatory=$true)][string]$ArtifactRoot,
    [Parameter(Mandatory=$true)][ValidateRange(1,3)][int]$Repeat,
    [Parameter(Mandatory=$true)][int]$Port,
    [Parameter(Mandatory=$true)][string]$BrowserExecutable,
    [Parameter(Mandatory=$true)][string]$NodeExecutable,
    [Parameter(Mandatory=$true)][string]$NodePath,
    [string]$Image = 'nct-foundation-tests:local',
    [switch]$FoundationCapabilities
)
$ErrorActionPreference = 'Stop'

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    $output = & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE" }
    return ($output -join "`n").Trim()
}

$benchmarkRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$target = (Resolve-Path -LiteralPath $TargetRoot).Path
$corpus = (Resolve-Path -LiteralPath $CorpusRoot).Path
$browser = (Resolve-Path -LiteralPath $BrowserExecutable).Path
$node = (Resolve-Path -LiteralPath $NodeExecutable).Path
$targetForGit = $target.Replace('\','/')
$revision = Invoke-Checked 'git' @('-c', "safe.directory=$targetForGit", '-C', $target, 'rev-parse', 'HEAD')
$status = Invoke-Checked 'git' @('-c', "safe.directory=$targetForGit", '-C', $target, 'status', '--porcelain=v1', '--untracked-files=all')
if ($status) { throw 'Target checkout must be clean before a retained browser repeat' }

$token = [guid]::NewGuid().ToString()
$containerName = "nct-phase0-browser-$($token.Substring(0,8))"
$proxyName = "nct-phase0-browser-proxy-$($token.Substring(0,8))"
$networkName = "nct-phase0-browser-net-$($token.Substring(0,8))"
$dataRoot = Join-Path $WorkRoot "data-$token"
$containerDataRoot = '/data'
$profileRoot = Join-Path $WorkRoot "profile-$token"
$artifact = [System.IO.Path]::GetFullPath($ArtifactRoot)
$resultPath = Join-Path $artifact 'result.json'
$runnerResultPath = Join-Path $artifact 'runner-result.json'
$configPath = Join-Path $artifact 'controller-config.json'
$prepareReport = Join-Path $artifact 'preparation.json'
$cleanupReport = Join-Path $artifact 'controller-cleanup.json'
if (Test-Path -LiteralPath $dataRoot) { throw 'Fresh data root already exists' }
if (Test-Path -LiteralPath $profileRoot) { throw 'Fresh profile root already exists' }
if (Test-Path -LiteralPath $artifact) { throw 'Artifact root must not exist before a repeat' }
New-Item -ItemType Directory -Path $artifact -Force | Out-Null
New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null

$containerStarted = $false
$proxyStarted = $false
$networkCreated = $false
$runSucceeded = $false
try {
    New-Item -ItemType Directory -Path $dataRoot | Out-Null
    $imageId = Invoke-Checked 'docker' @('image', 'inspect', '--format', '{{.Id}}', $Image)
    $foundationFlag = @()
    if ($FoundationCapabilities) { $foundationFlag = @('--foundation-capabilities') }
    $prepareArgs = @(
        'run','--rm','--network','none',
        '-v',"${target}:/target:ro",
        '-v',"${benchmarkRoot}:/benchmark:ro",
        '-v',"${corpus}:/corpus:ro",
        '-v',"${dataRoot}:/data:rw",
        '-w','/benchmark',$Image,'python','scripts/prepare_phase0_browser_data.py',
        '--target-root','/target','--corpus','/corpus','--data-root',$containerDataRoot,
        '--revision',$revision,'--output',"$containerDataRoot/.phase0-browser-preparation-output.json",
        '--allow-existing-empty-data-root'
    ) + $foundationFlag
    Invoke-Checked 'docker' $prepareArgs | Set-Content -LiteralPath $prepareReport -Encoding utf8
    $prepared = Get-Content -LiteralPath $prepareReport -Raw | ConvertFrom-Json

    Invoke-Checked 'docker' @('network','create','--internal',$networkName) | Out-Null
    $networkCreated = $true
    $network = (Invoke-Checked 'docker' @('network','inspect',$networkName) | ConvertFrom-Json)[0]
    if (-not $network.Internal) { throw 'Benchmark network is not internal' }

    $containerId = Invoke-Checked 'docker' @(
        'run','-d','--name',$containerName,'--network',$networkName,
        '--label',"nct.phase0.browser.token=$token",
        '-v',"${target}:/workspace:ro",
        '-v',"${benchmarkRoot}:/benchmark:ro",
        '-v',"${dataRoot}:/data:rw",
        '-w','/workspace','-e','ANALYZER_DATA_DIR=/data','-e','NCT_AUTH_MODE=disabled',
        $Image,'python','-m','uvicorn','app.main:app','--host','0.0.0.0','--port','8080'
    )
    $containerStarted = $true
    $proxyId = Invoke-Checked 'docker' @(
        'run','-d','--name',$proxyName,'--network','bridge',
        '--label',"nct.phase0.browser.proxy-token=$token",
        '-p',"127.0.0.1:${Port}:8080",
        '-v',"${benchmarkRoot}:/benchmark:ro",
        $Image,'python','/benchmark/scripts/phase0_loopback_proxy.py',
        '--listen','0.0.0.0:8080','--upstream',"${containerName}:8080"
    )
    $proxyStarted = $true
    Invoke-Checked 'docker' @('network','connect',$networkName,$proxyName) | Out-Null
    $ready = $false
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/analysis" -TimeoutSec 2
            if ($response.StatusCode -eq 200) { $ready = $true; break }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'Application did not become ready on the loopback publication' }
    foreach ($route in @('/analysis','/hunting','/reachability','/network-map')) {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port$route" -TimeoutSec 120
        if ($response.StatusCode -ne 200) { throw "Live prewarm failed for $route" }
    }

    $inspect = (Invoke-Checked 'docker' @('inspect',$containerName) | ConvertFrom-Json)[0]
    $proxyInspect = (Invoke-Checked 'docker' @('inspect',$proxyName) | ConvertFrom-Json)[0]
    if ($inspect.Id -ne $containerId -or $inspect.Image -ne $imageId) { throw 'Inspected container identity changed' }
    $env:NODE_PATH = $NodePath
    $playwrightVersion = Invoke-Checked $node @('-e',"console.log(require('playwright/package.json').version)")
    $browserVersion = (Get-Item -LiteralPath $browser).VersionInfo.ProductVersion
    $browserSha = (Get-FileHash -LiteralPath $browser -Algorithm SHA256).Hash.ToLowerInvariant()
    $identity = [ordered]@{
        type = 'externally-verified-browser-controller-attestations'
        validated = $true
        git = [ordered]@{
            verification_method = 'controller:git-rev-parse-status-and-source-digest'
            revision = $revision
            clean = $true
            source_digest_sha256 = $prepared.source_digest_sha256
        }
        corpus = [ordered]@{
            verification_method = 'controller:canonical-corpus-regeneration'
            manifest_sha256 = $prepared.corpus_manifest_sha256
        }
        container = [ordered]@{
            verification_method = 'controller:docker-inspect-and-prewarm'
            container_id = $inspect.Id
            image_id = $inspect.Image
            proxy_container_id = $proxyInspect.Id
            proxy_image_id = $proxyInspect.Image
            proxy_created_at = $proxyInspect.Created
            created_at = $inspect.Created
            controller_token = $token
            fresh_container = $true
            fresh_data_root = $true
            staging_complete = $true
            prewarm_complete = $true
            live_http_prewarm_complete = $true
            source_mount_read_only = $true
            benchmark_mount_read_only = $true
            source_mount_host_path = $target
            benchmark_mount_host_path = $benchmarkRoot
            data_mount_host_path = $dataRoot
            network_internal = $true
            network_id = $network.Id
            loopback_only_publication = $true
            published_host_ip = '127.0.0.1'
            relay_architecture = 'app on internal-only network; disposable dual-network TCP relay published on loopback'
        }
    }
    $config = [ordered]@{
        base_url = "http://127.0.0.1:$Port"
        repeat = $Repeat
        foundation_capabilities = [bool]$FoundationCapabilities
        container_name = $containerName
        container_id = $inspect.Id
        container_image_id = $inspect.Image
        revision = $revision
        source_digest_sha256 = $prepared.source_digest_sha256
        corpus_manifest_sha256 = $prepared.corpus_manifest_sha256
        browser_executable = $browser
        browser_sha256 = $browserSha
        browser_version = $browserVersion
        playwright_version = $playwrightVersion
        profile_root = $profileRoot
        artifact_root = $artifact
        snapshot_script_in_container = '/benchmark/scripts/snapshot_phase0_browser_state.py'
        identity_evidence = $identity
    }
    $config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $configPath -Encoding utf8
    Invoke-Checked $node @((Join-Path $benchmarkRoot 'scripts\benchmark_phase0_browser.mjs'),'--config',$configPath,'--output',$runnerResultPath) | Out-Null
    $runSucceeded = $true
} finally {
    $containerRemoved = $false
    $networkRemoved = $false
    $dataRemoved = $false
    $proxyRemoved = $false
    if ($proxyStarted) { & docker rm -f $proxyName | Out-Null; $proxyRemoved = $LASTEXITCODE -eq 0 }
    if ($containerStarted) { & docker rm -f $containerName | Out-Null; $containerRemoved = $LASTEXITCODE -eq 0 }
    if ($networkCreated) { & docker network rm $networkName | Out-Null; $networkRemoved = $LASTEXITCODE -eq 0 }
    if (Test-Path -LiteralPath $dataRoot) { Remove-Item -LiteralPath $dataRoot -Recurse -Force }
    $dataRemoved = -not (Test-Path -LiteralPath $dataRoot)
    if (Test-Path -LiteralPath $profileRoot) { Remove-Item -LiteralPath $profileRoot -Recurse -Force }
    $profileRemoved = -not (Test-Path -LiteralPath $profileRoot)
    $runnerResultSha = if (Test-Path -LiteralPath $runnerResultPath) { (Get-FileHash -LiteralPath $runnerResultPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
    $cleanupEvidence = [ordered]@{verification_method='controller:post-run-resource-verification';run_succeeded=$runSucceeded;app_container_removed=$containerRemoved;relay_container_removed=$proxyRemoved;internal_network_removed=$networkRemoved;data_root_removed=$dataRemoved;browser_profile_removed=$profileRemoved;controller_token=$token;runner_result_sha256=$runnerResultSha}
    $cleanupEvidence |
        ConvertTo-Json | Set-Content -LiteralPath $cleanupReport -Encoding utf8
}
if (-not $runSucceeded) { throw 'Rendered-browser repeat failed' }
if (-not ($containerRemoved -and $proxyRemoved -and $networkRemoved -and $dataRemoved -and $profileRemoved)) { throw 'Rendered-browser cleanup verification failed' }
$finalResult = Get-Content -LiteralPath $runnerResultPath -Raw | ConvertFrom-Json
$finalResult | Add-Member -NotePropertyName controller_cleanup -NotePropertyValue $cleanupEvidence
$finalResult | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $resultPath -Encoding utf8
Write-Output $resultPath
