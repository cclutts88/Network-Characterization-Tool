param(
    [Parameter(Mandatory=$true)][string]$TargetRoot,
    [Parameter(Mandatory=$true)][string]$CorpusRoot,
    [Parameter(Mandatory=$true)][string]$WorkRoot,
    [Parameter(Mandatory=$true)][string]$ArtifactRoot,
    [Parameter(Mandatory=$true)][ValidateRange(1,3)][int]$Repeat,
    [string]$Image = 'nct-foundation-tests:local'
)
$ErrorActionPreference = 'Stop'

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    $output = & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE" }
    return ($output -join "`n").Trim()
}

function Wait-ForApplication([string]$Container) {
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        & docker exec $Container python -c "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=2))['status'])" 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Milliseconds 500
    }
    throw 'Application did not become ready'
}

$benchmarkRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$target = (Resolve-Path -LiteralPath $TargetRoot).Path
$corpus = (Resolve-Path -LiteralPath $CorpusRoot).Path
$targetForGit = $target.Replace('\','/')
$revision = Invoke-Checked 'git' @('-c', "safe.directory=$targetForGit", '-C', $target, 'rev-parse', 'HEAD')
$status = Invoke-Checked 'git' @('-c', "safe.directory=$targetForGit", '-C', $target, 'status', '--porcelain=v1', '--untracked-files=all')
if ($status) { throw 'Target checkout must be clean before a retained concurrency repeat' }

$token = [guid]::NewGuid().ToString('N')
$appName = "nct-phase0-concurrent-app-$($token.Substring(0,8))"
$clientName = "nct-phase0-concurrent-client-$($token.Substring(0,8))"
$networkName = "nct-phase0-concurrent-net-$($token.Substring(0,8))"
$dataRoot = Join-Path $WorkRoot "data-$token"
$artifact = [System.IO.Path]::GetFullPath($ArtifactRoot)
$dataRootExistedBefore = Test-Path -LiteralPath $dataRoot
if ($dataRootExistedBefore) { throw 'Fresh data root already exists' }
if (Test-Path -LiteralPath $artifact) { throw 'Artifact root must not exist before a repeat' }
New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
New-Item -ItemType Directory -Path $artifact -Force | Out-Null
New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null

$setupPath = Join-Path $artifact 'setup.json'
$beforePath = Join-Path $artifact 'before.json'
$runPath = Join-Path $artifact 'client-run.json'
$verificationPath = Join-Path $artifact 'verification.json'
$resultPath = Join-Path $artifact 'result.json'
$cleanupPath = Join-Path $artifact 'cleanup.json'
$appLogPath = Join-Path $artifact 'application.log'
$preparePath = Join-Path $artifact 'preparation.json'
$processPath = Join-Path $artifact 'application-processes.json'
$appResourceBeforePath = Join-Path $artifact 'application-resource-before.json'
$appResourceAfterPath = Join-Path $artifact 'application-resource-after.json'
$inspectionPath = Join-Path $artifact 'container-inspection.json'
$attestationPath = Join-Path $artifact 'git-fresh-attestation.json'
$runSucceeded = $false
$appCreated = $false
$clientCreated = $false
$networkCreated = $false
$imageId = $null
try {
    $attestation = [ordered]@{
        verification_method='controller:git-status-and-fresh-root-preflight'
        revision=$revision;status_porcelain=$status;clean=$true;target_root=$target
        data_root_host_path=$dataRoot;data_root_existed_before=[bool]$dataRootExistedBefore
        data_root_empty_after_creation=((Get-ChildItem -LiteralPath $dataRoot -Force).Count -eq 0)
    }
    if (-not $attestation.data_root_empty_after_creation) { throw 'Fresh benchmark data root was not empty' }
    $attestation | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $attestationPath -Encoding utf8
    $imageId = Invoke-Checked 'docker' @('image','inspect','--format','{{.Id}}',$Image)
    Invoke-Checked 'docker' @(
        'run','--rm','--network','none',
        '-v',"${target}:/target:ro",'-v',"${benchmarkRoot}:/benchmark:ro",
        '-v',"${corpus}:/corpus:ro",'-v',"${dataRoot}:/data:rw",'-w','/benchmark',
        $Image,'python','scripts/prepare_phase0_browser_data.py',
        '--target-root','/target','--corpus','/corpus','--data-root','/data',
        '--revision',$revision,'--foundation-capabilities','--allow-existing-empty-data-root',
        '--output','/data/.phase0-concurrent-preparation.json'
    ) | Set-Content -LiteralPath $preparePath -Encoding utf8

    Invoke-Checked 'docker' @('network','create','--internal',$networkName) | Out-Null
    $networkCreated = $true
    $network = (Invoke-Checked 'docker' @('network','inspect',$networkName) | ConvertFrom-Json)[0]
    if (-not $network.Internal) { throw 'Benchmark network is not internal' }

    $appId = Invoke-Checked 'docker' @(
        'create','--name',$appName,'--network',$networkName,
        '--label',"nct.phase0.concurrent.token=$token",
        '-v',"${target}:/workspace:ro",'-v',"${benchmarkRoot}:/benchmark:ro",
        '-v',"${dataRoot}:/data:rw",'-w','/workspace',
        '-e','ANALYZER_DATA_DIR=/data','-e','NCT_AUTH_MODE=local',
        '-e','NCT_BOOTSTRAP_ADMIN=phase0admin','-e','NCT_BOOTSTRAP_PASSWORD=phase0 phase0admin password',
        $Image,'python','-m','uvicorn','app.main:app','--host','0.0.0.0','--port','8080'
    )
    $appCreated = $true
    Invoke-Checked 'docker' @('start',$appName) | Out-Null
    Wait-ForApplication $appName

    Invoke-Checked 'docker' @(
        'run','--rm','--network',$networkName,
        '-v',"${benchmarkRoot}:/benchmark:ro",'-v',"${artifact}:/artifacts:rw",'-w','/benchmark',
        $Image,'python','scripts/benchmark_phase0_concurrent_clients.py','--mode','setup',
        '--base-url',"http://${appName}:8080",'--output','/artifacts/setup.json'
    ) | Out-Null

    Invoke-Checked 'docker' @('stop','--time','15',$appName) | Out-Null
    Invoke-Checked 'docker' @(
        'run','--rm','--network','none','-v',"${benchmarkRoot}:/benchmark:ro",
        '-v',"${dataRoot}:/data:ro",'-w','/benchmark',$Image,'python',
        'scripts/verify_phase0_concurrent_state.py','--mode','snapshot','--data-root','/data'
    ) | Set-Content -LiteralPath $beforePath -Encoding utf8

    Invoke-Checked 'docker' @('start',$appName) | Out-Null
    Wait-ForApplication $appName
    $processRaw = Invoke-Checked 'docker' @('exec',$appName,'python','/benchmark/scripts/capture_application_processes.py')
    $processRaw | Set-Content -LiteralPath $processPath -Encoding utf8
    $processes = $processRaw | ConvertFrom-Json
    if ($processes.uvicorn_application_process_count -ne 1) { throw 'Expected exactly one Uvicorn application process' }
    $appResourceBeforeRaw = Invoke-Checked 'docker' @('exec',$appName,'python','/benchmark/scripts/capture_linux_cgroup_resources.py')
    $appResourceBeforeRaw | Set-Content -LiteralPath $appResourceBeforePath -Encoding utf8
    $appResourceBefore = $appResourceBeforeRaw | ConvertFrom-Json

    $clientId = Invoke-Checked 'docker' @(
        'run','-d','--name',$clientName,'--network',$networkName,
        '--label',"nct.phase0.concurrent.client-token=$token",
        '-v',"${benchmarkRoot}:/benchmark:ro",'-v',"${artifact}:/artifacts:rw",'-w','/benchmark',
        $Image,'python','scripts/benchmark_phase0_concurrent_clients.py','--mode','run',
        '--base-url',"http://${appName}:8080",'--setup','/artifacts/setup.json',
        '--output','/artifacts/client-run.json'
    )
    $clientCreated = $true
    $deadline = (Get-Date).AddSeconds(300)
    do {
        $running = (Invoke-Checked 'docker' @('inspect','--format','{{.State.Running}}',$clientName)) -eq 'true'
        if ($running) { Start-Sleep -Milliseconds 500 }
    } while ($running -and (Get-Date) -lt $deadline)
    if ($running) { throw 'Concurrent client workload exceeded the controller deadline' }
    $clientExit = [int](Invoke-Checked 'docker' @('inspect','--format','{{.State.ExitCode}}',$clientName))
    if ($clientExit -ne 0) {
        Invoke-Checked 'docker' @('logs',$clientName) | Set-Content -LiteralPath (Join-Path $artifact 'client-error.log') -Encoding utf8
        throw "Concurrent client workload exited $clientExit"
    }
    $appResourceAfterRaw = Invoke-Checked 'docker' @('exec',$appName,'python','/benchmark/scripts/capture_linux_cgroup_resources.py')
    $appResourceAfterRaw | Set-Content -LiteralPath $appResourceAfterPath -Encoding utf8
    $appResourceAfter = $appResourceAfterRaw | ConvertFrom-Json
    $appLogLines = & docker logs $appName 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Could not read application logs' }
    $appLogLines | Set-Content -LiteralPath $appLogPath -Encoding utf8
    $appLog = Get-Content -LiteralPath $appLogPath -Raw
    if ($appLog -match '(?i)database is locked|database is busy|sqlite.*locked|traceback|exception in asgi') {
        throw 'Application log contains a database lock or unhandled error'
    }
    Invoke-Checked 'docker' @('stop','--time','15',$appName) | Out-Null

    Invoke-Checked 'docker' @(
        'run','--rm','--network','none','-v',"${benchmarkRoot}:/benchmark:ro",
        '-v',"${dataRoot}:/data:ro",'-v',"${artifact}:/artifacts:rw",'-w','/benchmark',
        $Image,'python','scripts/verify_phase0_concurrent_state.py','--mode','verify',
        '--data-root','/data','--before','/artifacts/before.json','--setup','/artifacts/setup.json',
        '--run','/artifacts/client-run.json','--output','/artifacts/verification.json'
    ) | Out-Null

    $run = Get-Content -LiteralPath $runPath -Raw | ConvertFrom-Json
    $verification = Get-Content -LiteralPath $verificationPath -Raw | ConvertFrom-Json
    if (-not $run.summary.passed -or -not $verification.passed) { throw 'Concurrent benchmark correctness verification failed' }
    $appCpuSeconds = ([double]$appResourceAfter.cpu_usage_usec - [double]$appResourceBefore.cpu_usage_usec) / 1000000
    $appPeak = [long]$appResourceAfter.peak_memory_bytes
    $clientCpuSeconds = [double]$run.client_container_resources.cpu_usage_usec / 1000000
    $clientPeak = [long]$run.client_container_resources.peak_memory_bytes
    $resourceLimits = [ordered]@{app_cpu_seconds=240;client_cpu_seconds=240;app_peak_memory_bytes=2147483648;client_peak_memory_bytes=2147483648}
    if ($appCpuSeconds -gt $resourceLimits.app_cpu_seconds -or $clientCpuSeconds -gt $resourceLimits.client_cpu_seconds -or $appPeak -gt $resourceLimits.app_peak_memory_bytes -or $clientPeak -gt $resourceLimits.client_peak_memory_bytes) {
        throw 'A predeclared CPU or peak-memory limit was exceeded'
    }
    $inspect = (Invoke-Checked 'docker' @('inspect',$appName) | ConvertFrom-Json)[0]
    $clientInspect = (Invoke-Checked 'docker' @('inspect',$clientName) | ConvertFrom-Json)[0]
    $appMounts = @($inspect.Mounts | ForEach-Object { [ordered]@{destination=$_.Destination;rw=[bool]$_.RW;source=$_.Source} })
    $clientMounts = @($clientInspect.Mounts | ForEach-Object { [ordered]@{destination=$_.Destination;rw=[bool]$_.RW;source=$_.Source} })
    $appNetworks = @($inspect.NetworkSettings.Networks.PSObject.Properties.Name)
    $clientNetworks = @($clientInspect.NetworkSettings.Networks.PSObject.Properties.Name)
    if ($inspect.Image -ne $imageId -or $clientInspect.Image -ne $imageId) { throw 'Inspected container image identity changed' }
    if ($appNetworks.Count -ne 1 -or $appNetworks[0] -ne $networkName -or $clientNetworks.Count -ne 1 -or $clientNetworks[0] -ne $networkName) { throw 'A measured container is not isolated on the internal benchmark network' }
    $appMountByDestination = @{}; foreach($mount in $appMounts){$appMountByDestination[$mount.destination]=$mount}
    $clientMountByDestination = @{}; foreach($mount in $clientMounts){$clientMountByDestination[$mount.destination]=$mount}
    if ($appMountByDestination['/workspace'].rw -or $appMountByDestination['/benchmark'].rw -or -not $appMountByDestination['/data'].rw -or $clientMountByDestination['/benchmark'].rw -or -not $clientMountByDestination['/artifacts'].rw) { throw 'Inspected benchmark mount permissions are incorrect' }
    $inspection = [ordered]@{
        verification_method='controller:docker-inspect-sanitized';network=[ordered]@{id=$network.Id;name=$networkName;internal=[bool]$network.Internal}
        application=[ordered]@{id=$inspect.Id;image=$inspect.Image;created=$inspect.Created;path=$inspect.Path;args=@($inspect.Args);mounts=$appMounts;networks=$appNetworks}
        client=[ordered]@{id=$clientInspect.Id;image=$clientInspect.Image;created=$clientInspect.Created;path=$clientInspect.Path;args=@($clientInspect.Args);mounts=$clientMounts;networks=$clientNetworks}
    }
    $inspection | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $inspectionPath -Encoding utf8
    $rawArtifactNames = @('setup.json','preparation.json','before.json','client-run.json','verification.json','application.log','application-processes.json','application-resource-before.json','application-resource-after.json','container-inspection.json','git-fresh-attestation.json')
    $rawArtifacts = [ordered]@{}
    foreach($name in $rawArtifactNames){$rawArtifacts[$name]=(Get-FileHash -LiteralPath (Join-Path $artifact $name) -Algorithm SHA256).Hash.ToLowerInvariant()}
    $preparation = Get-Content -LiteralPath $preparePath -Raw | ConvertFrom-Json
    $result = [ordered]@{
        benchmark_version='phase0-concurrent-controller:1'; passed=$true; repeat=$Repeat
        identity=[ordered]@{
            revision=$revision; clean_git=$true; target_root=$target; image_id=$imageId; app_container_id=$appId
            client_container_id=$clientId; network_id=$network.Id; network_internal=$true
            controller_token=$token; fresh_data_root=$true; data_root_host_path=$dataRoot; source_mount_read_only=$true
            benchmark_mount_read_only=$true; corpus_manifest_sha256=(Get-Content -LiteralPath $preparePath -Raw | ConvertFrom-Json).corpus_manifest_sha256
            source_digest_sha256=$preparation.source_digest_sha256
            runner_sha256=(Get-FileHash -LiteralPath (Join-Path $benchmarkRoot 'scripts/benchmark_phase0_concurrent_clients.py') -Algorithm SHA256).Hash.ToLowerInvariant()
            verifier_sha256=(Get-FileHash -LiteralPath (Join-Path $benchmarkRoot 'scripts/verify_phase0_concurrent_state.py') -Algorithm SHA256).Hash.ToLowerInvariant()
            controller_sha256=(Get-FileHash -LiteralPath (Join-Path $benchmarkRoot 'scripts/run_phase0_concurrent_repeat.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
            preparation_sha256=(Get-FileHash -LiteralPath (Join-Path $benchmarkRoot 'scripts/prepare_phase0_browser_data.py') -Algorithm SHA256).Hash.ToLowerInvariant()
            process_capture_sha256=(Get-FileHash -LiteralPath (Join-Path $benchmarkRoot 'scripts/capture_application_processes.py') -Algorithm SHA256).Hash.ToLowerInvariant()
            resource_capture_sha256=(Get-FileHash -LiteralPath (Join-Path $benchmarkRoot 'scripts/capture_linux_cgroup_resources.py') -Algorithm SHA256).Hash.ToLowerInvariant()
            single_application_process=$processes
            app_container_created_at=$inspect.Created
        }
        resources=[ordered]@{
            limits=$resourceLimits
            application=[ordered]@{cpu_seconds=[math]::Round($appCpuSeconds,6);container_lifetime_peak_memory_bytes=$appPeak;memory_scope='full measured container lifetime, including startup and setup'}
            clients=[ordered]@{cpu_seconds=[math]::Round($clientCpuSeconds,6);container_lifetime_peak_memory_bytes=$clientPeak;memory_scope='full client container lifetime'}
        }
        client_summary=$run.summary
        state_verification=[ordered]@{
            passed=$verification.passed; actual_changed_tables=$verification.actual_changed_tables
            evidence_sha256=$verification.after.evidence_sha256
            evidence_file_count=$verification.after.evidence_file_count
            database_integrity=$verification.after.database_integrity
        }
        limitations=@(
            'Eight simulated analyst client processes against one single-process Uvicorn NCT container.',
            'No multi-worker server, multiple application containers, worker lease/checkpoint, live scan, browser, Range, production-scale, or mission claim.'
        )
        raw_artifacts=$rawArtifacts
    }
    $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resultPath -Encoding utf8
    $runSucceeded = $true
} finally {
    $clientRemoved = $false; $appRemoved = $false; $networkRemoved = $false; $dataRemoved = $false
    if ($clientCreated) { & docker rm -f $clientName | Out-Null; $clientRemoved = $LASTEXITCODE -eq 0 }
    if ($appCreated) { & docker rm -f $appName | Out-Null; $appRemoved = $LASTEXITCODE -eq 0 }
    if ($networkCreated) { & docker network rm $networkName | Out-Null; $networkRemoved = $LASTEXITCODE -eq 0 }
    if (Test-Path -LiteralPath $dataRoot) { Remove-Item -LiteralPath $dataRoot -Recurse -Force }
    $dataRemoved = -not (Test-Path -LiteralPath $dataRoot)
    $cleanup = [ordered]@{
        verification_method='controller:post-run-resource-verification';run_succeeded=$runSucceeded
        app_container_removed=$appRemoved;client_container_removed=$clientRemoved
        internal_network_removed=$networkRemoved;data_root_removed=$dataRemoved;controller_token=$token
        result_sha256=if(Test-Path -LiteralPath $resultPath){(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
    }
    $cleanup | ConvertTo-Json | Set-Content -LiteralPath $cleanupPath -Encoding utf8
}
if (-not $runSucceeded) { throw 'Concurrent benchmark repeat did not complete' }
