param(
    [Parameter(Mandatory = $true)][string]$ProjectUuid,
    [Parameter(Mandatory = $true)][string]$Image,
    [Parameter(Mandatory = $true)][string]$Sbom,
    [string]$DependencyTree,
    [string]$VulnerabilityRules,
    [string]$Output = "sca-accuracy-out",
    [switch]$WithLlm
)

$ErrorActionPreference = "Stop"

if (-not $env:DEPENDENCY_TRACK_URL) { throw "DEPENDENCY_TRACK_URL is required" }
if (-not $env:DEPENDENCY_TRACK_API_KEY) { throw "DEPENDENCY_TRACK_API_KEY is required" }
if (-not (Test-Path -LiteralPath $Sbom -PathType Leaf)) { throw "SBOM file not found: $Sbom" }

New-Item -ItemType Directory -Force -Path $Output | Out-Null
$findings = Join-Path $Output "findings.vdr.json"

$uploadJson = uv run sca-accuracy-dtrack upload-bom --project $ProjectUuid --file $Sbom
if ($LASTEXITCODE -ne 0) { throw "Initial SBOM upload failed" }
$upload = $uploadJson | ConvertFrom-Json
if (-not $upload.token) { throw "Dependency-Track did not return a BOM processing token" }

uv run sca-accuracy-dtrack wait-bom --token $upload.token --timeout 600
if ($LASTEXITCODE -ne 0) { throw "Dependency-Track did not finish the initial BOM" }
uv run sca-accuracy-dtrack export-vdr --project $ProjectUuid --output $findings
if ($LASTEXITCODE -ne 0) { throw "VDR export failed" }

$analysisArgs = @(
    "run", "sca-accuracy",
    "--sbom", $Sbom,
    "--image", $Image,
    "--output", $Output,
    "--findings", $findings,
    "--vex-mode", "safe"
)
if ($DependencyTree) { $analysisArgs += @("--dependency-tree", $DependencyTree) }
if ($VulnerabilityRules) { $analysisArgs += @("--vulnerability-rules", $VulnerabilityRules) }
if ($WithLlm) { $analysisArgs += "--with-llm" }
& uv @analysisArgs
if ($LASTEXITCODE -ne 0) { throw "SCA accuracy analysis failed" }

$enrichedSbom = Join-Path $Output "sbom.enriched.json"
$vex = Join-Path $Output "vex.json"
$enrichedJson = uv run sca-accuracy-dtrack upload-bom --project $ProjectUuid --file $enrichedSbom
if ($LASTEXITCODE -ne 0) { throw "Enriched SBOM upload failed" }
$enrichedUpload = $enrichedJson | ConvertFrom-Json
if ($enrichedUpload.token) {
    uv run sca-accuracy-dtrack wait-bom --token $enrichedUpload.token --timeout 600
    if ($LASTEXITCODE -ne 0) { throw "Dependency-Track did not finish the enriched SBOM" }
}
uv run sca-accuracy-dtrack apply-vex --project $ProjectUuid --file $vex
if ($LASTEXITCODE -ne 0) { throw "VEX upload failed" }

Write-Output "##teamcity[publishArtifacts '$Output/** => sca-accuracy.zip']"
Write-Output "SCA accuracy pipeline completed for $Image"
