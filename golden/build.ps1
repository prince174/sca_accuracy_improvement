$ErrorActionPreference = "Stop"

$goldenRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$mavenImage = "maven:3.9.11-eclipse-temurin-21"
$runtimeImage = "sca-accuracy-golden:latest"
$bindMount = "type=bind,source=$goldenRoot,target=/workspace"
$cacheMount = "type=volume,source=sca-accuracy-m2,target=/root/.m2"

docker run --rm --mount $bindMount --mount $cacheMount -w /workspace/app $mavenImage `
    mvn -B clean package
if ($LASTEXITCODE -ne 0) { throw "Golden application Maven build failed" }

docker run --rm --mount $bindMount --mount $cacheMount -w /workspace/image-libs $mavenImage `
    mvn -B clean package
if ($LASTEXITCODE -ne 0) { throw "Golden image libraries Maven build failed" }

docker build --tag $runtimeImage $goldenRoot
if ($LASTEXITCODE -ne 0) { throw "Golden container build failed" }

Write-Output "Built $runtimeImage"
Write-Output "SBOM: $goldenRoot\app\target\bom.json"
Write-Output "Dependency tree: $goldenRoot\app\target\dependency-tree.json"
