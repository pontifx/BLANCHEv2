Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$burpDir = Join-Path $repoRoot "burp-extension"
$srcDir = Join-Path $burpDir "src\main\java"
$resourcesDir = Join-Path $burpDir "src\main\resources"
$buildDir = Join-Path $burpDir "build"
$depsDir = Join-Path $buildDir "deps"
$classesDir = Join-Path $buildDir "classes"
$runtimeDir = Join-Path $buildDir "runtime"
$manifestPath = Join-Path $buildDir "jar-manifest.mf"
$jarPath = Join-Path $buildDir "blanche-burp-extension-0.1.0-all.jar"
$javacCommand = Get-Command javac
if (-not $javacCommand) {
    throw "javac was not found on PATH"
}

$javaBinDir = Split-Path -Parent $javacCommand.Source
$jarExe = Join-Path $javaBinDir "jar.exe"
if (-not (Test-Path $jarExe)) {
    $discoveredJar = Get-ChildItem "C:\Program Files\Java" -Recurse -Filter jar.exe -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName -First 1
    if (-not $discoveredJar) {
        throw "jar.exe was not found next to javac at $javaBinDir and could not be discovered under C:\Program Files\Java"
    }

    $jarExe = $discoveredJar
}

$versions = @{
    Montoya = "2025.11"
    Jackson = "2.19.0"
}

$dependencies = @(
    @{
        File = "montoya-api-$($versions.Montoya).jar"
        Url  = "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/$($versions.Montoya)/montoya-api-$($versions.Montoya).jar"
        Runtime = $false
    },
    @{
        File = "jackson-databind-$($versions.Jackson).jar"
        Url  = "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/$($versions.Jackson)/jackson-databind-$($versions.Jackson).jar"
        Runtime = $true
    },
    @{
        File = "jackson-core-$($versions.Jackson).jar"
        Url  = "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/$($versions.Jackson)/jackson-core-$($versions.Jackson).jar"
        Runtime = $true
    },
    @{
        File = "jackson-annotations-$($versions.Jackson).jar"
        Url  = "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/$($versions.Jackson)/jackson-annotations-$($versions.Jackson).jar"
        Runtime = $true
    }
)

New-Item -ItemType Directory -Force $depsDir, $classesDir, $runtimeDir | Out-Null
Remove-Item -Recurse -Force $classesDir, $runtimeDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $classesDir, $runtimeDir | Out-Null

foreach ($dependency in $dependencies) {
    $target = Join-Path $depsDir $dependency.File
    if (-not (Test-Path $target)) {
        Write-Host "Downloading $($dependency.File)..."
        & curl.exe -L --fail --silent --show-error $dependency.Url --output $target
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to download $($dependency.Url)"
        }
    }
}

$classpath = ($dependencies | ForEach-Object { Join-Path $depsDir $_.File }) -join ";"
$javaFiles = Get-ChildItem -Path $srcDir -Recurse -Filter *.java | Select-Object -ExpandProperty FullName
if (-not $javaFiles) {
    throw "No Java sources found under $srcDir"
}

Write-Host "Compiling Burp extension sources..."
& javac -cp $classpath -d $classesDir $javaFiles
if ($LASTEXITCODE -ne 0) {
    throw "javac failed"
}

Write-Host "Staging runtime contents..."
Copy-Item -Recurse -Force (Join-Path $classesDir "*") $runtimeDir
if (Test-Path $resourcesDir) {
    Copy-Item -Recurse -Force (Join-Path $resourcesDir "*") $runtimeDir
}

Push-Location $runtimeDir
foreach ($dependency in $dependencies | Where-Object { $_.Runtime }) {
    & $jarExe xf (Join-Path $depsDir $dependency.File)
    if ($LASTEXITCODE -ne 0) {
        Pop-Location
        throw "Failed to unpack $($dependency.File)"
    }
}
Pop-Location

Get-ChildItem -Path (Join-Path $runtimeDir "META-INF") -Recurse -Include *.SF, *.DSA, *.RSA -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

@"
Manifest-Version: 1.0
Implementation-Title: BLANCHE Burp Extension
Implementation-Version: 0.1.0
"@ | Set-Content -Path $manifestPath -Encoding ascii

if (Test-Path $jarPath) {
    Remove-Item -Force $jarPath
}

Write-Host "Creating $jarPath..."
& $jarExe --create --file $jarPath --manifest $manifestPath -C $runtimeDir .
if ($LASTEXITCODE -ne 0) {
    throw "jar packaging failed"
}

Write-Host "Built Burp extension jar at $jarPath"
