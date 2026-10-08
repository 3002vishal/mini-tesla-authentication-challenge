# Run from any directory: the script resolves paths relative to its own project folder.
param(
    [ValidateSet('demo', 'test')][string]$Mode = 'demo',
    [switch]$Verbose
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if ($Verbose -and $Mode -ne 'demo') { throw '-Verbose is supported in demo mode. Tests use assertions and run without tracing.' }
# Require an externally supplied key; never silently create a default encryption key.
if (-not $env:TESLA_MASTER_KEY) { throw 'Set TESLA_MASTER_KEY to a Base64-encoded 32-byte random key first (see README).' }
New-Item -ItemType Directory -Force target/classes | Out-Null
# Compile against the Java 17 API even when a newer JDK is installed.
$sources = @(Get-ChildItem src/main/java -Recurse -Filter *.java | ForEach-Object FullName)
& javac --release 17 -d target/classes $sources
if ($LASTEXITCODE -ne 0) { throw 'Compilation failed' }
if ($Mode -eq 'demo') {
    # Forward the switch to Java; normal demo output remains concise.
    $demoArguments = @()
    if ($Verbose) { $demoArguments += '--verbose' }
    & java -cp target/classes com.vyomic.tesla.Demo @demoArguments
} else {
    New-Item -ItemType Directory -Force .tools, target/test-classes | Out-Null
    $junit = '.tools/junit-platform-console-standalone-1.11.4.jar'
    # Cache the standalone test runner so subsequent runs do not need another download.
    if (-not (Test-Path $junit)) {
        Invoke-WebRequest 'https://repo.maven.apache.org/maven2/org/junit/platform/junit-platform-console-standalone/1.11.4/junit-platform-console-standalone-1.11.4.jar' -OutFile $junit
    }
    $tests = @(Get-ChildItem src/test/java -Recurse -Filter *.java | ForEach-Object FullName)
    & javac --release 17 -cp "target/classes;$junit" -d target/test-classes $tests
    if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed' }
    # Discover JUnit tests and report failure if no tests are found or any assertion fails.
    & java -jar $junit execute --class-path 'target/classes;target/test-classes' --scan-class-path --fail-if-no-tests
}
if ($LASTEXITCODE -ne 0) { throw 'Execution failed' }
