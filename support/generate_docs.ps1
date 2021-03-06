$supportPath = Split-Path $SCRIPT:MyInvocation.MyCommand.Path -Parent
$repoPath = Split-Path $supportPath -Parent

$generatedDocPath = Join-Path -Path (Join-Path -Path $repoPath -ChildPath "target") -ChildPath "doc"
$docPath = Join-Path -Path $repoPath -ChildPath "docs"

Write-Host "Generating Rust documentation for windows-acl..." -ForegroundColor Yellow
$null = cargo doc --no-deps

If (Test-Path -Type Container $generatedDocPath -ErrorAction SilentlyContinue) {
    Write-Host "Copying docs to $docPath"
    Get-ChildItem $generatedDocPath | Copy-Item -Destination $docPath -Recurse -ErrorAction SilentlyContinue
    Write-Host "Done" -ForegroundColor Green
} Else {
    Write-Host "Failed to generate documention!" -ForegroundColor Red
}