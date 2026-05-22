$ErrorActionPreference = "Stop"
$projectRoot = "C:\Users\turbo\Desktop\secureia"
$publishDir = "$projectRoot\publish"
$installerDir = "$projectRoot\Secureia.Installer"

Write-Host "=== Step 1: Restore project ===" -ForegroundColor Cyan
& "C:\Program Files\dotnet\dotnet.exe" restore "$projectRoot\Secureia\Secureia.csproj"
if (-not $?) { throw "Secureia restore failed" }

Write-Host "=== Step 2: Publish Secureia (self-contained) ===" -ForegroundColor Cyan
Remove-Item -LiteralPath $publishDir -Recurse -Force -ErrorAction SilentlyContinue
& "C:\Program Files\dotnet\dotnet.exe" publish "$projectRoot\Secureia\Secureia.csproj" `
    -c Release -r win-x64 --self-contained true -o $publishDir
if (-not $?) { throw "Secureia publish failed" }

# Copy installer assets to publish directory
Copy-Item -LiteralPath "$projectRoot\logo.png" -Destination "$publishDir\logo.png" -Force
Copy-Item -LiteralPath "$installerDir\license.rtf" -Destination "$publishDir\license.rtf" -Force

Write-Host "=== Step 4: Harvest files ===" -ForegroundColor Cyan
& "$installerDir\harvest-files.ps1" -PublishDir $publishDir -OutputPath "$installerDir\Files.wxs"
if (-not $?) { throw "Harvest failed" }

$msiPath = "$projectRoot\SecureAI-1.0.0.msi"
Remove-Item -LiteralPath $msiPath -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$env:TEMP\SecureAI-1.0.0.msi" -Force -ErrorAction SilentlyContinue

Write-Host "=== Step 5: Build MSI ===" -ForegroundColor Cyan
& "$env:USERPROFILE\.dotnet\tools\wix.exe" build -o "$env:TEMP\SecureAI-1.0.0.msi" "$installerDir\Product.wxs" "$installerDir\Files.wxs" -b "$publishDir" -ext "$projectRoot\.wix\extensions\WixToolset.UI.wixext\7.0.0\wixext7\WixToolset.UI.wixext.dll" -ext "$projectRoot\.wix\extensions\WixToolset.NetFx.wixext\7.0.0\wixext7\WixToolset.Netfx.wixext.dll"
if (-not $?) { throw "Wix build failed" }

Copy-Item -LiteralPath "$env:TEMP\SecureAI-1.0.0.msi" -Destination $msiPath -Force

Write-Host "=== Done! MSI created at $msiPath ===" -ForegroundColor Green
