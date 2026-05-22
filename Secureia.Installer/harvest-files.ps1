param(
    [Parameter(Mandatory)]
    [string]$PublishDir,
    [Parameter(Mandatory)]
    [string]$OutputPath
)

$outputDir = Split-Path $OutputPath -Parent
if (!(Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }

# Normalize paths to full paths
$PublishDir = [System.IO.Path]::GetFullPath($PublishDir.TrimEnd('\'))

$files = Get-ChildItem -LiteralPath $PublishDir -Recurse -File | Where-Object {
    $_.Extension -ne ".pdb" -and $_.Extension -ne ".nupkg"
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
[void]$sb.AppendLine('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">')
[void]$sb.AppendLine('  <Fragment>')
[void]$sb.AppendLine('    <ComponentGroup Id="PublishedFiles" Directory="INSTALLFOLDER">')

$componentId = 0
foreach ($file in $files) {
    $fullPath = $file.FullName
    # Manual relative path calculation for PS 5.1
    if ($fullPath.StartsWith($PublishDir, [StringComparison]::OrdinalIgnoreCase)) {
        $relativePath = $fullPath.Substring($PublishDir.Length + 1)
    } else {
        $relativePath = $file.Name
    }

    $componentIdStr = "cmp_$componentId"
    $fileId = "fil_$componentId"

    $backslashIdx = $relativePath.IndexOf('\')
    if ($backslashIdx -ge 0) {
        $dirPart = [System.IO.Path]::GetDirectoryName($relativePath)
        [void]$sb.AppendLine("      <Component Id=`"$componentIdStr`" Guid=`"*`" Subdirectory=`"$dirPart`">")
    } else {
        [void]$sb.AppendLine("      <Component Id=`"$componentIdStr`" Guid=`"*`">")
    }
    [void]$sb.AppendLine("        <File Id=`"$fileId`" Source=`"$relativePath`" />")
    [void]$sb.AppendLine('      </Component>')
    $componentId++
}

[void]$sb.AppendLine('    </ComponentGroup>')
[void]$sb.AppendLine('  </Fragment>')
[void]$sb.AppendLine('</Wix>')

$sb.ToString() | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "Generated $componentId file entries in $OutputPath"
