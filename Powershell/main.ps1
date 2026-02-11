# -- Import core modules --------------------------------------------------------
. "$PSScriptRoot\core\console.ps1"
. "$PSScriptRoot\core\types.ps1"
. "$PSScriptRoot\core\memory.ps1"

# -- Console setup --------------------------------------------------------------
Clear-Screen
Set-Title "read.write. | PowerShell"
Show-Banner

# -- Escalate privileges immediately on startup ---------------------------------
Warn "Obtaining maximum privileges..."
if (-not (Get-MaxPrivileges)) {
    Info "Could not obtain privileges. Run as Administrator."
    Read-Host
} else {
    Success "Obtained maximum privileges!"
}

# =============================================================================
# Demo - Notepad.exe
# =============================================================================
Start-Process "notepad.exe"
Start-Sleep -Seconds 1

$mem = [Memory]::new()
if (-not $mem.Attach("notepad.exe")) {
    Info "Could not attach. Make sure to run this script as Administrator."
    exit 1
}

$base = $mem.GetBaseAddress()

# -- Read demo (PE header) -----------------------------------------------------
Write-Host "`n --- READ demo (PE header) ---"

$mz = $mem.Read($base, "ushort")
$tag = if ($mz -eq 0x5A4D) { "$CHECK MZ" } else { $CROSS }
Info "DOS magic  ${pink}:${reset} 0x$('{0:x4}' -f $mz)  $tag"

$raw = $mem.Read($base, "bytes", 2)
Info "Raw bytes  ${pink}:${reset} $($raw -join ', ')"

$peOff = $mem.Read([IntPtr]($base.ToInt64() + 0x3C), "int")
Info "PE offset  ${pink}:${reset} 0x$('{0:x}' -f $peOff)"

$peSig = $mem.Read([IntPtr]($base.ToInt64() + $peOff), "uint")
$tag = if ($peSig -eq 0x4550) { "$CHECK PE" } else { $CROSS }
Info "PE sig     ${pink}:${reset} 0x$('{0:x4}' -f $peSig)  $tag"

# -- Write demo (allocated memory) ---------------------------------------------
Write-Host "`n --- WRITE demo (allocated memory) ---"

$alloc = $mem.Allocate(256)
Info "Allocated 256 bytes ${pink}@${reset} 0x$($alloc.ToString('x'))"

$mem.Write($alloc, 1337, "int") | Out-Null
Info "int     1337        ${pink}>${reset} $($mem.Read($alloc, 'int'))"

$mem.Write([IntPtr]($alloc.ToInt64() + 8), 3.14, "float") | Out-Null
Info "float   3.14        ${pink}>${reset} $("{0:F2}" -f $mem.Read([IntPtr]($alloc.ToInt64() + 8), 'float'))"

$mem.Write([IntPtr]($alloc.ToInt64() + 16), 2.718281828, "double") | Out-Null
Info "double  2.718..     ${pink}>${reset} $("{0:F9}" -f $mem.Read([IntPtr]($alloc.ToInt64() + 16), 'double'))"

$mem.Write([IntPtr]($alloc.ToInt64() + 32), 0xDEADBEEFCAFE, "longlong") | Out-Null
Info "int64   0xDEAD..    ${pink}>${reset} 0x$('{0:x}' -f $mem.Read([IntPtr]($alloc.ToInt64() + 32), 'longlong'))"

$mem.Write([IntPtr]($alloc.ToInt64() + 64), "Hello from PowerShell!", "str") | Out-Null
Info "string              ${pink}>${reset} '$($mem.Read([IntPtr]($alloc.ToInt64() + 64), 'str', 22))'"

$mem.Write([IntPtr]($alloc.ToInt64() + 128), [byte[]]@(0xDE, 0xAD, 0xBE, 0xEF), "bytes") | Out-Null
$readBytes = $mem.Read([IntPtr]($alloc.ToInt64() + 128), "bytes", 4)
$hex = [BitConverter]::ToString($readBytes).Replace('-','').ToLower()
Info "bytes               ${pink}>${reset} $hex"

$mem.Write([IntPtr]($alloc.ToInt64() + 140), $true, "bool") | Out-Null
Info "bool    True        ${pink}>${reset} $($mem.Read([IntPtr]($alloc.ToInt64() + 140), 'bool'))"

$mem.Free($alloc)
Warn "Freed allocated memory"

$mem.Detach()
Success "Demo complete."
