# ---------------------------------------------------------------------------
# Privilege escalation
# ---------------------------------------------------------------------------

function Get-MaxPrivileges {
    try {
        $hProc = [System.Diagnostics.Process]::GetCurrentProcess().Handle
        $hToken = [IntPtr]::Zero

        if (-not [Advapi32]::OpenProcessToken($hProc, [Advapi32]::TOKEN_ADJUST_PRIVILEGES -bor [Advapi32]::TOKEN_QUERY, [ref]$hToken)) {
            return $false
        }

        # First call - get required buffer size (TokenPrivileges = 3)
        $needed = 0
        $null = [Advapi32]::GetTokenInformation($hToken, 3, [IntPtr]::Zero, 0, [ref]$needed)

        # Second call - fill buffer
        $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($needed)
        try {
            if (-not [Advapi32]::GetTokenInformation($hToken, 3, $buffer, $needed, [ref]$needed)) {
                return $false
            }

            # Parse: first 4 bytes = PrivilegeCount, then array of LUID_AND_ATTRIBUTES (12 bytes each)
            $count = [System.Runtime.InteropServices.Marshal]::ReadInt32($buffer, 0)

            # Build new TOKEN_PRIVILEGES with all privileges enabled
            $singleLuidSize = 12  # sizeof(LUID_AND_ATTRIBUTES)
            $newSize = 4 + ($count * $singleLuidSize)
            $newBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($newSize)
            try {
                [System.Runtime.InteropServices.Marshal]::WriteInt32($newBuffer, 0, $count)

                for ($i = 0; $i -lt $count; $i++) {
                    $srcOffset = 4 + ($i * $singleLuidSize)
                    $dstOffset = 4 + ($i * $singleLuidSize)

                    # Copy LUID (8 bytes)
                    $luidLow  = [System.Runtime.InteropServices.Marshal]::ReadInt32($buffer, $srcOffset)
                    $luidHigh = [System.Runtime.InteropServices.Marshal]::ReadInt32($buffer, $srcOffset + 4)

                    [System.Runtime.InteropServices.Marshal]::WriteInt32($newBuffer, $dstOffset, $luidLow)
                    [System.Runtime.InteropServices.Marshal]::WriteInt32($newBuffer, $dstOffset + 4, $luidHigh)
                    # Set SE_PRIVILEGE_ENABLED
                    [System.Runtime.InteropServices.Marshal]::WriteInt32($newBuffer, $dstOffset + 8, [Advapi32]::SE_PRIVILEGE_ENABLED)
                }

                $null = [Advapi32]::AdjustTokenPrivileges($hToken, $false, $newBuffer, 0, [IntPtr]::Zero, [IntPtr]::Zero)
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($newBuffer)
            }
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        }

        [Kernel32]::CloseHandle($hToken) | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------

function Get-Processes {
    $snapshot = [Kernel32]::CreateToolhelp32Snapshot([Kernel32]::TH32CS_SNAPPROCESS, 0)
    if ($snapshot -eq [IntPtr]::new(-1)) { return @() }

    $entry = New-Object Kernel32+PROCESSENTRY32W
    $entry.dwSize = [System.Runtime.InteropServices.Marshal]::SizeOf($entry)
    $result = @()

    if ([Kernel32]::Process32FirstW($snapshot, [ref]$entry)) {
        do {
            $result += [PSCustomObject]@{
                Name      = $entry.szExeFile
                Pid       = $entry.th32ProcessID
                Threads   = $entry.cntThreads
            }
        } while ([Kernel32]::Process32NextW($snapshot, [ref]$entry))
    }

    [Kernel32]::CloseHandle($snapshot) | Out-Null
    return $result
}

# ---------------------------------------------------------------------------
# Memory class
# ---------------------------------------------------------------------------

class Memory {
    [IntPtr]  $Handle
    [uint32]  $Pid
    [IntPtr]  $BaseAddr
    [string]  $ProcessName

    Memory() {
        $this.Handle      = [IntPtr]::Zero
        $this.Pid         = 0
        $this.BaseAddr    = [IntPtr]::Zero
        $this.ProcessName = $null
    }

    # -- attach / detach ----------------------------------------------------

    [bool] Attach([string]$processName) {
        $procs = Get-Processes
        foreach ($proc in $procs) {
            if ($proc.Name -eq $processName) {
                $this.Pid = $proc.Pid
                $this.Handle = [Kernel32]::OpenProcess([Kernel32]::PROCESS_ALL_ACCESS, $false, $this.Pid)
                if ($this.Handle -eq [IntPtr]::Zero) { return $false }

                $this.ProcessName = $processName
                $this.BaseAddr = $this.FindModuleBase($processName)

                Write-Host " [$script:pink+$script:reset] Attached to '$processName' (PID $($this.Pid))"
                if ($this.BaseAddr -ne [IntPtr]::Zero) {
                    Write-Host " [$script:pink+$script:reset] Base address: 0x$($this.BaseAddr.ToString('x'))"
                }
                return $true
            }
        }
        Write-Host " [$script:pink!$script:reset] Process '$processName' not found."
        return $false
    }

    [void] Detach() {
        if ($this.Handle -ne [IntPtr]::Zero) {
            $null = [Kernel32]::CloseHandle($this.Handle)
        }
        Write-Host " [$script:pink+$script:reset] Detached from '$($this.ProcessName)' (PID $($this.Pid))"
        $this.Handle      = [IntPtr]::Zero
        $this.Pid         = 0
        $this.BaseAddr    = [IntPtr]::Zero
        $this.ProcessName = $null
    }

    [IntPtr] GetBaseAddress() {
        return $this.BaseAddr
    }

    # -- read ---------------------------------------------------------------

    [object] Read([IntPtr]$address, [string]$typeName) {
        return $this.Read($address, $typeName, 0)
    }

    [object] Read([IntPtr]$address, [string]$typeName, [int]$size) {
        $bytesRead = 0

        switch ($typeName) {
            "bytes" {
                $buf = New-Object byte[] $size
                $null = [Kernel32]::ReadProcessMemory($this.Handle, $address, $buf, $size, [ref]$bytesRead)
                return $buf
            }
            "str" {
                if ($size -eq 0) { $size = 50 }
                $buf = New-Object byte[] $size
                $null = [Kernel32]::ReadProcessMemory($this.Handle, $address, $buf, $size, [ref]$bytesRead)
                $end = [Array]::IndexOf($buf, [byte]0)
                if ($end -lt 0) { $end = $size }
                return [System.Text.Encoding]::UTF8.GetString($buf, 0, $end)
            }
            "ptr" {
                $buf = New-Object byte[] 8
                $null = [Kernel32]::ReadProcessMemory($this.Handle, $address, $buf, 8, [ref]$bytesRead)
                return [IntPtr][BitConverter]::ToInt64($buf, 0)
            }
            default {
                $typeInfo = [Memory]::GetTypeInfo($typeName)
                $buf = New-Object byte[] $typeInfo.Size
                $null = [Kernel32]::ReadProcessMemory($this.Handle, $address, $buf, $typeInfo.Size, [ref]$bytesRead)
                return $typeInfo.FromBytes.InvokeReturnAsIs($buf)
            }
        }
        return $null
    }

    # -- write --------------------------------------------------------------

    [bool] Write([IntPtr]$address, [object]$value, [string]$typeName) {
        $bytesWritten = 0

        try {
            switch ($typeName) {
                "bytes" {
                    [byte[]]$data = $value
                    $null = [Kernel32]::WriteProcessMemory($this.Handle, $address, $data, $data.Length, [ref]$bytesWritten)
                    return $true
                }
                "str" {
                    [byte[]]$data = [System.Text.Encoding]::UTF8.GetBytes([string]$value + [char]0)
                    $null = [Kernel32]::WriteProcessMemory($this.Handle, $address, $data, $data.Length, [ref]$bytesWritten)
                    return $true
                }
                "ptr" {
                    [byte[]]$data = [BitConverter]::GetBytes([long]$value)
                    $null = [Kernel32]::WriteProcessMemory($this.Handle, $address, $data, 8, [ref]$bytesWritten)
                    return $true
                }
                default {
                    $typeInfo = [Memory]::GetTypeInfo($typeName)
                    [byte[]]$data = $typeInfo.ToBytes.InvokeReturnAsIs($value)
                    $null = [Kernel32]::WriteProcessMemory($this.Handle, $address, $data, $typeInfo.Size, [ref]$bytesWritten)
                    return $true
                }
            }
        }
        catch {
            return $false
        }
        return $false
    }

    # -- allocation ---------------------------------------------------------

    [IntPtr] Allocate([uint32]$size) {
        return [Kernel32]::VirtualAllocEx(
            $this.Handle, [IntPtr]::Zero, $size,
            [Kernel32]::MEM_COMMIT -bor [Kernel32]::MEM_RESERVE,
            [Kernel32]::PAGE_READWRITE
        )
    }

    [void] Free([IntPtr]$address) {
        $null = [Kernel32]::VirtualFreeEx($this.Handle, $address, 0, [Kernel32]::MEM_RELEASE)
    }

    # -- type map -----------------------------------------------------------

    static [hashtable] GetTypeInfo([string]$typeName) {
        $map = @{
            "int"       = @{ Size = 4; FromBytes = { param($b) [BitConverter]::ToInt32($b, 0) };       ToBytes = { param($v) [BitConverter]::GetBytes([int32]$v) } }
            "int32"     = @{ Size = 4; FromBytes = { param($b) [BitConverter]::ToInt32($b, 0) };       ToBytes = { param($v) [BitConverter]::GetBytes([int32]$v) } }
            "uint"      = @{ Size = 4; FromBytes = { param($b) [BitConverter]::ToUInt32($b, 0) };      ToBytes = { param($v) [BitConverter]::GetBytes([uint32]$v) } }
            "uint32"    = @{ Size = 4; FromBytes = { param($b) [BitConverter]::ToUInt32($b, 0) };      ToBytes = { param($v) [BitConverter]::GetBytes([uint32]$v) } }
            "short"     = @{ Size = 2; FromBytes = { param($b) [BitConverter]::ToInt16($b, 0) };       ToBytes = { param($v) [BitConverter]::GetBytes([int16]$v) } }
            "int16"     = @{ Size = 2; FromBytes = { param($b) [BitConverter]::ToInt16($b, 0) };       ToBytes = { param($v) [BitConverter]::GetBytes([int16]$v) } }
            "ushort"    = @{ Size = 2; FromBytes = { param($b) [BitConverter]::ToUInt16($b, 0) };      ToBytes = { param($v) [BitConverter]::GetBytes([uint16]$v) } }
            "uint16"    = @{ Size = 2; FromBytes = { param($b) [BitConverter]::ToUInt16($b, 0) };      ToBytes = { param($v) [BitConverter]::GetBytes([uint16]$v) } }
            "long"      = @{ Size = 4; FromBytes = { param($b) [BitConverter]::ToInt32($b, 0) };       ToBytes = { param($v) [BitConverter]::GetBytes([int32]$v) } }
            "longlong"  = @{ Size = 8; FromBytes = { param($b) [BitConverter]::ToInt64($b, 0) };       ToBytes = { param($v) [BitConverter]::GetBytes([int64]$v) } }
            "int64"     = @{ Size = 8; FromBytes = { param($b) [BitConverter]::ToInt64($b, 0) };       ToBytes = { param($v) [BitConverter]::GetBytes([int64]$v) } }
            "ulong"     = @{ Size = 4; FromBytes = { param($b) [BitConverter]::ToUInt32($b, 0) };      ToBytes = { param($v) [BitConverter]::GetBytes([uint32]$v) } }
            "ulonglong" = @{ Size = 8; FromBytes = { param($b) [BitConverter]::ToUInt64($b, 0) };      ToBytes = { param($v) [BitConverter]::GetBytes([uint64]$v) } }
            "uint64"    = @{ Size = 8; FromBytes = { param($b) [BitConverter]::ToUInt64($b, 0) };      ToBytes = { param($v) [BitConverter]::GetBytes([uint64]$v) } }
            "float"     = @{ Size = 4; FromBytes = { param($b) [BitConverter]::ToSingle($b, 0) };      ToBytes = { param($v) [BitConverter]::GetBytes([float]$v) } }
            "double"    = @{ Size = 8; FromBytes = { param($b) [BitConverter]::ToDouble($b, 0) };      ToBytes = { param($v) [BitConverter]::GetBytes([double]$v) } }
            "bool"      = @{ Size = 1; FromBytes = { param($b) [BitConverter]::ToBoolean($b, 0) };     ToBytes = { param($v) [BitConverter]::GetBytes([bool]$v) } }
            "char"      = @{ Size = 1; FromBytes = { param($b) [char]$b[0] };                          ToBytes = { param($v) [byte[]]@([byte][char]$v) } }
            "uchar"     = @{ Size = 1; FromBytes = { param($b) $b[0] };                                ToBytes = { param($v) [byte[]]@([byte]$v) } }
        }

        $info = $map[$typeName]
        if ($null -eq $info) {
            throw "Unknown type '$typeName'. Valid: $($map.Keys -join ', '), bytes, str, ptr"
        }
        return $info
    }

    # -- internal helpers ---------------------------------------------------

    hidden [IntPtr] FindModuleBase([string]$name) {
        $snapshot = [Kernel32]::CreateToolhelp32Snapshot(
            [Kernel32]::TH32CS_SNAPMODULE -bor [Kernel32]::TH32CS_SNAPMODULE32,
            $this.Pid
        )
        if ($snapshot -eq [IntPtr]::new(-1)) { return [IntPtr]::Zero }

        $entry = New-Object Kernel32+MODULEENTRY32W
        $entry.dwSize = [System.Runtime.InteropServices.Marshal]::SizeOf($entry)

        if ([Kernel32]::Module32FirstW($snapshot, [ref]$entry)) {
            do {
                if ($entry.szModule -eq $name) {
                    $base = $entry.modBaseAddr
                    $null = [Kernel32]::CloseHandle($snapshot)
                    return $base
                }
            } while ([Kernel32]::Module32NextW($snapshot, [ref]$entry))
        }

        $null = [Kernel32]::CloseHandle($snapshot)
        return [IntPtr]::Zero
    }
}
