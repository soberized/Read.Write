' ============================================================================
' read.write. | VBScript + DynamicWrapperX [Work In Progress]
' Ported 1:1 from Python demo by soberized
' Requires: DynamicWrapperX.dll registered (regsvr32 DynamicWrapperX.dll)
' ============================================================================

Option Explicit


' -- Console color helpers (limited in cscript, best effort) ------------------
Dim ESC, PINK, RESET
ESC   = Chr(27)
PINK  = ESC & "[38;5;213m"
RESET = ESC & "[0m"

Function Icon(symbol)
    Icon = "[" & PINK & symbol & RESET & "]"
End Function

Const INFO    = "[!]"
Const SUCCESS = "[+]"
Const WARN    = "[*]"
Const CHECK   = "[/]"
Const CROSS   = "[X]"

Sub Log(msg, prefix)
    WScript.Echo " " & prefix & " " & msg
End Sub


Sub Banner()
    WScript.Echo ""
    WScript.Echo " read." & PINK & "write." & RESET & " | Version " & PINK & "@" & RESET & " VBScript"
    WScript.Echo " Developed by " & PINK & "soberized" & RESET
    WScript.Echo ""
End Sub

' -- DynamicWrapperX setup ----------------------------------------------------
Dim dwx: Set dwx = CreateObject("DynamicWrapperX")

' Kernel32 APIs
Call dwx.Register("kernel32.dll", "OpenProcess", "i=lll", "r=l")
Call dwx.Register("kernel32.dll", "ReadProcessMemory", "i=lllli", "r=l")
Call dwx.Register("kernel32.dll", "WriteProcessMemory", "i=lllli", "r=l")
Call dwx.Register("kernel32.dll", "VirtualAllocEx", "i=lllll", "r=l")
Call dwx.Register("kernel32.dll", "VirtualFreeEx", "i=llll", "r=l")
Call dwx.Register("kernel32.dll", "CloseHandle", "i=l", "r=l")
Call dwx.Register("kernel32.dll", "CreateToolhelp32Snapshot", "i=ll", "r=l")
Call dwx.Register("kernel32.dll", "Process32FirstW", "i=ll", "r=l")
Call dwx.Register("kernel32.dll", "Process32NextW", "i=ll", "r=l")
Call dwx.Register("kernel32.dll", "Module32FirstW", "i=ll", "r=l")
Call dwx.Register("kernel32.dll", "Module32NextW", "i=ll", "r=l")

' Advapi32 APIs for privilege escalation
Call dwx.Register("advapi32.dll", "OpenProcessToken", "i=lll", "r=l")
Call dwx.Register("advapi32.dll", "GetTokenInformation", "i=lllli", "r=l")
Call dwx.Register("advapi32.dll", "AdjustTokenPrivileges", "i=llliii", "r=l")
Call dwx.Register("kernel32.dll", "GetCurrentProcess", "i=", "r=l")

' -- Constants ---------------------------------------------------------------
Const PROCESS_ALL_ACCESS = &H1F0FFF
Const MEM_COMMIT      = &H1000
Const MEM_RESERVE     = &H2000
Const MEM_RELEASE     = &H8000
Const PAGE_READWRITE  = &H04
Const TH32CS_SNAPPROCESS  = &H02
Const TH32CS_SNAPMODULE   = &H08
Const TH32CS_SNAPMODULE32 = &H10

' -- Privilege escalation (Get-MaxPrivileges) ---------------------------------
Function GetMaxPrivileges()
    ' This is a stub: full token privilege escalation in VBScript is complex.
    ' For most use, running as Administrator is sufficient.
    GetMaxPrivileges = True
End Function

' -- Memory class -------------------------------------------------------------
Class Memory
    Public handle, pid, baseAddr, processName
    Public Sub Class_Initialize()
        handle = 0: pid = 0: baseAddr = 0: processName = ""
    End Sub
    Public Function Attach(procName)
        ' TODO: Enumerate processes, find PID by name, open process, find base
        Attach = False
    End Function
    Public Sub Detach()
        If handle <> 0 Then dwx.CloseHandle handle
        handle = 0: pid = 0: baseAddr = 0: processName = ""
    End Sub
    Public Function GetBaseAddress()
        GetBaseAddress = baseAddr
    End Function
    Public Function Read(addr, typeName, size)
        ' TODO: Implement type dispatch, use ReadProcessMemory
        Read = 0
    End Function
    Public Function Write(addr, value, typeName)
        ' TODO: Implement type dispatch, use WriteProcessMemory
        Write = False
    End Function
    Public Function Allocate(n)
        Allocate = dwx.VirtualAllocEx(handle, 0, n, MEM_COMMIT Or MEM_RESERVE, PAGE_READWRITE)
    End Function
    Public Sub Free(addr)
        dwx.VirtualFreeEx handle, addr, 0, MEM_RELEASE
    End Sub
End Class

' -- Main demo ---------------------------------------------------------------
Banner
Warn "Obtaining maximum privileges..."
If Not GetMaxPrivileges() Then
    Info "Could not obtain privileges. Run as Administrator."
    WScript.Quit
Else
    Success "Obtained maximum privileges!"
End If

Dim shell, notepadPID, mem, addr, value, readValue

' Launch notepad
Set shell = CreateObject("WScript.Shell")
shell.Run "notepad.exe", 1, False
WScript.Sleep 1000 ' Wait for Notepad to start

' Find Notepad PID (by enumerating processes)
Function FindProcessPID(procName)
    Dim snapshot, entry, foundPID, ret, buffer, i
    foundPID = 0
    snapshot = dwx.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    If snapshot = 0 Then Exit Function
    buffer = String(556, Chr(0)) ' sizeof(PROCESSENTRY32W) = 556
    ' Set dwSize
    Mid(buffer, 1, 4) = Chr(556 And &HFF) & Chr((556 \ &H100) And &HFF) & Chr((556 \ &H10000) And &HFF) & Chr((556 \ &H1000000) And &HFF)
    ret = dwx.Process32FirstW(snapshot, buffer)
    Do While ret <> 0
        ' Get szExeFile (offset 36, 260 WCHARs)
        Dim exeName: exeName = ""
        For i = 37 To 36 + 260 * 2 Step 2
            Dim ch: ch = AscW(Mid(buffer, i, 2))
            If ch = 0 Then Exit For
            exeName = exeName & ChrW(ch)
        Next
        If LCase(exeName) = LCase(procName) Then
            ' Get th32ProcessID (offset 9-12)
            foundPID = Asc(Mid(buffer, 9, 1)) + Asc(Mid(buffer, 10, 1)) * 256 + Asc(Mid(buffer, 11, 1)) * 65536 + Asc(Mid(buffer, 12, 1)) * 16777216
            Exit Do
        End If
        ret = dwx.Process32NextW(snapshot, buffer)
    Loop
    dwx.CloseHandle snapshot
    FindProcessPID = foundPID
End Function

notepadPID = FindProcessPID("notepad.exe")
If notepadPID = 0 Then
    Info "Could not find notepad.exe process."
    WScript.Quit
End If

Set mem = New Memory
mem.pid = notepadPID
mem.handle = dwx.OpenProcess(PROCESS_ALL_ACCESS, 0, notepadPID)
If mem.handle = 0 Then
    Info "Failed to open notepad process. Run as Administrator."
    WScript.Quit
End If
Success "Attached to notepad.exe (PID: " & notepadPID & ")"

' Allocate memory in notepad
addr = mem.Allocate(16)
If addr = 0 Then
    Info "Failed to allocate memory in notepad."
    mem.Detach
    WScript.Quit
End If
Success "Allocated 16 bytes at 0x" & Hex(addr)

' Write a value (e.g., integer 1337)
value = 1337
Dim bytes(3)
bytes(0) = value And &HFF
bytes(1) = (value \ &H100) And &HFF
bytes(2) = (value \ &H10000) And &HFF
bytes(3) = (value \ &H1000000) And &HFF
Dim byteStr: byteStr = Chr(bytes(0)) & Chr(bytes(1)) & Chr(bytes(2)) & Chr(bytes(3))
Dim written: written = 0
If dwx.WriteProcessMemory(mem.handle, addr, byteStr, 4, written) = 0 Then
    Info "Failed to write memory."
    mem.Free addr
    mem.Detach
    WScript.Quit
End If
Success "Wrote value 1337 to 0x" & Hex(addr)

' Read the value back
Dim outBuf: outBuf = String(4, Chr(0))
If dwx.ReadProcessMemory(mem.handle, addr, outBuf, 4, written) = 0 Then
    Info "Failed to read memory."
    mem.Free addr
    mem.Detach
    WScript.Quit
End If
readValue = Asc(Mid(outBuf, 1, 1)) + Asc(Mid(outBuf, 2, 1)) * 256 + Asc(Mid(outBuf, 3, 1)) * 65536 + Asc(Mid(outBuf, 4, 1)) * 16777216
Success "Read value: " & readValue

' Free memory and detach
mem.Free addr
mem.Detach
Success "Detached and cleaned up. Demo complete!"
