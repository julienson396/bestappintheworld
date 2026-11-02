#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Усиленная защита ScreenConnect (v2.3).
  ВНИМАНИЕ: "невозможность удаления от SYSTEM" недостижима в user-mode.
  Скрипт делает снятие защиты дорогим, шумным и авто-восстанавливаемым.
  Полный откат: Unprotect-ScreenConnect.ps1 -Id <id>

  Изменения v2.3:
    - Три задачи SYSTEM: monitor, watch, guard (сторож сторожа).
    - Deny-DACL на процесс службы: PROCESS_TERMINATE / SUSPEND_RESUME /
      SET_INFORMATION / SET_QUOTA / WRITE_DAC / WRITE_OWNER для
      BUILTIN\Administrators и BUILTIN\Users. SYSTEM — полный доступ.
    - DACL на процессы monitor/watch/guard — их тоже нельзя убить через taskmgr.
    - Три WMI-подписки в root\subscription:
        8a. Schedule modification   → пересоздаёт задачу SCProtect_<Id>
        8b. ProcessStop monitor_<Id> → Start-ScheduledTask SCProtect_<Id>
        8c. ProcessStop watch_<Id>   → Start-ScheduledTask SCProtectWatch_<Id>
    - Диспетчер задач НЕ блокируется (taskmgr.exe исключён из IFEO).
#>

param(
    [string]$Id = "8a4733bc8e95601f"
)

$ErrorActionPreference = "Stop"

$serviceName  = "ScreenConnect Client ($Id)"
$serviceKey   = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$protectDir   = Join-Path $env:ProgramData "SCProtect_$Id"
$backupDir    = Join-Path $env:ProgramData "SCProtect_Backup"
$backupFile   = Join-Path $backupDir "backup_$Id.json"
$logFile      = Join-Path $protectDir "protect.log"

$taskMain     = "SCProtect_$Id"
$taskWatch    = "SCProtectWatch_$Id"
$taskGuard    = "SCProtectGuard_$Id"

$wmiFilterS   = "SCProtectFilterS_$Id"
$wmiConsumerS = "SCProtectConsumerS_$Id"
$wmiFilterM   = "SCProtectFilterM_$Id"
$wmiConsumerM = "SCProtectConsumerM_$Id"
$wmiFilterW   = "SCProtectFilterW_$Id"
$wmiConsumerW = "SCProtectConsumerW_$Id"

$targetFolders = @(
    "C:\Program Files\ScreenConnect Client ($Id)",
    "C:\Program Files (x86)\ScreenConnect Client ($Id)",
    "C:\ProgramData\ScreenConnect Client ($Id)"
)

# Путь к модулю защиты процесса (общий для всех трёх задач)
$procGuardPath = Join-Path $protectDir "ProcessGuard.ps1"

# ---------- Лог ----------
New-Item -ItemType Directory -Path $protectDir -Force | Out-Null
New-Item -ItemType Directory -Path $backupDir  -Force | Out-Null

function Write-Log([string]$msg, [string]$color = "Gray") {
    $line = "$(Get-Date -Format s)  $msg"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Write-Host $msg -ForegroundColor $color
}

# ---------- Проверка службы ----------
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Log "Служба '$serviceName' не найдена. Проверьте ID." "Red"
    return
}

# ==============================================================================
# Модуль защиты процесса (P/Invoke SetSecurityInfo, ручная сборка ACL)
# Работает и в Windows PowerShell 5.1, и в PowerShell 7+ (.NET Core).
# ==============================================================================
$procGuardSource = @'
# ProcessGuard.ps1 — применяет Deny-DACL к процессу, чтобы нельзя было убить
# через taskmgr.exe / Stop-Process / TerminateProcess от Administrators.
# SYSTEM сохраняет полный доступ.

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class ProcAcl
{
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(
        IntPtr handle,
        int ObjectType,
        uint SecurityInfo,
        IntPtr psidOwner,
        IntPtr psidGroup,
        IntPtr pDacl,
        IntPtr pSacl);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    const int SE_KERNEL_OBJECT = 6;
    const uint DACL_SECURITY_INFORMATION = 0x00000004;
    const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

    const byte ACCESS_ALLOWED_ACE_TYPE = 0x00;
    const byte ACCESS_DENIED_ACE_TYPE  = 0x01;

    private static IntPtr BuildDacl(
        out int aclSize,
        uint sysMask,
        uint baMask,
        string[] denySids,
        uint denyMask)
    {
        var aceBytes = new List<byte[]>();

        aceBytes.Add(BuildAce(ACCESS_ALLOWED_ACE_TYPE, sysMask,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)));
        aceBytes.Add(BuildAce(ACCESS_ALLOWED_ACE_TYPE, baMask,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)));
        foreach (var s in denySids)
        {
            var sid = new SecurityIdentifier(s);
            aceBytes.Add(BuildAce(ACCESS_DENIED_ACE_TYPE, denyMask, sid));
        }

        int total = 8;
        foreach (var a in aceBytes) total += a.Length;

        IntPtr buf = Marshal.AllocHGlobal(total);
        int off = 0;

        Marshal.WriteByte(buf, off + 0, 2);
        Marshal.WriteByte(buf, off + 1, 0);
        Marshal.WriteInt16(buf, off + 2, (short)total);
        Marshal.WriteInt16(buf, off + 4, (short)aceBytes.Count);
        Marshal.WriteInt16(buf, off + 6, 0);
        off += 8;

        foreach (var a in aceBytes)
        {
            Marshal.Copy(a, 0, new IntPtr(buf.ToInt64() + off), a.Length);
            off += a.Length;
        }

        aclSize = total;
        return buf;
    }

    private static byte[] BuildAce(byte type, uint mask, SecurityIdentifier sid)
    {
        byte[] sidBytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(sidBytes, 0);

        int size = 4 + 4 + sidBytes.Length;
        byte[] ace = new byte[size];
        ace[0] = type;
        ace[1] = 0;
        ace[2] = (byte)(size & 0xFF);
        ace[3] = (byte)((size >> 8) & 0xFF);
        BitConverter.GetBytes(mask).CopyTo(ace, 4);
        Array.Copy(sidBytes, 0, ace, 8, sidBytes.Length);
        return ace;
    }

    public static void ApplyDeny(int pid, string[] denySids, uint denyMask)
    {
        IntPtr h = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (h == IntPtr.Zero)
            throw new Exception("OpenProcess failed: " + Marshal.GetLastWin32Error());

        IntPtr pDacl = IntPtr.Zero;
        try
        {
            uint sysMask = 0x1F0FFF;
            uint baMask  = 0x0400 | 0x1000 | 0x20000 | 0x100000;

            int aclSize;
            pDacl = BuildDacl(out aclSize, sysMask, baMask, denySids, denyMask);

            uint r = SetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                                      IntPtr.Zero, IntPtr.Zero, pDacl, IntPtr.Zero);
            if (r != 0)
                throw new Exception("SetSecurityInfo failed: " + r);
        }
        finally
        {
            if (pDacl != IntPtr.Zero) Marshal.FreeHGlobal(pDacl);
            CloseHandle(h);
        }
    }
}
"@

#   PROCESS_TERMINATE        = 0x0001
#   PROCESS_SET_QUOTA        = 0x0100
#   PROCESS_SET_INFORMATION  = 0x0200
#   PROCESS_SUSPEND_RESUME   = 0x0800
#   WRITE_DAC                = 0x00040000
#   WRITE_OWNER              = 0x00080000
$denyMask = 0x0001 -bor 0x0100 -bor 0x0200 -bor 0x0800 -bor 0x00040000 -bor 0x00080000

$adminSidStr = (New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)).Value
$usersSidStr = (New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)).Value

$denySids = @($adminSidStr, $usersSidStr)

function Protect-TargetProcesses {
    param([string]$ServiceName)
    $procs = @()
    try {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($svc -and $svc.ProcessId -gt 0) {
            $procs += Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue
        }
    } catch {}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        try {
            if ($p.Path -and ($targetFolders | Where-Object { $p.Path -like "$_*" })) {
                $procs += $p
            }
        } catch {}
    }
    $procs = $procs | Sort-Object Id -Unique
    foreach ($p in $procs) {
        try {
            [ProcAcl]::ApplyDeny($p.Id, $denySids, $denyMask)
        } catch {}
    }
    return $procs
}
'@

$procGuardSource | Set-Content -Path $procGuardPath -Encoding UTF8
. $procGuardPath

# ==============================================================================
# Бэкап
# ==============================================================================
$backup = @{
    Id            = $Id
    ServiceName   = $serviceName
    ServiceSddl   = $null
    ServiceKeyAcl = $null
    FolderAcls    = @{}
    ImagePath     = $null
    Timestamp     = (Get-Date).ToString("o")
}

$backup.ServiceSddl = ((& sc.exe sdshow "$serviceName") -join "`n" -split "`n" |
    Where-Object { $_ -match '^D:' }) -join ''

$backup.ServiceKeyAcl = (Get-Acl $serviceKey).Sddl
$backup.ImagePath     = (Get-ItemProperty $serviceKey -Name ImagePath).ImagePath

foreach ($p in $targetFolders) {
    if (Test-Path $p) { $backup.FolderAcls[$p] = (Get-Acl $p).Sddl }
}

$backup | ConvertTo-Json -Depth 5 | Set-Content -Path $backupFile -Encoding UTF8
Write-Log "Бэкап: $backupFile" "DarkGray"

# ==============================================================================
# 1. SDDL службы
# ==============================================================================
Write-Log "[1/8] Защита службы (SDDL)..." "Cyan"

$sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)"

& sc.exe sdset "$serviceName" "$sddl" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Log "  sc sdset вернул $LASTEXITCODE — служба НЕ защищена" "Yellow"
} else {
    Write-Log "  Служба защищена." "Green"
}

# ==============================================================================
# 2. Deny ACL на ключ реестра службы
# ==============================================================================
Write-Log "[2/8] Защита ключа реестра..." "Cyan"

$adminSid = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

try {
    $keyAcl = Get-Acl $serviceKey
    $denyKey = New-Object System.Security.AccessControl.RegistryAccessRule(
        $adminSid,
        "Delete, SetValue, CreateSubKey, ChangePermissions, TakeOwnership",
        "ContainerInherit",
        "None",
        "Deny")
    $keyAcl.AddAccessRule($denyKey)
    Set-Acl -Path $serviceKey -AclObject $keyAcl
    Write-Log "  Ключ реестра защищён." "Green"
} catch {
    Write-Log "  Ошибка защиты ключа: $_" "Yellow"
}

# ==============================================================================
# 3. Deny ACL на папки
# ==============================================================================
Write-Log "[3/8] Защита папок..." "Cyan"

foreach ($path in $targetFolders) {
    if (-not (Test-Path $path)) { continue }
    try {
        $acl = Get-Acl $path
        $rules = @(
            @{ Rights = "Delete, DeleteSubdirectoriesAndFiles"; Inherit = "ContainerInherit, ObjectInherit" },
            @{ Rights = "ChangePermissions, TakeOwnership";     Inherit = "ContainerInherit, ObjectInherit" },
            @{ Rights = "WriteData, AppendData";                Inherit = "ContainerInherit, ObjectInherit" }
        )
        foreach ($r in $rules) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $adminSid, $r.Rights, $r.Inherit, "None", "Deny")
            $acl.AddAccessRule($rule)
        }
        Set-Acl -Path $path -AclObject $acl
        Write-Log "  Заблокировано: $path" "Green"
    } catch {
        Write-Log "  Ошибка ACL $path : $_" "Yellow"
    }
}

foreach ($path in @($protectDir, $backupDir)) {
    try {
        $acl = Get-Acl $path
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adminSid, "Delete, DeleteSubdirectoriesAndFiles", "ContainerInherit, ObjectInherit", "None", "Deny")
        $acl.AddAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl
    } catch {}
}

# ==============================================================================
# 4. IFEO: перехват утилит (taskmgr.exe исключён!)
# ==============================================================================
Write-Log "[4/8] IFEO-перехват утилит..." "Cyan"

$ifeoBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
$ifeoTargets = @("sc.exe", "reg.exe", "taskkill.exe", "services.msc", "mmc.exe", "procexp.exe", "procexp64.exe", "psexec.exe", "psexec64.exe")

foreach ($t in $ifeoTargets) {
    $k = Join-Path $ifeoBase $t
    try {
        if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
        $stub = Join-Path $protectDir "block_stub.cmd"
        if (-not (Test-Path $stub)) {
            "@echo off`r`necho Blocked by SCProtect >> `"$logFile`"`r`nexit /b 1" |
                Set-Content -Path $stub -Encoding ASCII
        }
        Set-ItemProperty -Path $k -Name "Debugger" -Value "`"$stub`"" -Type String
    } catch {
        Write-Log "  IFEO $t : $_" "Yellow"
    }
}
Write-Log "  IFEO-перехват активен (taskmgr.exe НЕ блокируется)." "Green"

# ==============================================================================
# 5. Защита процесса службы (DACL на процесс)
# ==============================================================================
Write-Log "[5/8] Защита процесса службы (Deny TerminateProcess)..." "Cyan"

$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc.Status -ne 'Running') {
    try { Start-Service -Name $serviceName } catch {}
    Start-Sleep -Milliseconds 800
}

$protected = Protect-TargetProcesses -ServiceName $serviceName
if ($protected.Count -gt 0) {
    Write-Log "  Защищено процессов службы: $($protected.Count) (PIDs: $($protected.Id -join ', '))" "Green"
} else {
    Write-Log "  Не удалось найти процесс службы — монитор попробует позже." "Yellow"
}

# ==============================================================================
# 6. Монитор-задача (monitor_<Id>.ps1)
# ==============================================================================
Write-Log "[6/8] Мониторинг-задача..." "Cyan"

# Корректный литерал массива путей для монитора
$tfLiteral = ($targetFolders | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ","

$monitorScript = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$log      = '$logFile'
`$svcName  = '$serviceName'
`$svcKey   = '$serviceKey'
`$id       = '$Id'
`$adminSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, `$null)
`$targetFolders = @($tfLiteral)

Add-Content `$log "`$(Get-Date -f s)  [MON] started, PID=`$PID"

. '$procGuardPath'

function Log(`$m) { Add-Content `$log "`$(Get-Date -f s)  [MON] `$m" }

while (`$true) {
    `$s = Get-Service -Name `$svcName
    if (`$s.Status -ne 'Running') {
        Start-Service -Name `$svcName
        Log 'service restarted'
    }

    `$cur = ((& sc.exe sdshow `$svcName) -join "`n" -split "`n" | Where-Object { `$_ -match '^D:' }) -join ''
    if (`$cur -notmatch 'CCLCSWLOCRRC;;;BA' -or `$cur -match 'CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA') {
        & sc.exe sdset `$svcName 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)' | Out-Null
        Log 'SDDL re-applied'
    }

    `$k = Get-Acl `$svcKey
    `$hasDeny = `$k.Access | Where-Object { `$_.IdentityReference -eq `$adminSid -and `$_.AccessControlType -eq 'Deny' }
    if (-not `$hasDeny) {
        try {
            `$rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                `$adminSid, 'Delete, SetValue, CreateSubKey, ChangePermissions, TakeOwnership',
                'ContainerInherit', 'None', 'Deny')
            `$k.AddAccessRule(`$rule)
            Set-Acl -Path `$svcKey -AclObject `$k
            Log 'registry deny re-applied'
        } catch { Log "registry deny failed: `$_" }
    }

    `$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach (`$t in @('sc.exe','reg.exe','taskkill.exe','services.msc','mmc.exe','procexp.exe','procexp64.exe','psexec.exe','psexec64.exe')) {
        `$k2 = Join-Path `$ifeo `$t
        `$stub = Join-Path '$protectDir' 'block_stub.cmd'
        if (-not (Test-Path `$k2) -or (Get-ItemProperty `$k2 -Name Debugger -ErrorAction SilentlyContinue).Debugger -ne "```"`$stub```"") {
            if (-not (Test-Path `$k2)) { New-Item `$k2 -Force | Out-Null }
            Set-ItemProperty -Path `$k2 -Name Debugger -Value "```"`$stub```"" -Type String
            Log "IFEO `$t re-applied"
        }
    }

    try {
        `$p = Protect-TargetProcesses -ServiceName `$svcName
        if (`$p.Count -gt 0) { Log "process DACL re-applied to PIDs: `$(`$p.Id -join ',')" }
    } catch { Log "process DACL failed: `$_" }

    if (-not (Get-ScheduledTask -TaskName '$taskWatch' -ErrorAction SilentlyContinue)) {
        `$wscript = Join-Path '$protectDir' 'watch.ps1'
        if (Test-Path `$wscript) {
            schtasks /create /tn '$taskWatch' /tr "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"`$wscript`"" /sc onstart /ru SYSTEM /rl HIGHEST /f | Out-Null
            schtasks /run /tn '$taskWatch' | Out-Null
            Log 'watchdog task recreated'
        }
    }

    if (-not (Get-ScheduledTask -TaskName '$taskGuard' -ErrorAction SilentlyContinue)) {
        `$gscript = Join-Path '$protectDir' 'guard.ps1'
        if (Test-Path `$gscript) {
            schtasks /create /tn '$taskGuard' /tr "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"`$gscript`"" /sc onstart /ru SYSTEM /rl HIGHEST /f | Out-Null
            schtasks /run /tn '$taskGuard' | Out-Null
            Log 'guard task recreated'
        }
    }

    Start-Sleep -Seconds 2
}
"@

$monitorPath = Join-Path $protectDir "monitor_$Id.ps1"
$monitorScript | Set-Content -Path $monitorPath -Encoding UTF8

# ==============================================================================
# 7. Сторож-задача (watch_<Id>.ps1)
# ==============================================================================
Write-Log "[7/8] Сторож-задача..." "Cyan"

$watchScript = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$log = '$logFile'
`$monitorScriptPath = '$monitorPath'
`$taskMainName = '$taskMain'

. '$procGuardPath'

function Log(`$m) { Add-Content `$log "`$(Get-Date -f s)  [WATCH] `$m" }

`$denyMask = 0x0001 -bor 0x0100 -bor 0x0200 -bor 0x0800 -bor 0x00040000 -bor 0x00080000
`$adminSidStr = (New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, `$null)).Value
`$usersSidStr = (New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, `$null)).Value
`$denySids = @(`$adminSidStr, `$usersSidStr)

Log "started, PID=`$PID"

while (`$true) {
    if (-not (Get-ScheduledTask -TaskName `$taskMainName -ErrorAction SilentlyContinue)) {
        if (Test-Path `$monitorScriptPath) {
            schtasks /create /tn `$taskMainName /tr "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"`$monitorScriptPath`"" /sc onstart /ru SYSTEM /rl HIGHEST /f | Out-Null
            schtasks /run /tn `$taskMainName | Out-Null
            Log 'main task recreated'
        }
    }

    `$monProcs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { `$_.CommandLine -and `$_.CommandLine -like "*`$monitorScriptPath*" }

    if (-not `$monProcs) {
        Start-ScheduledTask -TaskName `$taskMainName -ErrorAction SilentlyContinue
        Log 'monitor process missing, task restarted'
    } else {
        foreach (`$mp in `$monProcs) {
            try { [ProcAcl]::ApplyDeny([int]`$mp.ProcessId, `$denySids, `$denyMask) } catch { }
        }
    }

    Start-Sleep -Seconds 3
}
"@

$watchPath = Join-Path $protectDir "watch_$Id.ps1"
$watchScript | Set-Content -Path $watchPath -Encoding UTF8

# ==============================================================================
# 7b. Guard-задача — сторож для сторожа (guard_<Id>.ps1)
# ==============================================================================
$guardScript = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$log = '$logFile'
`$watchScriptPath = '$watchPath'
`$taskWatchName   = '$taskWatch'

Add-Content `$log "`$(Get-Date -f s)  [GUARD] started, PID=`$PID"

. '$procGuardPath'

function Log(`$m) { Add-Content `$log "`$(Get-Date -f s)  [GUARD] `$m" }

`$denyMask = 0x0001 -bor 0x0100 -bor 0x0200 -bor 0x0800 -bor 0x00040000 -bor 0x00080000
`$adminSidStr = (New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, `$null)).Value
`$usersSidStr = (New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, `$null)).Value
`$denySids = @(`$adminSidStr, `$usersSidStr)

while (`$true) {
    if (-not (Get-ScheduledTask -TaskName `$taskWatchName -ErrorAction SilentlyContinue)) {
        if (Test-Path `$watchScriptPath) {
            schtasks /create /tn `$taskWatchName /tr "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"`$watchScriptPath`"" /sc onstart /ru SYSTEM /rl HIGHEST /f | Out-Null
            schtasks /run /tn `$taskWatchName | Out-Null
            Log 'watchdog task recreated'
        }
    }

    `$wp = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { `$_.CommandLine -and `$_.CommandLine -like "*`$watchScriptPath*" }

    if (-not `$wp) {
        Start-ScheduledTask -TaskName `$taskWatchName -ErrorAction SilentlyContinue
        Log 'watchdog process missing, task restarted'
    } else {
        foreach (`$p in `$wp) {
            try { [ProcAcl]::ApplyDeny([int]`$p.ProcessId, `$denySids, `$denyMask) } catch { }
        }
    }

    Start-Sleep -Seconds 3
}
"@

$guardPath = Join-Path $protectDir "guard_$Id.ps1"
$guardScript | Set-Content -Path $guardPath -Encoding UTF8

# ==============================================================================
# Регистрация трёх задач
# ==============================================================================
$actMain  = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$monitorPath`""
$actWatch = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$watchPath`""
$actGuard = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$guardPath`""

$trig   = New-ScheduledTaskTrigger -AtStartup
$prin   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$setts  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $taskMain  -Action $actMain  -Trigger $trig -Principal $prin -Settings $setts -Force | Out-Null
Register-ScheduledTask -TaskName $taskWatch -Action $actWatch -Trigger $trig -Principal $prin -Settings $setts -Force | Out-Null
Register-ScheduledTask -TaskName $taskGuard -Action $actGuard -Trigger $trig -Principal $prin -Settings $setts -Force | Out-Null

Start-ScheduledTask -TaskName $taskMain
Start-ScheduledTask -TaskName $taskWatch
Start-ScheduledTask -TaskName $taskGuard
Write-Log "  Задачи '$taskMain', '$taskWatch', '$taskGuard' запущены." "Green"

# Защищаем процессы всех трёх задач через ProcAcl
Start-Sleep -Seconds 3
$allProtected = @()
foreach ($pair in @(
    @{ Path = $monitorPath; Label = 'monitor' },
    @{ Path = $watchPath;   Label = 'watch'   },
    @{ Path = $guardPath;   Label = 'guard'   }
)) {
    $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -like "*$($pair.Path)*" }
    foreach ($p in $procs) {
        try {
            [ProcAcl]::ApplyDeny([int]$p.ProcessId, $denySids, $denyMask)
            $allProtected += "$($pair.Label):$($p.ProcessId)"
        } catch {}
    }
}
if ($allProtected.Count -gt 0) {
    Write-Log "  Защищены процессы: $($allProtected -join ', ')" "Green"
} else {
    Write-Log "  Процессы ещё не стартовали — сторож/guard защитят их через 3 сек." "Yellow"
}

foreach ($tn in @($taskMain, $taskWatch, $taskGuard)) {
    $ti = Get-ScheduledTaskInfo -TaskName $tn -ErrorAction SilentlyContinue
    if ($ti) {
        $st = (Get-ScheduledTask -TaskName $tn).State
        Write-Log ("  {0}: State={1}, LastResult={2}" -f $tn, $st, $ti.LastTaskResult) "DarkGray"
    }
}

# ==============================================================================
# 8. WMI Permanent Event Subscriptions
#    8a. Schedule modification   → пересоздать SCProtect_<Id>
#    8b. ProcessStop monitor_<Id> → Start-ScheduledTask SCProtect_<Id>
#    8c. ProcessStop watch_<Id>   → Start-ScheduledTask SCProtectWatch_<Id>
# ==============================================================================
Write-Log "[8/8] WMI-подписки..." "Cyan"

$ns = "root\subscription"

function Remove-ScWmiSub([string]$filterName, [string]$consumerName) {
    Get-WmiObject -Namespace $ns -Class __EventFilter            -Filter "Name='$filterName'"       -ErrorAction SilentlyContinue | Remove-WmiObject
    Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter "Name='$consumerName'"     -ErrorAction SilentlyContinue | Remove-WmiObject
    Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -Filter "__Path LIKE '%$filterName%'" -ErrorAction SilentlyContinue | Remove-WmiObject
}

function New-ScWmiSub([string]$filterName, [string]$consumerName, [string]$wql, [string]$commandLine) {
    $f = Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{
        Name           = $filterName
        EventNamespace = "root\cimv2"
        QueryLanguage  = "WQL"
        Query          = $wql
    }
    $c = Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{
        Name                = $consumerName
        CommandLineTemplate = $commandLine
    }
    Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{
        Filter   = $f
        Consumer = $c
    } | Out-Null
}

try {
    # --- 8a. Schedule modification ---
    Remove-ScWmiSub $wmiFilterS $wmiConsumerS
    $consumerScriptS = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"if (-not (Get-ScheduledTask -TaskName '$taskMain' -ErrorAction SilentlyContinue)) { schtasks /create /tn '$taskMain' /tr 'powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"`"$monitorPath`"`"' /sc onstart /ru SYSTEM /rl HIGHEST /f; schtasks /run /tn '$taskMain' }`""
    New-ScWmiSub $wmiFilterS $wmiConsumerS `
        "SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name = 'Schedule'" `
        $consumerScriptS

    # --- 8b. ProcessStop monitor_<Id>.ps1 ---
    Remove-ScWmiSub $wmiFilterM $wmiConsumerM
    $wqlM = "SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'powershell.exe' AND TargetInstance.CommandLine LIKE '%monitor_$Id.ps1%'"
    $cmdM = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"Start-ScheduledTask -TaskName '$taskMain' -ErrorAction SilentlyContinue`""
    New-ScWmiSub $wmiFilterM $wmiConsumerM $wqlM $cmdM

    # --- 8c. ProcessStop watch_<Id>.ps1 ---
    Remove-ScWmiSub $wmiFilterW $wmiConsumerW
    $wqlW = "SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'powershell.exe' AND TargetInstance.CommandLine LIKE '%watch_$Id.ps1%'"
    $cmdW = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"Start-ScheduledTask -TaskName '$taskWatch' -ErrorAction SilentlyContinue`""
    New-ScWmiSub $wmiFilterW $wmiConsumerW $wqlW $cmdW

    Write-Log "  WMI-подписки активны (Schedule / monitor / watch)." "Green"
} catch {
    Write-Log "  WMI-подписка не создана: $_" "Yellow"
}

# ---------- Итог ----------
Write-Log ""
Write-Log "Защита v2.3 активирована." "Green"
Write-Log "  Монитор:  $taskMain" "DarkGray"
Write-Log "  Сторож:   $taskWatch" "DarkGray"
Write-Log "  Guard:    $taskGuard" "DarkGray"
Write-Log "  WMI:      Schedule / monitor / watch" "DarkGray"
Write-Log "Бэкап: $backupFile" "DarkGray"
Write-Log "Лог:   $logFile" "DarkGray"
Write-Log "Откат: Unprotect-ScreenConnect.ps1 -Id $Id" "Yellow"
Write-Log "ВНИМАНИЕ: IFEO-перехват ломает sc/reg/taskkill/services.msc/mmc. taskmgr.exe НЕ блокируется," "Red"
Write-Log "          но завершить процесс службы/монитора/сторожа/guard через него нельзя." "Red"
Write-Log "Основной скрипт можно закрывать — защиту держат 3 задачи SYSTEM + 3 WMI-подписки." "Yellow"