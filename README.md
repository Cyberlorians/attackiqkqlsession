# AttackIQ Defender XDR KQL CTF Scenarios

<details>
<summary><strong>Scenario 01 - Credentials In Registry Script</strong></summary>

### What Happened

AttackIQ ran a PowerShell script that simulates looking for credentials stored in the Windows registry.

### Your Challenge

Find the timestamp, device, account, process name, exact command line, parent process name, and parent command line for the credentials-in-registry script.

### KQL Skill & How To Hunt

Use `DeviceProcessEvents` when the question is about a command that ran. Start by scoping to the AttackIQ workstation.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then search the command line for the scenario keyword: `credentials_in_registry`.

<blockquote>

<details>
<summary>Hint</summary>

Filter on `ProcessCommandLine`. The useful clue is `credentials_in_registry`. Don't forget your challenge to `project` the answers. Pun intended.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has "credentials_in_registry"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

Result:

- Script: `credentials_in_registry.ps1`
- Process: `powershell.exe`
- Account: `xadmin`
- Parent: `python.exe` running `attack_graph.py`

Why it works:

- `ProcessCommandLine` shows the full PowerShell command.
- `credentials_in_registry` is the unique scenario clue.
- `InitiatingProcessFileName` and `InitiatingProcessCommandLine` show the AttackIQ parent process.

</details>

</blockquote>

</details>

<details>
<summary><strong>Scenario 02 - Dump SAM Registry Hive</strong></summary>

### What Happened

AttackIQ tried to save the local SAM registry hive with `reg save`.

### Your Challenge

Find the timestamp, device, account, process name, and exact command line that tried to save the SAM hive.

### KQL Skill & How To Hunt

Use `DeviceProcessEvents` for command-line evidence. Use `has_all` when the command must contain more than one clue.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then search for both `reg save` and `hklm\\sam` in the same command line.

<blockquote>

<details>
<summary>Hint</summary>

Filter on `ProcessCommandLine`. This scenario needs `has_all` because both clues must be present.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has_all ("reg save", "hklm\\sam")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

Result:

- Process: `cmd.exe`
- Account: `xadmin`
- Command: `cmd.exe /c "reg save hklm\sam C:\Users\xadmin\AppData\Local\Temp\sam"`
- Output path: `C:\Users\xadmin\AppData\Local\Temp\sam`

Why it works:

- `reg save` proves a registry hive export attempt.
- `hklm\\sam` proves the SAM hive was the target.
- `ProcessCommandLine` contains the destination path.

</details>

</blockquote>

</details>

<details>
<summary><strong>Scenario 03 - Browser WebCache Collection</strong></summary>

### What Happened

PowerShell launched `esentutl.exe` to collect browser WebCache data.

### Your Challenge

Find the timestamp, device, account, process name, exact command line, parent process name, and parent command line for the WebCache collection activity.

### KQL Skill & How To Hunt

Use `DeviceProcessEvents` and compare process rows to parent process columns. `FileName` is the process that ran. `InitiatingProcessFileName` is what launched it.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then look for `collect_database_webcache`, `WebCache`, and `esentutl`.

<blockquote>

<details>
<summary>Hint</summary>

Filter on both `ProcessCommandLine` and `InitiatingProcessCommandLine`. The child process is `esentutl.exe`, but the parent PowerShell command explains why it ran.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName in~ ("powershell.exe", "esentutl.exe")
| where ProcessCommandLine has_any ("collect_database_webcache", "WebCache", "esentutl")
   or InitiatingProcessCommandLine has "collect_database_webcache"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

Result:

- Script: `collect_database_webcache.ps1`
- Child process: `esentutl.exe`
- Parent process: `powershell.exe`
- Target path includes `C:\Users\xadmin\AppData\Local\Microsoft\Windows\WebCache`

Why it works:

- `FileName in~ (...)` keeps both the PowerShell and `esentutl.exe` rows.
- `InitiatingProcessCommandLine` connects `esentutl.exe` back to the PowerShell script.
- `ProcessCommandLine` shows the WebCache path.

</details>

</blockquote>

</details>

<details>
<summary><strong>Scenario 04 - Kerberoasting With Rubeus</strong></summary>

### What Happened

AttackIQ staged Rubeus for a Kerberoasting test.

### Your Challenge

Find the timestamp, device, file action, file name, folder path, and SHA256 for the staged Rubeus file.

### KQL Skill & How To Hunt

Use `DeviceFileEvents` when the evidence is a file created or deleted on disk.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then filter the file name for `rubeus`.

<blockquote>

<details>
<summary>Hint</summary>

Filter on `FileName`. Keep `ActionType`, `FolderPath`, and `SHA256` in your `project` so the file evidence is report-ready.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "rubeus"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

Result:

- File: `Rubeus.exe`
- Action: `FileCreated`, followed by cleanup with `FileDeleted`
- SHA256: `1e1fe8a1730bf8caabd867fd2f990b0e52aee0f9f8635578ff8b18c0950b616c`

Why it works:

- `DeviceFileEvents` shows staged files even when execution is blocked or short-lived.
- `ActionType` shows the file lifecycle.
- `SHA256` identifies the exact Rubeus artifact.

</details>

</blockquote>

</details>

<details>
<summary><strong>Scenario 05 - Invoke-Kerberoast PowerShell Files</strong></summary>

### What Happened

AttackIQ staged PowerShell Kerberoasting files.

### Your Challenge

Find the timestamp, device, file action, file name, and folder path for the Kerberoast PowerShell files.

### KQL Skill & How To Hunt

Use `DeviceFileEvents` and start with a broad file-name clue. This scenario has more than one related script.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then filter the file name for `kerberoast`.

<blockquote>

<details>
<summary>Hint</summary>

Filter on `FileName`. The broad clue `kerberoast` should reveal both the wrapper script and the main script. `Project` the file action and path so you can prove they were staged.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "kerberoast"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
| order by Timestamp asc
```

Result:

- `call-invoke-kerberoast.ps1`
- `invoke-kerberoast.ps1`
- Both were created under an AttackIQ temp folder.

Why it works:

- `FileName has "kerberoast"` catches both related PowerShell files.
- `ActionType` confirms the files were staged.
- `FolderPath` shows where AttackIQ placed them.

</details>

</blockquote>

</details>

<details>
<summary><strong>Scenario 06 - LSASS Minidump</strong></summary>

### What Happened

AttackIQ tried to dump LSASS memory to a minidump file.

### Your Challenge

Find the timestamp, device, file action, dump file name, and folder path for the LSASS dump.

### KQL Skill & How To Hunt

Use `DeviceFileEvents` and hunt file patterns. Dump files often end in `.dmp`, and AttackIQ dump names may include `pid_`.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then search for `.dmp` or `pid_`.

<blockquote>

<details>
<summary>Hint</summary>

Do not guess the full dump filename. Filter with `FileName endswith ".dmp"` or `FolderPath has "pid_"`.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName endswith ".dmp" or FolderPath has "pid_"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
| order by Timestamp asc
```

Result:

- Dump file: `pid_976_2ztj_d6a.dmp`
- Action: `FileCreated`
- Folder path: `C:\Users\xadmin\AppData\Local\Temp\pid_976_2ztj_d6a.dmp`

Why it works:

- `.dmp` finds dump files without knowing the exact random name.
- `pid_` catches the AttackIQ naming pattern.
- `FolderPath` shows where the dump landed.

</details>

</blockquote>

</details>

<details>
<summary><strong>Scenario 07 - PwDump7</strong></summary>

### What Happened

AttackIQ staged PwDump7, and Defender prevented the hacktool.

### Your Challenge

Find the timestamp, device, alert title, severity, entity type, file name, and SHA256 for the PwDump evidence.

### KQL Skill & How To Hunt

Use `AlertEvidence` when the question asks what Defender called or did with the activity. For alert evidence, get the alert IDs from the target device first, then show the related file and machine rows.

Starter:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then filter the alert title for `PWDump`.

<blockquote>

<details>
<summary>Hint</summary>

Start from the machine alert where `Title has "PWDump"`, then use the matching `AlertId` to reveal the file row with `pwdump7.zip`.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
let TargetAlerts =
    AlertEvidence
    | where Timestamp > ago(14d)
    | where DeviceName == TargetDevice
    | where Title has "PWDump"
    | distinct AlertId;
AlertEvidence
| where Timestamp > ago(14d)
| where AlertId in (TargetAlerts)
| where EntityType in ("Machine", "File")
| project Timestamp, DeviceName=iff(isempty(DeviceName), TargetDevice, DeviceName), Title, Severity, EntityType, FileName, SHA256
| order by Timestamp asc
```

Result:

- Artifact: `pwdump7.zip`
- Defender verdict: `'PWDump' hacktool was prevented`
- SHA256: `ee29e80a2e8c469655fe215eac14c2fbb201116e40fd056dcd1f602e1959263b`

Why it works:

- The machine row scopes the alert to `usm262346`.
- The related file row gives the artifact name and hash.
- `Title` gives Defender's prevention verdict.

</details>

</blockquote>

</details>

<details>
<summary><strong>Scenario 08 - gsecdump</strong></summary>

### What Happened

AttackIQ staged `gsecdump`, but Defender used the detection name `Vigorf`.

### Your Challenge

Find the timestamp, device, alert title, severity, entity type, file name, and SHA256 for the gsecdump/Vigorf evidence.

### KQL Skill & How To Hunt

Use `AlertEvidence` and search for Defender's detection name. Tool names and alert titles do not always match.

Starter:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then filter the alert title for `Vigorf`.

<blockquote>

<details>
<summary>Hint</summary>

Start from `Title has "Vigorf"`, then use the matching `AlertId` to reveal the actual staged filename.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
let TargetAlerts =
    AlertEvidence
    | where Timestamp > ago(14d)
    | where DeviceName == TargetDevice
    | where Title has "Vigorf"
    | distinct AlertId;
AlertEvidence
| where Timestamp > ago(14d)
| where AlertId in (TargetAlerts)
| where EntityType in ("Machine", "File")
| project Timestamp, DeviceName=iff(isempty(DeviceName), TargetDevice, DeviceName), Title, Severity, EntityType, FileName, SHA256
| order by Timestamp asc
```

Result:

- Staged file: `gsecdump-0.7-win32.zip`
- Defender verdict: `'Vigorf' malware was prevented`
- SHA256: `e5b9080d2c9c5b6190567acb7224ed84b48fad50d2a0c666c97a8c8c6b2099f8`

Why it works:

- `Vigorf` is Defender's detection name.
- The related file row shows the actual tool name.
- The hash identifies the staged zip file.

</details>

</blockquote>

</details>

<details>
<summary><strong>Scenario 09 - LaZagne Cleanup</strong></summary>

### What Happened

AttackIQ staged LaZagne, then cleanup removed it.

### Your Challenge

Find the timestamp, device, file action, file name, folder path, and SHA256 for the LaZagne file lifecycle.

### KQL Skill & How To Hunt

Use `DeviceFileEvents` and keep `ActionType`; it tells you whether the file was created, deleted, or changed.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then filter the file name for `lazagne`.

<blockquote>

<details>
<summary>Hint</summary>

Look for more than one row. `FileCreated` and `FileDeleted` together tell the cleanup story.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

Result:

- Artifact: `laZagne_windows_x64.exe`
- Actions: `FileCreated`, then `FileDeleted`
- SHA256 on creation: `5f26175299518e9c5541db9c17ce5981c2c5dcfc7ad2347716f4776e67af8ff3`

Why it works:

- `ActionType` shows the lifecycle.
- `FileName has "lazagne"` catches the staged tool.
- Cleanup does not remove the telemetry.

</details>

</blockquote>

</details>

<details>
<summary><strong>Scenario 10 - Obfuscated Mimikatz Script</strong></summary>

### What Happened

AttackIQ staged a Mimikatz-style PowerShell script instead of a simple `mimikatz.exe` process.

### Your Challenge

Find the timestamp, device, alert title, severity, entity type, file name, and SHA256 for the Mimikatz-style script artifact.

### KQL Skill & How To Hunt

Use `AlertEvidence` when Defender has a verdict and hash for a staged script. Scope to the target device first, then pull back the related file evidence.

Starter:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then filter for Defender's Mimikatz alert and the exact script filename.

<blockquote>

<details>
<summary>Hint</summary>

Do not search only for `mimikatz.exe`. Use `AlertId` to connect the target-device alert to the script file row with the hash.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
let TargetAlerts =
    AlertEvidence
    | where Timestamp > ago(14d)
    | where DeviceName == TargetDevice
    | where Title has "Mimikatz credential theft tool"
    | distinct AlertId;
AlertEvidence
| where Timestamp > ago(14d)
| where AlertId in (TargetAlerts)
| where FileName =~ "mimikatz_dump_passwords_v2.ps1"
| project Timestamp, DeviceName=iff(isempty(DeviceName), TargetDevice, DeviceName), Title, Severity, EntityType, FileName, SHA256
| order by Timestamp asc
```

Result:

- Script artifact: `mimikatz_dump_passwords_v2.ps1`
- Defender verdict: `Mimikatz credential theft tool`
- SHA256: `0984af597a9f4b6fb311ec64cf5d853c7390e0d375a43f1ce0e28bf3a81b0856`

Why it works:

- The target-device alert scopes the hunt to `usm262346`.
- `FileName =~ "mimikatz_dump_passwords_v2.ps1"` keeps the answer focused on the script.
- `SHA256` gives the durable indicator for the script.

</details>

</blockquote>

</details>

<details>
<summary><strong>Scenario 11 - Original Mimikatz Package</strong></summary>

### What Happened

AttackIQ staged the classic Mimikatz package, and Defender identified it as a credential theft tool.

### Your Challenge

Find the timestamp, device, alert title, severity, entity type, file name, and SHA256 for the original Mimikatz package evidence.

### KQL Skill & How To Hunt

Use `AlertEvidence` when the answer needs Defender's verdict and the file hash. Scope to the target device, then pull back the related file evidence.

Starter:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then intersect the target-device Mimikatz alert with the exact package filename.

<blockquote>

<details>
<summary>Hint</summary>

The exact file is `mimikatz-x64.zip`. Use `AlertId` to connect the target-device alert to the file evidence row with the hash.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
let TargetAlerts =
    AlertEvidence
    | where Timestamp > ago(14d)
    | where DeviceName == TargetDevice
    | where Title has "Mimikatz credential theft tool"
    | distinct AlertId;
AlertEvidence
| where Timestamp > ago(14d)
| where AlertId in (TargetAlerts)
| where FileName =~ "mimikatz-x64.zip"
| project Timestamp, DeviceName=iff(isempty(DeviceName), TargetDevice, DeviceName), Title, Severity, EntityType, FileName, SHA256
| order by Timestamp asc
```

Result:

- Artifact: `mimikatz-x64.zip`
- Defender verdict: `Mimikatz credential theft tool`
- Severity: `High`
- SHA256: `29a3e90d067a848bac1d7301e22d6ac7b6979c89be10373b98a47845e94c45b8`

Why it works:

- `Title` confirms Defender's verdict.
- `FileName =~ "mimikatz-x64.zip"` keeps this focused on the original package.
- `SHA256` gives the durable indicator for the package.

</details>

</blockquote>

</details>
