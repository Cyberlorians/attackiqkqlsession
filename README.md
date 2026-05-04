# AttackIQ Scenario: Security Control Baseline - Endpoint EDR

This is a KQL teaching lab built from an authorized AttackIQ `Security Control Baseline - Endpoint EDR` run. The goal is not just to show finished queries. The goal is to teach students how to think like hunters: start with one workstation, find clues, pivot across tables, and explain what happened.

The class story: a simulated attacker ran a fast credential-access sequence on one workstation. Students have to catch each move with KQL.

## Scope

All hunts are intentionally scoped to the workstation where AttackIQ ran. This keeps the lesson realistic for a customer environment where only the test workstation is in scope.

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
```

Sentinel Data Lake uses `TimeGenerated`. Microsoft Defender XDR Advanced Hunting commonly uses `Timestamp`. If students run these in the XDR portal and the table uses `Timestamp`, swap the time column:

```kusto
// Sentinel Data Lake
| where TimeGenerated between (Start .. End)

// Defender XDR Advanced Hunting
| where Timestamp between (Start .. End)
```

## Core Tables

| Table | Why students use it |
|---|---|
| `DeviceProcessEvents` | Process execution, command lines, parent processes, initiating users. |
| `DeviceFileEvents` | Tool staging, scripts, zip files, dump files, cleanup. |
| `AlertEvidence` | Defender alerts, prevented tools, MITRE mappings, file hashes. |

## Learning Objectives

- Use `let` statements to control scope and time windows.
- Filter a single workstation with `DeviceName == TargetDevice`.
- Hunt process execution in `DeviceProcessEvents`.
- Hunt staged tools and cleanup in `DeviceFileEvents`.
- Use `AlertEvidence` to learn from blocked or prevented activity.
- Combine evidence with `union`, `project`, `order by`, `has`, `has_any`, and `has_all`.
- Reconstruct attacker behavior from endpoint telemetry.

Each scenario is built like a beginner CTF card:

- Mission: what the student is trying to catch.
- KQL logic: the table, column, and operator that matter.
- Build it slowly: small query pieces before the final hunt.
- CTF question: the investigation answer students should prove.

For every mini-query, paste the shared scope block first unless it is already included:

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
```

## KQL 101: How To Read These Queries

KQL reads from top to bottom. Think of each line as one instruction in a recipe.

```kusto
DeviceProcessEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where ProcessCommandLine has "reg save"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

How to read it:

- `DeviceProcessEvents`: start with the process table.
- `|`: pipe the rows into the next step.
- `where`: keep only rows that match a condition.
- `between (Start .. End)`: keep only rows inside the time window.
- `==`: exact match.
- `has`: word-based search for one clue.
- `has_any`: match any clue in a list.
- `has_all`: require every clue in a list.
- `=~`: case-insensitive exact match, useful for known filenames.
- `in~`: case-insensitive match against a list of exact values.
- `endswith`: useful for extensions like `.dmp`.
- `project`: choose the columns students need for the answer.
- `summarize`: group rows into counts or rollups.
- `order by`: sort results so the story is easier to read.

Beginner habit: every answer should prove four things when possible: **when**, **where**, **what**, and **why it matters**.

## Run Context

| Field | Value |
|---|---|
| AttackIQ package | `Security Control Baseline - Endpoint EDR` |
| Target workstation | `usm262346` |
| Primary account | `xadmin` |
| Package launcher | `SecBase_security-control-baseline-endpoint-edr_V1_0_51_amd64_gui-sig.exe` |
| Runtime path | `C:\Users\xadmin\Downloads\.ghostex-cli-wd-2170286878` |
| Orchestrator | `python.exe` running `attack_graph.py` |
| Validation window | `2026-05-04T13:10:00Z` to `2026-05-04T13:20:00Z` |

## Scenario Coverage

All 11 scenarios produced telemetry on `usm262346`.

| # | Scenario | Best evidence tables |
|---|---|---|
| 00 | Warm-Up: Rebuild the Attack Timeline | `DeviceProcessEvents`, `DeviceFileEvents`, `AlertEvidence` |
| 01 | Credentials In Registry Script | `DeviceProcessEvents`, `DeviceFileEvents`, `AlertEvidence` |
| 02 | Dump SAM Registry Hive via `reg save` | `DeviceProcessEvents`, `AlertEvidence` |
| 03 | Collect Browser Data via Esentutl and PowerShell | `DeviceProcessEvents`, `DeviceFileEvents` |
| 04 | Kerberoasting using Rubeus | `DeviceFileEvents`, `AlertEvidence` |
| 05 | Kerberoasting using PowerShell Empire Invoke-Kerberoast | `DeviceFileEvents`, `AlertEvidence` |
| 06 | Dump LSASS Process to Minidump File | `DeviceFileEvents`, `AlertEvidence` |
| 07 | Dump Passwords using PwDump7 | `DeviceFileEvents`, `AlertEvidence` |
| 08 | Dump Passwords using gsecdump | `DeviceFileEvents`, `AlertEvidence` |
| 09 | Dump Passwords using LaZagne | `DeviceFileEvents`, `AlertEvidence` |
| 10 | Dump Windows Passwords with Obfuscated Mimikatz | `DeviceFileEvents`, `AlertEvidence` |
| 11 | Dump Windows Passwords with Original Mimikatz | `DeviceFileEvents`, `AlertEvidence` |

---

<details open>
<summary><strong>00 - Warm-Up: Rebuild the Attack Timeline</strong></summary>

## Story

Before chasing individual scenarios, students rebuild the attacker timeline. This teaches them that one table rarely tells the whole story.

## KQL Skills

`let`, `union`, `project`, `order by`, workstation scoping.

## KQL Teaching Question

Why does this warm-up use `union isfuzzy=true` instead of querying only one table?

<details>
<summary>KQL Answer</summary>

Endpoint investigations usually need more than one evidence type. `DeviceProcessEvents` shows execution, `DeviceFileEvents` shows staged or deleted files, and `AlertEvidence` shows Defender verdicts. `union isfuzzy=true` lets students combine those tables even when the projected columns are not identical across every source.

The teaching point: use `project` inside each branch to normalize the output columns, then `order by TimeGenerated asc` to turn separate tables into one readable timeline.

</details>

## Build It Slowly

Start with the question: "What happened on this one computer during the test window?"

The beginner mistake is to search the whole tenant first. The better habit is to scope early:

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
DeviceProcessEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| take 20
```

Now teach the timeline idea. A timeline needs a time column, an evidence type, and a detail column:

```kusto
DeviceProcessEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| project TimeGenerated, EvidenceType="Process", Detail=ProcessCommandLine
| order by TimeGenerated asc
```

Beginner checkpoint: Which column tells you when it happened? Which column tells you what command ran?

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
union isfuzzy=true
(
    DeviceProcessEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where ProcessCommandLine has_any (".ghostex-cli", "AppData\\Local\\Temp\\aiq", "reg save", "esentutl", "credentials_in_registry", "collect_database_webcache")
    | project TimeGenerated, EvidenceType="Process", Action=FileName,
              Detail=ProcessCommandLine, Source=InitiatingProcessCommandLine
),
(
    DeviceFileEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where FolderPath has_any (".ghostex-cli", "AppData\\Local\\Temp\\aiq")
    | where FileName has_any ("mimikatz", "lazagne", "gsecdump", "pwdump", "rubeus", "kerberoast", "credential", "webcache")
       or FileName endswith ".dmp"
    | project TimeGenerated, EvidenceType="File", Action=ActionType,
              Detail=strcat(FolderPath, "\\", FileName), Source=InitiatingProcessCommandLine
),
(
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
       or FileName has_any ("mimikatz", "lazagne", "gsecdump", "pwdump", "rubeus", "kerberoast", "credentials_in_registry")
    | project TimeGenerated, EvidenceType="Alert", Action=Title,
              Detail=strcat(EntityType, " | ", FileName, " | ", ProcessCommandLine), Source=ServiceSource
)
| order by TimeGenerated asc
```

## CTF Question

What launched the attack, what account ran it, and where did the AttackIQ runtime unpack itself?

<details>
<summary>Answer Key</summary>

- Launcher: `SecBase_security-control-baseline-endpoint-edr_V1_0_51_amd64_gui-sig.exe`
- Account: `xadmin`
- Runtime path: `C:\Users\xadmin\Downloads\.ghostex-cli-wd-2170286878`
- Main orchestrator: `python.exe` running `attack_graph.py`

### How The KQL Finds It

Read the warm-up query like this:

1. `DeviceProcessEvents` looks for commands that ran.
2. `DeviceFileEvents` looks for tools and scripts that appeared on disk.
3. `AlertEvidence` looks for Defender's security interpretation.
4. Each branch uses `project` to rename different columns into the same story columns: `TimeGenerated`, `EvidenceType`, `Action`, `Detail`, and `Source`.
5. `order by TimeGenerated asc` turns all three evidence types into one timeline.

Beginner checkpoint: when you see `union`, ask, "What tables are being combined, and did we make their output columns match?"

</details>

</details>

---

<details>
<summary><strong>01 - Credentials In Registry Script</strong></summary>

## Story

The attacker tries to abuse the registry as a place where credential material can live. The task is to find the script, prove it ran, and connect it to Defender's ATT&CK mapping.

## KQL Idea

Start with a file or script name, then pivot into alert evidence.

## KQL Teaching Question

When you know the suspicious script name, which KQL pattern helps you prove both file staging and Defender detection?

<details>
<summary>KQL Answer</summary>

Use the script name as the anchor in more than one table. In this scenario, `FileName =~ "credentials_in_registry.ps1"` finds the staged file, while `AttackTechniques has_any ("Credentials in Registry", "T1552.002")` connects the behavior to the Defender/ATT&CK context.

The teaching point: `=~` is a case-insensitive exact match, which is good when the filename is known. `has_any` is better for matching one of several alert or technique clues.

</details>

## Build It Slowly

Mission: find a PowerShell script related to credentials in the registry.

First, teach students where script file activity lives:

```kusto
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName =~ "credentials_in_registry.ps1"
| project TimeGenerated, FileName, FolderPath, ActionType
```

Then teach the pivot from file evidence to security meaning:

```kusto
AlertEvidence
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice or FileName =~ "credentials_in_registry.ps1"
| project TimeGenerated, Title, AttackTechniques, FileName
```

KQL logic to learn: use exact filename matching when the artifact name is known, then use `project` to keep only the columns that answer the CTF question.

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
union isfuzzy=true
(
    DeviceProcessEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where ProcessCommandLine has "credentials_in_registry.ps1"
    | project TimeGenerated, EvidenceType="Process", FileName, Detail=ProcessCommandLine, AccountName, SHA256
),
(
    DeviceFileEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where FileName =~ "credentials_in_registry.ps1"
    | project TimeGenerated, EvidenceType="File", FileName, Detail=FolderPath, AccountName=InitiatingProcessAccountName, SHA256
),
(
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice or FileName =~ "credentials_in_registry.ps1"
    | where Title has_any ("PowerShell", "Registry", "Credentials")
       or AttackTechniques has_any ("Credentials in Registry", "T1552.002")
    | project TimeGenerated, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", AttackTechniques), AccountName, SHA256
)
| order by TimeGenerated asc
```

## CTF Question

Which script is the registry-creds clue, and which ATT&CK technique did Defender attach to it?

<details>
<summary>Answer Key</summary>

- Script: `credentials_in_registry.ps1`
- Alert: `A malicious PowerShell Cmdlet was invoked on the machine`
- ATT&CK: `Credentials in Registry (T1552.002)`

### How The KQL Finds It

The answer comes from three beginner pivots:

1. `DeviceFileEvents` plus `FileName =~ "credentials_in_registry.ps1"` proves the script artifact existed.
2. `DeviceProcessEvents` plus `ProcessCommandLine has "credentials_in_registry.ps1"` checks whether PowerShell tried to run it.
3. `AlertEvidence` plus `AttackTechniques has_any ("Credentials in Registry", "T1552.002")` explains why Defender cared.

Beginner checkpoint: `FileName` tells you what the artifact was. `Title` and `AttackTechniques` tell you why it matters.

</details>

</details>

---

<details>
<summary><strong>02 - Dump SAM Registry Hive via reg save</strong></summary>

## Story

The attacker tries to copy the local SAM registry hive. The command line is the clue.

## KQL Idea

Use `has_all` when multiple terms must appear together in the same command line.

## KQL Teaching Question

Why is `has_all ("reg save", "hklm\\sam")` stronger than only searching for `reg` or `sam`?

<details>
<summary>KQL Answer</summary>

`reg` by itself is too broad, and `sam` by itself can appear in unrelated paths or names. `has_all` requires both clues to exist in the same command line, which makes the result much closer to the real behavior: saving the SAM registry hive.

The teaching point: use `has_all` when the detection idea depends on a combination of words, not just one keyword.

</details>

## Build It Slowly

Mission: find a command that saved the local SAM registry hive.

Start broad enough to see command lines for `cmd.exe`:

```kusto
DeviceProcessEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName =~ "cmd.exe"
| project TimeGenerated, FileName, ProcessCommandLine
```

Now add the required behavior terms:

```kusto
DeviceProcessEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where ProcessCommandLine has_all ("reg save", "hklm\\sam")
| project TimeGenerated, ProcessCommandLine, AccountName
```

KQL logic to learn: `has_all` is for "both of these clues must be present." That is different from `has_any`, where only one clue has to match.

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
union isfuzzy=true
(
    DeviceProcessEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where FileName =~ "cmd.exe"
    | where ProcessCommandLine has_all ("reg save", "hklm\\sam")
    | project TimeGenerated, EvidenceType="Process", FileName, Detail=ProcessCommandLine, AccountName, SHA256
),
(
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where ProcessCommandLine has_all ("reg save", "hklm\\sam")
       or Title has "RegistryExfil"
    | project TimeGenerated, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", ProcessCommandLine, " | ", AttackTechniques), AccountName, SHA256
)
| order by TimeGenerated asc
```

## CTF Question

Where did the attacker try to save the SAM hive?

<details>
<summary>Answer Key</summary>

The command line shows:

```text
cmd.exe /c "reg save hklm\sam C:\Users\xadmin\AppData\Local\Temp\sam"
```

Defender also produced a `RegistryExfil` prevention alert.

### How The KQL Finds It

The important beginner logic is the command-line filter:

```kusto
| where ProcessCommandLine has_all ("reg save", "hklm\\sam")
```

Read it as: keep only process rows where the command line contains both clues. `reg save` tells us the registry was being exported. `hklm\sam` tells us the SAM hive was the target.

Then `project TimeGenerated, FileName, Detail=ProcessCommandLine` keeps the columns needed to answer: when it happened, which process ran, and the exact command.

</details>

</details>

---

<details>
<summary><strong>03 - Browser Data via Esentutl and PowerShell</strong></summary>

## Story

The attacker goes after browser/WebCache data. PowerShell starts the script, and `esentutl.exe` does the database work.

## KQL Idea

Follow parent and child process relationships with `InitiatingProcessCommandLine`.

## KQL Teaching Question

How does KQL show that `esentutl.exe` was part of the PowerShell browser-data collection chain?

<details>
<summary>KQL Answer</summary>

Query both `FileName` and `InitiatingProcessCommandLine`. `FileName in~ ("powershell.exe", "esentutl.exe")` catches the parent and child process names, while `InitiatingProcessCommandLine has "collect_database_webcache.ps1"` ties the child process back to the script that launched it.

The teaching point: parent process fields are pivot fields. They explain why a normal Windows binary appeared in the timeline.

</details>

## Build It Slowly

Mission: prove that browser/WebCache collection happened and show the parent-child process chain.

First, find the two process names students care about:

```kusto
DeviceProcessEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName in~ ("powershell.exe", "esentutl.exe")
| project TimeGenerated, FileName, ProcessCommandLine
```

Then add the parent process columns:

```kusto
DeviceProcessEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName =~ "esentutl.exe"
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

KQL logic to learn: `InitiatingProcessFileName` and `InitiatingProcessCommandLine` answer "who launched this?"

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
DeviceProcessEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName in~ ("powershell.exe", "esentutl.exe")
| where ProcessCommandLine has_any ("collect_database_webcache.ps1", "esentutl", "WebCache")
   or InitiatingProcessCommandLine has "collect_database_webcache.ps1"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName, SHA256
| order by TimeGenerated asc
```

## CTF Question

Which process launched `esentutl.exe`, and what browser/cache path was targeted?

<details>
<summary>Answer Key</summary>

- Parent process: `powershell.exe`
- Script: `collect_database_webcache.ps1`
- Child process: `esentutl.exe`
- Target path includes `C:\Users\xadmin\AppData\Local\Microsoft\Windows\WebCache`

### How The KQL Finds It

This answer is about parent and child process thinking:

1. `FileName in~ ("powershell.exe", "esentutl.exe")` keeps the two process names students care about.
2. `ProcessCommandLine has_any (...)` finds direct command-line clues like `WebCache`.
3. `InitiatingProcessCommandLine has "collect_database_webcache.ps1"` shows what launched the child process.
4. `project ... InitiatingProcessFileName, InitiatingProcessCommandLine` keeps the parent process evidence visible.

Beginner checkpoint: `FileName` is the process itself. `InitiatingProcessFileName` is the process that started it.

</details>

</details>

---

<details>
<summary><strong>04 - Kerberoasting Using Rubeus</strong></summary>

## Story

The attacker stages Rubeus for Kerberoasting. Defender interrupts the move, but the staged file and alert evidence prove what happened.

## KQL Idea

A blocked tool may not produce a clean process execution row. Hunt file staging and `AlertEvidence`.

## KQL Teaching Question

If Defender blocks a tool before normal execution telemetry appears, which tables should students query first?

<details>
<summary>KQL Answer</summary>

Start with `DeviceFileEvents` and `AlertEvidence`. `DeviceFileEvents` can show that `Rubeus.exe` was staged on disk. `AlertEvidence` can show the Defender verdict and ATT&CK mapping even if there is no clean `DeviceProcessEvents` execution row.

The teaching point: absence of process execution is not absence of activity. Blocked tools often leave stronger evidence in file and alert tables.

</details>

## Build It Slowly

Mission: catch Rubeus even if Defender blocked it before normal execution.

Start with file staging:

```kusto
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName =~ "Rubeus.exe"
| project TimeGenerated, FileName, FolderPath, ActionType, SHA256
```

Then ask Defender what it thought the file meant:

```kusto
AlertEvidence
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice or FileName =~ "Rubeus.exe"
| project TimeGenerated, Title, AttackTechniques, FileName, SHA256
```

KQL logic to learn: when the process table is quiet, check file and alert tables before deciding nothing happened.

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
union isfuzzy=true
(
    DeviceFileEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where FileName =~ "Rubeus.exe"
    | project TimeGenerated, EvidenceType="File", FileName, Detail=strcat(ActionType, " | ", FolderPath), AccountName=InitiatingProcessAccountName, SHA256
),
(
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice or FileName =~ "Rubeus.exe"
    | where FileName =~ "Rubeus.exe" or AttackTechniques has_any ("Kerberoasting", "T1558.003")
    | project TimeGenerated, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", AttackTechniques), AccountName, SHA256
)
| order by TimeGenerated asc
```

## CTF Question

What file name and hash identify the Rubeus attempt?

<details>
<summary>Answer Key</summary>

- File: `Rubeus.exe`
- Hash: `1e1fe8a1730bf8caabd867fd2f990b0e52aee0f9f8635578ff8b18c0950b616c`
- ATT&CK: `Kerberoasting (T1558.003)`

### How The KQL Finds It

This scenario teaches that blocked tools may be easier to find in file and alert tables:

1. `DeviceFileEvents` plus `FileName =~ "Rubeus.exe"` proves the tool was staged.
2. `AlertEvidence` plus `AttackTechniques has_any ("Kerberoasting", "T1558.003")` proves the behavior category.
3. `SHA256` gives a durable identifier for the exact file.

Beginner checkpoint: if `DeviceProcessEvents` is quiet, do not stop. Check `DeviceFileEvents` and `AlertEvidence`.

</details>

</details>

---

<details>
<summary><strong>05 - PowerShell Empire Invoke-Kerberoast</strong></summary>

## Story

The attacker switches from a standalone executable to a PowerShell Kerberoasting script.

## KQL Idea

Hunt script staging first, then pivot to alert evidence and ATT&CK context.

## KQL Teaching Question

Why does this query use `FileName has_any ("invoke-kerberoast", "call-invoke-kerberoast")` instead of an exact filename match?

<details>
<summary>KQL Answer</summary>

This scenario stages more than one related PowerShell file. `has_any` lets the query catch both the wrapper script and the main Kerberoast script without writing separate filters for each filename.

The teaching point: use `has_any` when a scenario may have several related artifact names and any one of them is enough to include the row.

</details>

## Build It Slowly

Mission: find the PowerShell Kerberoasting files.

Start by searching for the family name, not one exact file:

```kusto
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName has "kerberoast"
| project TimeGenerated, FileName, FolderPath, ActionType
```

Then tighten the logic to the expected pair of files:

```kusto
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName has_any ("invoke-kerberoast", "call-invoke-kerberoast")
| project TimeGenerated, FileName, FolderPath, ActionType
```

KQL logic to learn: `has` is good for one clue. `has_any` is good when several related clue words can identify the same scenario.

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
union isfuzzy=true
(
    DeviceFileEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where FileName has_any ("invoke-kerberoast", "call-invoke-kerberoast")
    | project TimeGenerated, EvidenceType="File", FileName, Detail=strcat(ActionType, " | ", FolderPath), AccountName=InitiatingProcessAccountName, SHA256
),
(
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice or FileName has "invoke-kerberoast"
    | where FileName has "invoke-kerberoast" or AttackTechniques has_any ("Kerberoasting", "T1558.003")
    | project TimeGenerated, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", AttackTechniques), AccountName, SHA256
)
| order by TimeGenerated asc
```

## CTF Question

Which two PowerShell files were staged for the Kerberoasting test?

<details>
<summary>Answer Key</summary>

- `call-invoke-kerberoast.ps1`
- `invoke-kerberoast.ps1`
- Defender generated detections tied to `invoke-kerberoast.ps1`.

### How The KQL Finds It

The query uses a list because there are two related script names:

```kusto
| where FileName has_any ("invoke-kerberoast", "call-invoke-kerberoast")
```

Read it as: keep rows where the filename has either of those terms. That is useful when a scenario uses a launcher script and a payload script.

Then the `AlertEvidence` branch uses the same keyword family to connect the script to Defender's Kerberoasting context.

Beginner checkpoint: `has_any` is for "any one of these clues is enough."

</details>

</details>

---

<details>
<summary><strong>06 - LSASS Minidump</strong></summary>

## Story

The attacker tries to dump LSASS. A dump file lands in temp and Defender raises a `DumpLsass` prevention alert.

## KQL Idea

Dump files are investigation gold. Hunt for `.dmp`, then connect the file to alert evidence.

## KQL Teaching Question

How can students find LSASS dump behavior even if the dump filename is random?

<details>
<summary>KQL Answer</summary>

Look for file patterns and alert semantics instead of relying on one exact filename. `FileName endswith ".dmp"` catches dump files, while `Title has_any ("DumpLsass", "LSASS")` and `AttackTechniques has_any ("LSASS Memory", "T1003.001")` catch the Defender interpretation.

The teaching point: random filenames are common, so hunt on file extension, path pattern, alert title, and ATT&CK technique.

</details>

## Build It Slowly

Mission: catch LSASS dumping even when the dump filename is not predictable.

Start with the most beginner-friendly clue: dump files end in `.dmp`.

```kusto
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName endswith ".dmp"
| project TimeGenerated, FileName, FolderPath, ActionType
```

Then connect the file to the detection language:

```kusto
AlertEvidence
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where Title has_any ("DumpLsass", "LSASS")
| project TimeGenerated, Title, AttackTechniques, ProcessCommandLine
```

KQL logic to learn: use `endswith` for extensions and use alert titles to translate a suspicious file into attacker behavior.

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
union isfuzzy=true
(
    DeviceFileEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where FileName endswith ".dmp" or FolderPath has "pid_"
    | project TimeGenerated, EvidenceType="File", FileName, Detail=strcat(ActionType, " | ", FolderPath), AccountName=InitiatingProcessAccountName, SHA256
),
(
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where Title has_any ("DumpLsass", "LSASS") or AttackTechniques has_any ("LSASS Memory", "T1003.001")
    | project TimeGenerated, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", ProcessCommandLine, " | ", AttackTechniques), AccountName, SHA256
)
| order by TimeGenerated asc
```

## CTF Question

What dump file was created, and what ATT&CK sub-technique did the alert map to?

<details>
<summary>Answer Key</summary>

- Dump file: `pid_976_2ztj_d6a.dmp`
- Alert: `An active 'DumpLsass' hacktool in a command line was prevented from executing`
- ATT&CK: `LSASS Memory (T1003.001)`

### How The KQL Finds It

This scenario teaches pattern hunting when filenames are random:

1. `FileName endswith ".dmp"` finds dump files without knowing the full filename.
2. `FolderPath has "pid_"` catches the AttackIQ-style dump path pattern.
3. `Title has_any ("DumpLsass", "LSASS")` searches the Defender alert language.
4. `AttackTechniques has_any ("LSASS Memory", "T1003.001")` ties the alert to the ATT&CK sub-technique.

Beginner checkpoint: random names require pattern logic. Extensions, folders, titles, and ATT&CK fields are all clues.

</details>

</details>

---

<details>
<summary><strong>07 - Dump Passwords Using PwDump7</strong></summary>

## Story

The attacker stages PwDump7. Defender prevents the hacktool, but students can still prove the attempted credential dump.

## KQL Idea

Use `AlertEvidence` for prevented tools and `DeviceFileEvents` for the staged artifact.

## KQL Teaching Question

What KQL evidence tells you the PwDump scenario was attempted but prevented?

<details>
<summary>KQL Answer</summary>

Use a `union` of file and alert evidence. `DeviceFileEvents | where FileName has "pwdump"` shows the artifact, and `AlertEvidence | where Title has "PWDump"` shows Defender's prevention verdict.

The teaching point: a prevented attack still produces useful telemetry. Teach students to read `Title`, `Severity`, and `FileName` together.

</details>

## Build It Slowly

Mission: prove PwDump was attempted and explain whether it ran or was blocked.

First, search file evidence with a simple keyword:

```kusto
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName has "pwdump"
| project TimeGenerated, FileName, FolderPath, ActionType
```

Then search the alert wording:

```kusto
AlertEvidence
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice or FileName has "pwdump"
| where FileName has "pwdump" or Title has "PWDump"
| project TimeGenerated, Title, Severity, FileName
```

KQL logic to learn: `Title` often tells you the outcome. Words like `prevented` or `blocked` change the story from execution to attempted execution.

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
union isfuzzy=true
(
    DeviceFileEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where FileName has "pwdump"
    | project TimeGenerated, EvidenceType="File", FileName, Detail=strcat(ActionType, " | ", FolderPath), AccountName=InitiatingProcessAccountName, SHA256
),
(
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice or FileName has "pwdump"
    | where Title has "PWDump" or FileName has "pwdump"
    | project TimeGenerated, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", Severity), AccountName, SHA256
)
| order by TimeGenerated asc
```

## CTF Question

Was PwDump executed cleanly, or was it prevented? What tells you?

<details>
<summary>Answer Key</summary>

- Artifact: `pwdump7.zip`
- Defender alert: `'PWDump' hacktool was prevented`
- It was prevented, but the attempt is still visible.

### How The KQL Finds It

The answer comes from comparing file evidence with alert evidence:

1. `DeviceFileEvents | where FileName has "pwdump"` finds the staged artifact.
2. `AlertEvidence | where Title has "PWDump"` finds Defender's verdict.
3. `project TimeGenerated, EvidenceType, FileName, Detail` keeps the result readable.

The word `prevented` in the alert title matters. It tells students this was an attempted credential dump, not clean execution.

Beginner checkpoint: the security outcome is usually in `Title`, not just `FileName`.

</details>

</details>

---

<details>
<summary><strong>08 - Dump Passwords Using gsecdump</strong></summary>

## Story

The attacker stages `gsecdump`. Defender does not necessarily call it by that exact name, which is the point of the lesson.

## KQL Idea

Tool names and detection names do not always match. Hunt both the staged file name and alert title.

## KQL Teaching Question

Why should the query search for both `gsecdump` and `Vigorf`?

<details>
<summary>KQL Answer</summary>

The tool name and the detection name are not always the same. `FileName has "gsecdump"` finds the staged artifact, while `Title has_any ("Vigorf", "malware")` catches how Defender classified the threat.

The teaching point: do not assume the alert title will repeat the tool name. Pair artifact terms with detection-family terms.

</details>

## Build It Slowly

Mission: connect the staged `gsecdump` artifact to Defender's different detection name.

Start with the tool name:

```kusto
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName has "gsecdump"
| project TimeGenerated, FileName, FolderPath, ActionType
```

Then search alert evidence with both artifact and detection-family terms:

```kusto
AlertEvidence
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice or FileName has "gsecdump"
| where FileName has "gsecdump" or Title has_any ("Vigorf", "malware")
| project TimeGenerated, Title, Severity, FileName
```

KQL logic to learn: one table may show the attacker tool name while another table shows the security product's malware family name.

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
union isfuzzy=true
(
    DeviceFileEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where FileName has "gsecdump"
    | project TimeGenerated, EvidenceType="File", FileName, Detail=strcat(ActionType, " | ", FolderPath), AccountName=InitiatingProcessAccountName, SHA256
),
(
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice or FileName has "gsecdump"
    | where FileName has "gsecdump" or Title has_any ("Vigorf", "malware")
    | project TimeGenerated, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", Severity), AccountName, SHA256
)
| order by TimeGenerated asc
```

## CTF Question

What did Defender call the threat, and what was the actual staged file name?

<details>
<summary>Answer Key</summary>

- Staged file: `gsecdump-0.7-win32.zip`
- Defender alert: `'Vigorf' malware was prevented`

### How The KQL Finds It

This is a naming lesson:

1. `FileName has "gsecdump"` finds what AttackIQ staged.
2. `Title has_any ("Vigorf", "malware")` finds what Defender called it.
3. Seeing both in the same time window connects the artifact name to the detection name.

Beginner checkpoint: do not expect the alert title to repeat your search term. Defender may use a malware family or detection family name.

</details>

</details>

---

<details>
<summary><strong>09 - Dump Passwords Using LaZagne</strong></summary>

## Story

The attacker stages LaZagne, a credential recovery tool. It appears and then gets cleaned up.

## KQL Idea

Use file events to catch both `FileCreated` and `FileDeleted` for the same suspicious artifact.

## KQL Teaching Question

How can KQL show that LaZagne was staged and then cleaned up?

<details>
<summary>KQL Answer</summary>

Query `DeviceFileEvents` for `FileName has "lazagne"`, then keep `ActionType` in the projected output. Seeing both creation and deletion actions for the same artifact shows the tool lifecycle.

The teaching point: include `ActionType` when hunting file artifacts. The action tells the story, not just the filename.

</details>

## Build It Slowly

Mission: show that LaZagne appeared on disk and was later removed.

Start by finding every LaZagne file event:

```kusto
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| project TimeGenerated, FileName, ActionType, FolderPath
| order by TimeGenerated asc
```

Then summarize the lifecycle:

```kusto
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| summarize Actions=make_set(ActionType), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by FileName
```

KQL logic to learn: `summarize` turns many rows into one answer. `make_set(ActionType)` shows all actions seen for the file.

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
union isfuzzy=true
(
    DeviceFileEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where FileName has "lazagne"
    | project TimeGenerated, EvidenceType="File", FileName, Detail=strcat(ActionType, " | ", FolderPath), AccountName=InitiatingProcessAccountName, SHA256
),
(
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice or FileName has "lazagne"
    | where FileName has "lazagne" or AttackTechniques has_any ("Credentials from Password Stores", "T1555")
    | project TimeGenerated, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", AttackTechniques), AccountName, SHA256
)
| order by TimeGenerated asc
```

## CTF Question

How do we know the tool was cleaned up after staging?

<details>
<summary>Answer Key</summary>

- Artifact: `laZagne_windows_x64.exe`
- Evidence: the file was created and later deleted.
- Lesson: cleanup does not erase telemetry.

### How The KQL Finds It

This scenario teaches file lifecycle:

1. `FileName has "lazagne"` finds all file events for the tool.
2. `project TimeGenerated, ActionType, FileName, FolderPath` keeps the lifecycle visible.
3. `order by TimeGenerated asc` shows creation before deletion.
4. Optional: `summarize Actions=make_set(ActionType) by FileName` rolls multiple rows into one answer.

Beginner checkpoint: `ActionType` is the column that tells you whether the file was created, deleted, or changed.

</details>

</details>

---

<details>
<summary><strong>10 - Dump Windows Passwords with Obfuscated Mimikatz</strong></summary>

## Story

The attacker uses a Mimikatz-style script rather than a simple `mimikatz.exe` execution. The obvious filename hunt is not enough.

## KQL Idea

When names are hidden or changed, hunt for script artifacts and Defender's credential-theft verdict.

## KQL Teaching Question

What makes the obfuscated Mimikatz query a better lesson than simply searching for `mimikatz.exe`?

<details>
<summary>KQL Answer</summary>

The behavior is represented by a PowerShell script artifact, not a direct `mimikatz.exe` process. `FileName =~ "mimikatz_dump_passwords_v2.ps1"` catches the staged script, while `Title has "Mimikatz credential theft tool"` catches Defender's behavioral verdict.

The teaching point: exact executable hunts are fragile. Combine artifact names with security product verdicts.

</details>

## Build It Slowly

Mission: catch a Mimikatz-style attack that does not show up as `mimikatz.exe`.

Start with the script artifact:

```kusto
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName has "mimikatz"
| project TimeGenerated, FileName, FolderPath, ActionType
```

Then look for Defender's verdict, not only the filename:

```kusto
AlertEvidence
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice or FileName has "mimikatz"
| where Title has "Mimikatz credential theft tool" or FileName has "mimikatz"
| project TimeGenerated, Title, Severity, FileName, SHA256
```

KQL logic to learn: when tools are renamed, obfuscated, or wrapped in scripts, alert titles and behavior labels may be better clues than process names.

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
union isfuzzy=true
(
    DeviceFileEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where FileName =~ "mimikatz_dump_passwords_v2.ps1"
    | project TimeGenerated, EvidenceType="File", FileName, Detail=strcat(ActionType, " | ", FolderPath), AccountName=InitiatingProcessAccountName, SHA256
),
(
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice or FileName =~ "mimikatz_dump_passwords_v2.ps1"
    | where FileName =~ "mimikatz_dump_passwords_v2.ps1" or Title has "Mimikatz credential theft tool"
    | project TimeGenerated, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", Severity), AccountName, SHA256
)
| order by TimeGenerated asc
```

## CTF Question

What makes this hunt different from simply looking for `mimikatz.exe`?

<details>
<summary>Answer Key</summary>

- Artifact: `mimikatz_dump_passwords_v2.ps1`
- Defender verdict: `Mimikatz credential theft tool`
- The hunt works even when the executable name is not `mimikatz.exe`.

### How The KQL Finds It

This scenario teaches students not to hunt only process names:

1. `FileName =~ "mimikatz_dump_passwords_v2.ps1"` catches the script artifact.
2. `Title has "Mimikatz credential theft tool"` catches Defender's behavior verdict.
3. `or FileName =~ ...` in the alert branch keeps the search connected to the artifact even when `DeviceName` is missing or sparse in alert evidence.

Beginner checkpoint: a Mimikatz detection can come from a script, zip, command, memory behavior, or tool verdict. Do not rely only on `mimikatz.exe`.

</details>

</details>

---

<details>
<summary><strong>11 - Dump Windows Passwords with Original Mimikatz</strong></summary>

## Story

The attacker stages the classic Mimikatz package. This is the high-confidence scenario students expect, but they should still prove it with evidence.

## KQL Idea

Use obvious file names when available, but validate with alert evidence and hashes.

## KQL Teaching Question

When the filename is obvious, why should students still project `SHA256` and alert details?

<details>
<summary>KQL Answer</summary>

An obvious filename is a clue, not full proof. Projecting `SHA256`, `Title`, and `Severity` gives students a durable indicator and the Defender verdict that explains why the artifact matters.

The teaching point: finish a hunt by producing evidence another analyst can validate: filename, hash, alert title, severity, time, and device.

</details>

## Build It Slowly

Mission: validate the classic Mimikatz artifact with a filename, alert verdict, and hash.

Start with the obvious artifact:

```kusto
DeviceFileEvents
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice
| where FileName =~ "mimikatz-x64.zip"
| project TimeGenerated, FileName, FolderPath, ActionType, SHA256
```

Then collect the evidence you would put in a report:

```kusto
AlertEvidence
| where TimeGenerated between (Start .. End)
| where DeviceName == TargetDevice or FileName =~ "mimikatz-x64.zip"
| where FileName =~ "mimikatz-x64.zip" or Title has "Mimikatz credential theft tool"
| project TimeGenerated, Title, Severity, FileName, SHA256
```

KQL logic to learn: a good hunt answer includes the thing, the verdict, the hash, the time, and the device. That is what makes it repeatable.

## Catch It

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:20:00Z);
union isfuzzy=true
(
    DeviceFileEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | where FileName =~ "mimikatz-x64.zip"
    | project TimeGenerated, EvidenceType="File", FileName, Detail=strcat(ActionType, " | ", FolderPath), AccountName=InitiatingProcessAccountName, SHA256
),
(
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice or FileName =~ "mimikatz-x64.zip"
    | where FileName =~ "mimikatz-x64.zip" or Title has "Mimikatz credential theft tool"
    | project TimeGenerated, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", Severity), AccountName, SHA256
)
| order by TimeGenerated asc
```

## CTF Question

Which Mimikatz artifact was blocked, and what hash identifies it in alert evidence?

<details>
<summary>Answer Key</summary>

- Artifact: `mimikatz-x64.zip`
- Defender verdict: `Mimikatz credential theft tool`
- Alert evidence hash: `29a3e90d067a848bac1d7301e22d6ac7b6979c89be10373b98a47845e94c45b8`

### How The KQL Finds It

This answer teaches report-ready evidence:

1. `FileName =~ "mimikatz-x64.zip"` finds the known artifact exactly.
2. `Title has "Mimikatz credential theft tool"` confirms Defender's verdict.
3. `project ... SHA256` keeps the hash in the output so another analyst can verify the exact file.
4. Time, device, filename, verdict, and hash together make a complete CTF answer.

Beginner checkpoint: a filename starts the hunt. A hash helps finish it.

</details>

</details>

---

<details>
<summary><strong>Validated Coverage Query</strong></summary>

Use this query to prove every scenario has evidence on the scoped workstation.

```kusto
let TargetDevice = "usm262346";
let Start = datetime(2026-05-04T13:10:00Z);
let End = datetime(2026-05-04T13:25:00Z);
let ProcessEvidence =
    DeviceProcessEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | project TimeGenerated, SourceTable="DeviceProcessEvents", DeviceName, FileName, FolderPath, Detail=ProcessCommandLine, Title="", AttackTechniques="";
let FileEvidence =
    DeviceFileEvents
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice
    | project TimeGenerated, SourceTable="DeviceFileEvents", DeviceName, FileName, FolderPath, Detail=strcat(ActionType, " | ", InitiatingProcessCommandLine), Title="", AttackTechniques="";
let AlertEvidenceRows =
    AlertEvidence
    | where TimeGenerated between (Start .. End)
    | where DeviceName == TargetDevice or FolderPath has_any ("AppData\\Local\\Temp\\aiq", ".ghostex-cli-wd")
    | project TimeGenerated, SourceTable="AlertEvidence", DeviceName=iff(isempty(DeviceName), TargetDevice, DeviceName), FileName, FolderPath, Detail=ProcessCommandLine, Title, AttackTechniques;
union ProcessEvidence, FileEvidence, AlertEvidenceRows
| extend EvidenceText = strcat(FileName, " ", FolderPath, " ", Detail, " ", Title, " ", AttackTechniques)
| extend Scenario = case(
    EvidenceText has "credentials_in_registry" or EvidenceText has "Credentials in Registry", "01 - Credentials In Registry Script",
    EvidenceText has "reg save hklm\\sam" or EvidenceText has "RegistryExfil", "02 - Dump SAM Registry Hive via reg save",
    EvidenceText has "collect_database_webcache" or EvidenceText has "esentutl.exe" or EvidenceText has "WebCache", "03 - Collect Browser Data via Esentutl",
    EvidenceText has "Rubeus.exe" or EvidenceText has "Kerberoasting (T1558.003)", "04 - Kerberoasting using Rubeus",
    EvidenceText has "invoke-kerberoast.ps1" or EvidenceText has "call-invoke-kerberoast.ps1", "05 - Kerberoasting using Invoke-Kerberoast",
    EvidenceText has ".dmp" or EvidenceText has "DumpLsass", "06 - Dump LSASS Process to Minidump File",
    EvidenceText has "pwdump7" or EvidenceText has "PWDump", "07 - Dump Passwords using PwDump7",
    EvidenceText has "gsecdump" or EvidenceText has "Vigorf", "08 - Dump Passwords using gsecdump",
    EvidenceText has "laZagne" or EvidenceText has "LaZagne", "09 - Dump Passwords using LaZagne",
    EvidenceText has "mimikatz_dump_passwords_v2.ps1", "10 - Dump Windows Passwords with Obfuscated Mimikatz",
    EvidenceText has "mimikatz-x64.zip", "11 - Dump Windows Passwords with Original Mimikatz",
    "Other")
| where Scenario != "Other"
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), EvidenceRows=count(), Tables=make_set(SourceTable, 5), Example=any(strcat(SourceTable, " | ", Title, " | ", FileName, " | ", Detail)) by Scenario
| order by Scenario asc
```

Expected result: all 11 scenarios appear.

</details>

## Wrap-Up Challenge

Students should answer this without help:

1. Which scenarios produced process execution evidence?
2. Which scenarios were primarily caught through `AlertEvidence`?
3. Which scenarios left file-staging artifacts?
4. Which query operator helped most: `has`, `has_any`, `has_all`, `union`, or `project`?
5. If this were a real workstation compromise, what would you investigate next?
