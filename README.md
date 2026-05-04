# AttackIQ Scenario: Security Control Baseline - Endpoint EDR

This is a Microsoft Defender XDR Advanced Hunting KQL lab built from an authorized AttackIQ `Security Control Baseline - Endpoint EDR` run. The goal is not just to copy finished queries. The goal is to think like a hunter: start with one workstation, find clues, pivot across tables, and explain what happened.

The story: a simulated attacker ran a fast credential-access sequence on one workstation. Your job is to catch each move with KQL.

## Scope

All hunts are intentionally scoped to the workstation where AttackIQ ran. This keeps the lesson realistic for a customer environment where only the test workstation is in scope. To keep the beginner queries easy, the examples use the last 7 days. Instructors can tighten the time later if needed.

```kusto
let TargetDevice = "usm262346";
```

This lab is written for Microsoft Defender XDR Advanced Hunting. The XDR tables in this lesson use `Timestamp` for time filtering:

```kusto
| where Timestamp > ago(7d)
```

## Core Tables

| Table | Why it matters |
|---|---|
| `DeviceProcessEvents` | Process execution, command lines, parent processes, initiating users. |
| `DeviceFileEvents` | Tool staging, scripts, zip files, dump files, cleanup. |
| `AlertEvidence` | Defender verdicts, prevented tools, MITRE mappings, and alert-side file hashes. Use it when the question is about Defender's interpretation. |

## Learning Objectives

- Use `let` statements to control the target workstation.
- Filter a single workstation with `DeviceName == TargetDevice`.
- Hunt process execution in `DeviceProcessEvents`.
- Hunt staged tools and cleanup in `DeviceFileEvents`.
- Use `AlertEvidence` only when the question needs Defender's verdict, prevention result, ATT&CK mapping, or alert-side hash.
- Combine evidence with `union`, `project`, `order by`, `has`, `has_any`, and `has_all`.
- Reconstruct attacker behavior from endpoint telemetry.

Each scenario follows the same learner-friendly flow:

- What happened: the attacker story in plain English.
- KQL skill: the table, column, or operator that matters.
- How to think about the query: the hunting idea before the syntax.
- Build the hunt step by step: small query pieces to run first.
- Your challenge: the question to answer from the data.
- Full answer query: the complete check-your-work query.
- Answer key: the final answer plus how the KQL found it.

In other words: understand the move, practice the move, then answer the CTF question. The challenge is not the beginning; it is where you apply what you just learned.

For every mini-query, paste the shared scope block first unless it is already included:

```kusto
let TargetDevice = "usm262346";
```

<details open>
<summary><strong>KQL 101: How To Read These Queries</strong></summary>

## KQL 101: How To Read These Queries

KQL reads from top to bottom. Think of each line as one instruction in a recipe.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has "reg save"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

How to read it:

- `DeviceProcessEvents`: start with the process table.
- `|`: pipe the rows into the next step.
- `where`: keep only rows that match a condition.
- `ago(7d)`: look back over the last 7 days.
- `==`: exact match.
- `has`: word-based search for one clue.
- `has_any`: match any clue in a list.
- `has_all`: require every clue in a list.
- `=~`: case-insensitive exact match, useful for known filenames.
- `in~`: case-insensitive match against a list of exact values.
- `endswith`: useful for extensions like `.dmp`.
- `project`: choose the columns needed for the answer.
- `summarize`: group rows into counts or rollups.
- `order by`: sort results so the story is easier to read.

Beginner habit: every answer should prove four things when possible: **when**, **where**, **what**, and **why it matters**.

</details>

<details open>
<summary><strong>Pre-CTF KQL Refresher</strong></summary>

## Pre-CTF KQL Refresher

Before the CTF starts, practice the handful of KQL moves they will use over and over. This is the warm-up gym. Keep it light, fast, and interactive.

### Query Construction Flow

Every hunt in this lab follows the same pattern:

```text
Data table -> Filter -> Analyze or pivot -> Present evidence
```

In KQL form, that usually looks like this:

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has "keyword"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

What each stage means:

| Stage | KQL move | Student question |
|---|---|---|
| Data table | `DeviceProcessEvents` | Where does this kind of evidence live? |
| Filter | `where` | How do I reduce noise? |
| Analyze or pivot | `summarize`, parent columns, hashes, alerts | What pattern or next clue appears? |
| Present evidence | `project`, `order by` | What columns prove my answer? |

Quick note: do not try to write the perfect query first. Start messy, filter down, then clean up the output.

### Refresher 1: Filtering With `where`

`where` keeps rows that match your condition. It is the most important beginner operator.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

Beginner translation:

- Start in `DeviceProcessEvents`.
- Keep only rows from the last 7 days.
- Keep only rows from `usm262346`.
- Keep only PowerShell process rows.
- Show the columns that help us explain what ran.

Common `where` patterns:

| Pattern | Example | Use it when |
|---|---|---|
| Exact match | `DeviceName == TargetDevice` | The value must match exactly. |
| Case-insensitive exact match | `FileName =~ "powershell.exe"` | You know the exact filename. |
| One keyword | `ProcessCommandLine has "reg save"` | One clue is enough. |
| Any keyword from a list | `FileName has_any ("mimikatz", "rubeus", "lazagne")` | Several clues can identify the scenario. |
| All keywords required | `ProcessCommandLine has_all ("reg save", "hklm\\sam")` | The behavior needs multiple clues together. |
| File extension | `FileName endswith ".dmp"` | The exact filename may be random. |

### Refresher 2: Choosing Columns With `project`

`project` turns noisy raw telemetry into readable evidence.

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has_any ("mimikatz", "rubeus", "lazagne")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
```

Beginner translation:

- `Timestamp`: when did it happen?
- `DeviceName`: where did it happen?
- `ActionType`: was the file created, deleted, or detected?
- `FileName` and `FolderPath`: what artifact are we talking about?
- `SHA256`: how can another analyst verify the same file?

Mini-exercise: remove `SHA256` and run the query. Add it back. Which output is more useful for an incident report?

### Refresher 3: Counting With `summarize`

`summarize` groups rows into an answer. It is perfect when the CTF asks "how many" or "which ones."

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| summarize ProcessCount=count() by FileName
| order by ProcessCount desc
```

Beginner translation:

- Look at process events on the test workstation.
- Count how many rows each `FileName` produced.
- Sort the biggest counts first.

Useful summarize patterns:

```kusto
// Count events by process
| summarize Events=count() by FileName

// Count events by file action
| summarize Events=count() by ActionType, FileName

// Show first and last time seen
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by FileName

// Collect all actions seen for one file
| summarize Actions=make_set(ActionType) by FileName
```

Mini-exercise: use `summarize` to answer, "Which file action happened most often during the AttackIQ run?"

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| summarize Events=count() by ActionType
| order by Events desc
```

### Refresher 4: Sorting With `order by`

`order by` turns results into a story. For timelines, sort oldest to newest.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

Beginner translation:

- `asc` means ascending: oldest first.
- `desc` means descending: newest or largest first.
- Use `asc` for timelines.
- Use `desc` for counts and top talkers.

### Refresher 5: Pivoting Like A Hunter

A pivot means: take one clue from your first result and use it in the next query.

Example flow:

```text
Find suspicious file -> copy filename -> search alerts -> copy hash -> search file events
```

KQL example:

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "rubeus"
| project Timestamp, FileName, FolderPath, SHA256
```

Then pivot into alert evidence:

```kusto
AlertEvidence
| where Timestamp > ago(7d)
| where FileName has "rubeus" or SHA256 == "1e1fe8a1730bf8caabd867fd2f990b0e52aee0f9f8635578ff8b18c0950b616c"
| project Timestamp, Title, FileName, AttackTechniques, SHA256
```

Quick note: one good clue should create the next query.

### Refresher 6: Combining Tables With `union`

Sometimes the answer is split across tables. `union` stacks results together.

```kusto
union isfuzzy=true
(
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
    | where FileName has_any ("pwdump", "gsecdump", "lazagne")
    | project Timestamp, EvidenceType="File", Detail=strcat(ActionType, " | ", FileName)
),
(
    AlertEvidence
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice or FileName has_any ("pwdump", "gsecdump", "lazagne")
    | project Timestamp, EvidenceType="Alert", Detail=strcat(Title, " | ", FileName)
)
| order by Timestamp asc
```

Beginner translation:

- First branch: file evidence.
- Second branch: alert evidence.
- `project` makes both branches output the same columns.
- `order by` turns the combined result into a timeline.

Mini-exercise: add `"mimikatz"` to both `has_any` lists. What new evidence appears?

### Pre-CTF Practice Round

Before opening Scenario 01, answer these quick questions:

1. Which table shows process command lines?
2. Which table shows files created or deleted?
3. Which table shows Defender alert titles and ATT&CK techniques?
4. Which operator would you use for an exact workstation match?
5. Which operator would you use when either `mimikatz`, `rubeus`, or `lazagne` should match?
6. Which operator would you use when both `reg save` and `hklm\sam` must be present?

<details>
<summary>Pre-CTF Practice Answers</summary>

1. `DeviceProcessEvents`
2. `DeviceFileEvents`
3. `AlertEvidence`
4. `==`
5. `has_any`
6. `has_all`

</details>

</details>

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

<details>
<summary><strong>Instructor Notes: How To Run The Session</strong></summary>

## Instructor Notes

Use the incident only as an optional story hook. Do not make the class depend on a specific incident ID, because the customer tenant may group the AttackIQ activity differently or may not have the same incident at all.

Recommended teaching flow:

1. Start with **KQL 101** and the **Pre-CTF KQL Refresher**.
2. Set the shared target device variable.
3. Run the warm-up timeline so students see the activity cluster.
4. Open each scenario in order.
5. Have students run **Build The Hunt Step By Step** first.
6. Ask **Your Challenge**.
7. Use **Full Answer Query** only when students need a nudge or want to check their work.
8. Open **Answer Key** last.

What to say if students get lost:

- "Which table should have this evidence: process, file, or alert?"
- "Which column tells us the command?"
- "Which column tells us the Defender verdict?"
- "Can we reduce noise with `where DeviceName == TargetDevice`?"
- "Can we prove when, where, what, and why it matters?"

Time guidance:

- Student queries use `Timestamp > ago(7d)` to keep things simple.
- The original validation window was `2026-05-04T13:10:00Z` to `2026-05-04T13:20:00Z`.
- If the class has too many rows, tighten the time filter during delivery.

Example tighter filter:

```kusto
| where Timestamp between (datetime(2026-05-04T13:10:00Z) .. datetime(2026-05-04T13:20:00Z))
```

</details>

<details>
<summary><strong>Optional Instructor Pivot: If The Customer Has An XDR Incident</strong></summary>

## Optional XDR Incident Pivot

Use this only if the customer has an incident that clearly contains the AttackIQ run. If not, skip it. The lab still works because every scenario is based on endpoint telemetry in Advanced Hunting.

Why it is optional:

- Incident IDs are tenant-specific.
- Alert grouping can vary by tenant, policy, product, and timing.
- Some scenarios are prevented before they produce a clean process row, so the incident may show only part of the story.
- The safest student path is still: target workstation -> endpoint tables -> evidence.

If you do have an incident, use it as a launch point:

1. Open the XDR incident in the portal.
2. Note the affected device, user, alert titles, and rough time range.
3. Confirm the target device matches the lab workstation.
4. Pivot from the incident into Advanced Hunting.
5. Continue with the same scenario flow in this guide.

Optional query when `IncidentId` is available in your XDR hunting schema:

```kusto
let IncidentIdToReview = "PUT-INCIDENT-ID-HERE";
AlertInfo
| where Timestamp > ago(7d)
| where IncidentId == IncidentIdToReview
| project Timestamp, IncidentId, AlertId, Title, Severity, ServiceSource, DetectionSource, AttackTechniques
| order by Timestamp asc
```

Pivot from incident alerts to evidence:

```kusto
let IncidentIdToReview = "PUT-INCIDENT-ID-HERE";
let IncidentAlerts =
    AlertInfo
    | where Timestamp > ago(7d)
    | where IncidentId == IncidentIdToReview
    | project AlertId, IncidentId, AlertTitle=Title, Severity;
IncidentAlerts
| join kind=inner (
    AlertEvidence
    | where Timestamp > ago(7d)
) on AlertId
| project Timestamp, IncidentId, AlertTitle, Severity, EntityType, DeviceName, FileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

Instructor note: if the incident query does not return results, do not troubleshoot the incident during class. Move back to the device-scoped scenario queries and say: "Incidents are a helpful doorway, but endpoint telemetry is the ground truth for this lab."

</details>

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
| 06 | Dump LSASS Process to Minidump File | `DeviceFileEvents`, optional `AlertEvidence` pivot |
| 07 | Dump Passwords using PwDump7 | `DeviceFileEvents`, `AlertEvidence` |
| 08 | Dump Passwords using gsecdump | `DeviceFileEvents`, `AlertEvidence` |
| 09 | Dump Passwords using LaZagne | `DeviceFileEvents`, `AlertEvidence` |
| 10 | Dump Windows Passwords with Obfuscated Mimikatz | `DeviceFileEvents`, optional `AlertEvidence` pivot |
| 11 | Dump Windows Passwords with Original Mimikatz | `DeviceFileEvents`, `AlertEvidence` |

---

<details open>
<summary><strong>00 - Warm-Up: Rebuild the Attack Timeline</strong></summary>

## What Happened

Before chasing individual scenarios, rebuild the attacker timeline. This shows why one table rarely tells the whole story.

## KQL Skill

`let`, `union`, `project`, `order by`, workstation scoping.

## How To Think About The Query

Why does this warm-up use `union isfuzzy=true` instead of querying only one table?

<details>
<summary>Break Down The KQL</summary>

Endpoint investigations usually need more than one evidence type. `DeviceProcessEvents` shows execution, `DeviceFileEvents` shows staged or deleted files, and `AlertEvidence` shows Defender verdicts. `union isfuzzy=true` lets you combine those tables even when the projected columns are not identical across every source.

Why this matters: use `project` inside each branch to normalize the output columns, then `order by Timestamp asc` to turn separate tables into one readable timeline.

</details>

## Build The Hunt Step By Step

Start with the question: "What happened on this one computer during the test window?"

The beginner mistake is to search the whole tenant first. The better habit is to scope early:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| take 20
```

Now shape the rows into a timeline. A timeline needs a time column, an evidence type, and a detail column:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| project Timestamp, EvidenceType="Process", Detail=ProcessCommandLine
| order by Timestamp asc
```

Checkpoint: Which column tells you when it happened? Which column tells you what command ran?

## Your Challenge

What launched the attack, what account ran it, and where did the AttackIQ runtime unpack itself?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
    | where ProcessCommandLine has_any (".ghostex-cli", "AppData\\Local\\Temp\\aiq", "reg save", "esentutl", "credentials_in_registry", "collect_database_webcache")
    | project Timestamp, EvidenceType="Process", Action=FileName,
              Detail=ProcessCommandLine, Source=InitiatingProcessCommandLine
),
(
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
    | where FolderPath has_any (".ghostex-cli", "AppData\\Local\\Temp\\aiq")
    | where FileName has_any ("mimikatz", "lazagne", "gsecdump", "pwdump", "rubeus", "kerberoast", "credential", "webcache")
       or FileName endswith ".dmp"
    | project Timestamp, EvidenceType="File", Action=ActionType,
              Detail=strcat(FolderPath, "\\", FileName), Source=InitiatingProcessCommandLine
),
(
    AlertEvidence
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
       or FileName has_any ("mimikatz", "lazagne", "gsecdump", "pwdump", "rubeus", "kerberoast", "credentials_in_registry")
    | project Timestamp, EvidenceType="Alert", Action=Title,
              Detail=strcat(EntityType, " | ", FileName, " | ", ProcessCommandLine), Source=ServiceSource
)
| order by Timestamp asc
```


<details>
<summary>Full Answer And Explanation</summary>

- Launcher: `SecBase_security-control-baseline-endpoint-edr_V1_0_51_amd64_gui-sig.exe`
- Account: `xadmin`
- Runtime path: `C:\Users\xadmin\Downloads\.ghostex-cli-wd-2170286878`
- Main orchestrator: `python.exe` running `attack_graph.py`

### How The KQL Finds It

Read the warm-up query like this:

1. `DeviceProcessEvents` looks for commands that ran.
2. `DeviceFileEvents` looks for tools and scripts that appeared on disk.
3. `AlertEvidence` looks for Defender's security interpretation.
4. Each branch uses `project` to rename different columns into the same story columns: `Timestamp`, `EvidenceType`, `Action`, `Detail`, and `Source`.
5. `order by Timestamp asc` turns all three evidence types into one timeline.

Checkpoint: when you see `union`, ask, "What tables are being combined, and did we make their output columns match?"

</details>

</details>

---

<details>
<summary><strong>01 - Credentials In Registry Script</strong></summary>

## What Happened

The attacker tries to abuse the registry as a place where credential material can live. The task is to find the script, prove it ran, and connect it to Defender's ATT&CK mapping.

## KQL Skill

Start with a file or script name, then pivot into alert evidence.

## How To Think About The Query

When you know the suspicious script name, which KQL pattern helps you prove both file staging and Defender detection?

<details>
<summary>Break Down The KQL</summary>

Use the script name as the anchor in more than one table. In this scenario, `FileName =~ "credentials_in_registry.ps1"` finds the staged file, while `AttackTechniques has_any ("Credentials in Registry", "T1552.002")` connects the behavior to the Defender/ATT&CK context.

Why this matters: `=~` is a case-insensitive exact match, which is good when the filename is known. `has_any` is better for matching one of several alert or technique clues.

</details>

## Build The Hunt Step By Step

Mission: find a PowerShell script related to credentials in the registry.

First, find where script file activity lives:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "credentials_in_registry.ps1"
| project Timestamp, FileName, FolderPath, ActionType
```

Then pivot from file evidence to security meaning:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName =~ "credentials_in_registry.ps1"
| project Timestamp, Title, AttackTechniques, FileName
```

KQL logic to learn: use exact filename matching when the artifact name is known, then use `project` to keep only the columns that answer the CTF question.

## Your Challenge

Which script is the registry-creds clue, and which ATT&CK technique did Defender attach to it?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName =~ "credentials_in_registry.ps1"
| where Title has_any ("PowerShell", "Registry", "Credentials")
   or AttackTechniques has_any ("Credentials in Registry", "T1552.002")
| project Timestamp, Title, FileName, AttackTechniques, SHA256
| order by Timestamp asc
```


<details>
<summary>Full Answer And Explanation</summary>

- Script: `credentials_in_registry.ps1`
- Alert: `A malicious PowerShell Cmdlet was invoked on the machine`
- ATT&CK: `Credentials in Registry (T1552.002)`

### How The KQL Finds It

The answer comes from a focused alert-evidence query:

1. `FileName =~ "credentials_in_registry.ps1"` keeps the known script artifact connected to the alert.
2. `Title has_any (...)` catches Defender's PowerShell and credential wording.
3. `AttackTechniques has_any ("Credentials in Registry", "T1552.002")` explains why Defender cared.

Checkpoint: `FileName` tells you what the artifact was. `Title` and `AttackTechniques` tell you why it matters.

</details>

</details>

---

<details>
<summary><strong>02 - Dump SAM Registry Hive via reg save</strong></summary>

## What Happened

The attacker tries to copy the local SAM registry hive. The command line is the clue.

## KQL Skill

Use `has_all` when multiple terms must appear together in the same command line.

## How To Think About The Query

Why is `has_all ("reg save", "hklm\\sam")` stronger than only searching for `reg` or `sam`?

<details>
<summary>Break Down The KQL</summary>

`reg` by itself is too broad, and `sam` by itself can appear in unrelated paths or names. `has_all` requires both clues to exist in the same command line, which makes the result much closer to the real behavior: saving the SAM registry hive.

Why this matters: use `has_all` when the detection idea depends on a combination of words, not just one keyword.

</details>

## Build The Hunt Step By Step

Mission: find a command that saved the local SAM registry hive.

Start broad enough to see command lines for `cmd.exe`:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "cmd.exe"
| project Timestamp, FileName, ProcessCommandLine
```

Now add the required behavior terms:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has_all ("reg save", "hklm\\sam")
| project Timestamp, ProcessCommandLine, AccountName
```

KQL logic to learn: `has_all` is for "both of these clues must be present." That is different from `has_any`, where only one clue has to match.

## Your Challenge

Where did the attacker try to save the SAM hive?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_all ("reg save", "hklm\\sam")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```


<details>
<summary>Full Answer And Explanation</summary>

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

Then `project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine` keeps the columns needed to answer: when it happened, where it happened, who ran it, which process ran, and the exact command.

</details>

</details>

---

<details>
<summary><strong>03 - Browser Data via Esentutl and PowerShell</strong></summary>

## What Happened

The attacker goes after browser/WebCache data. PowerShell starts the script, and `esentutl.exe` does the database work.

## KQL Skill

Follow parent and child process relationships with `InitiatingProcessCommandLine`.

## How To Think About The Query

How does KQL show that `esentutl.exe` was part of the PowerShell browser-data collection chain?

<details>
<summary>Break Down The KQL</summary>

Query both `FileName` and `InitiatingProcessCommandLine`. `FileName in~ ("powershell.exe", "esentutl.exe")` catches the parent and child process names, while `InitiatingProcessCommandLine has "collect_database_webcache.ps1"` ties the child process back to the script that launched it.

Why this matters: parent process fields are pivot fields. They explain why a normal Windows binary appeared in the timeline.

</details>

## Build The Hunt Step By Step

Mission: prove that browser/WebCache collection happened and show the parent-child process chain.

First, find the two process names that matter:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName in~ ("powershell.exe", "esentutl.exe")
| project Timestamp, FileName, ProcessCommandLine
```

Then add the parent process columns:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "esentutl.exe"
| project Timestamp, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

KQL logic to learn: `InitiatingProcessFileName` and `InitiatingProcessCommandLine` answer "who launched this?"

## Your Challenge

Which process launched `esentutl.exe`, and what browser/cache path was targeted?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName in~ ("powershell.exe", "esentutl.exe")
| where ProcessCommandLine has_any ("collect_database_webcache.ps1", "esentutl", "WebCache")
   or InitiatingProcessCommandLine has "collect_database_webcache.ps1"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName, SHA256
| order by Timestamp asc
```


<details>
<summary>Full Answer And Explanation</summary>

- Parent process: `powershell.exe`
- Script: `collect_database_webcache.ps1`
- Child process: `esentutl.exe`
- Target path includes `C:\Users\xadmin\AppData\Local\Microsoft\Windows\WebCache`

### How The KQL Finds It

This answer is about parent and child process thinking:

1. `FileName in~ ("powershell.exe", "esentutl.exe")` keeps the two process names that matter.
2. `ProcessCommandLine has_any (...)` finds direct command-line clues like `WebCache`.
3. `InitiatingProcessCommandLine has "collect_database_webcache.ps1"` shows what launched the child process.
4. `project ... InitiatingProcessFileName, InitiatingProcessCommandLine` keeps the parent process evidence visible.

Checkpoint: `FileName` is the process itself. `InitiatingProcessFileName` is the process that started it.

</details>

</details>

---

<details>
<summary><strong>04 - Kerberoasting Using Rubeus</strong></summary>

## What Happened

The attacker stages Rubeus for Kerberoasting. Defender interrupts the move, but the staged file and alert evidence prove what happened.

## KQL Skill

A blocked tool may not produce a clean process execution row. Hunt file staging and `AlertEvidence`.

## How To Think About The Query

If Defender blocks a tool before normal execution telemetry appears, which tables should you query first?

<details>
<summary>Break Down The KQL</summary>

Start with `DeviceFileEvents` and `AlertEvidence`. `DeviceFileEvents` can show that `Rubeus.exe` was staged on disk. `AlertEvidence` can show the Defender verdict and ATT&CK mapping even if there is no clean `DeviceProcessEvents` execution row.

Why this matters: absence of process execution is not absence of activity. Blocked tools often leave stronger evidence in file and alert tables.

</details>

## Build The Hunt Step By Step

Mission: catch Rubeus even if Defender blocked it before normal execution.

Start with file staging:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "Rubeus.exe"
| project Timestamp, FileName, FolderPath, ActionType, SHA256
```

Then ask Defender what it thought the file meant:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName =~ "Rubeus.exe"
| project Timestamp, Title, AttackTechniques, FileName, SHA256
```

KQL logic to learn: when the process table is quiet, check file and alert tables before deciding nothing happened.

## Your Challenge

What file name and hash identify the Rubeus attempt?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
union isfuzzy=true
(
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
    | where FileName =~ "Rubeus.exe"
    | project Timestamp, EvidenceType="File", FileName, Detail=strcat(ActionType, " | ", FolderPath), AccountName=InitiatingProcessAccountName, SHA256
),
(
    AlertEvidence
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice or FileName =~ "Rubeus.exe"
    | where FileName =~ "Rubeus.exe" or AttackTechniques has_any ("Kerberoasting", "T1558.003")
    | project Timestamp, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", AttackTechniques), AccountName, SHA256
)
| order by Timestamp asc
```


<details>
<summary>Full Answer And Explanation</summary>

- File: `Rubeus.exe`
- Hash: `1e1fe8a1730bf8caabd867fd2f990b0e52aee0f9f8635578ff8b18c0950b616c`
- ATT&CK: `Kerberoasting (T1558.003)`

### How The KQL Finds It

This scenario teaches that blocked tools may be easier to find in file and alert tables:

1. `DeviceFileEvents` plus `FileName =~ "Rubeus.exe"` proves the tool was staged.
2. `AlertEvidence` plus `AttackTechniques has_any ("Kerberoasting", "T1558.003")` proves the behavior category.
3. `SHA256` gives a durable identifier for the exact file.

Checkpoint: if `DeviceProcessEvents` is quiet, do not stop. Check `DeviceFileEvents` and `AlertEvidence`.

</details>

</details>

---

<details>
<summary><strong>05 - PowerShell Empire Invoke-Kerberoast</strong></summary>

## What Happened

The attacker switches from a standalone executable to a PowerShell Kerberoasting script.

## KQL Skill

Hunt script staging first, then pivot to alert evidence and ATT&CK context.

## How To Think About The Query

Why does this query use `FileName has_any ("invoke-kerberoast", "call-invoke-kerberoast")` instead of an exact filename match?

<details>
<summary>Break Down The KQL</summary>

This scenario stages more than one related PowerShell file. `has_any` lets the query catch both the wrapper script and the main Kerberoast script without writing separate filters for each filename.

Why this matters: use `has_any` when a scenario may have several related artifact names and any one of them is enough to include the row.

</details>

## Build The Hunt Step By Step

Mission: find the PowerShell Kerberoasting files.

Start by searching for the family name, not one exact file:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "kerberoast"
| project Timestamp, FileName, FolderPath, ActionType
```

Then tighten the logic to the expected pair of files:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has_any ("invoke-kerberoast", "call-invoke-kerberoast")
| project Timestamp, FileName, FolderPath, ActionType
```

KQL logic to learn: `has` is good for one clue. `has_any` is good when several related clue words can identify the same scenario.

## Your Challenge

Which two PowerShell files were staged for the Kerberoasting test?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has_any ("invoke-kerberoast", "call-invoke-kerberoast")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Actions=make_set(ActionType) by FileName, FolderPath, SHA256
| order by FileName asc
```


<details>
<summary>Full Answer And Explanation</summary>

- `call-invoke-kerberoast.ps1`
- `invoke-kerberoast.ps1`
- Defender generated detections tied to `invoke-kerberoast.ps1`.

### How The KQL Finds It

The query uses a list because there are two related script names:

```kusto
| where FileName has_any ("invoke-kerberoast", "call-invoke-kerberoast")
```

Read it as: keep rows where the filename has either of those terms. That is useful when a scenario uses a launcher script and a payload script.

Then `summarize` rolls multiple file events into one row per file, showing first seen, last seen, and which file actions occurred.

Checkpoint: `has_any` is for "any one of these clues is enough."

</details>

</details>

---

<details>
<summary><strong>06 - LSASS Minidump</strong></summary>

## What Happened

The attacker tries to dump LSASS. A dump file lands in temp and Defender raises a `DumpLsass` prevention alert.

## KQL Skill

Dump files are investigation gold. Hunt for `.dmp`, then optionally pivot to alert evidence for the ATT&CK mapping.

## How To Think About The Query

How can you find LSASS dump behavior even if the dump filename is random?

<details>
<summary>Break Down The KQL</summary>

Look for file patterns and alert semantics instead of relying on one exact filename. `FileName endswith ".dmp"` catches dump files, while `Title has_any ("DumpLsass", "LSASS")` and `AttackTechniques has_any ("LSASS Memory", "T1003.001")` catch the Defender interpretation.

Why this matters: random filenames are common, so hunt on file extension, path pattern, alert title, and ATT&CK technique.

</details>

## Build The Hunt Step By Step

Mission: catch LSASS dumping even when the dump filename is not predictable.

Start with the most beginner-friendly clue: dump files end in `.dmp`.

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName endswith ".dmp"
| project Timestamp, FileName, FolderPath, ActionType
```

Then connect the file to the detection language:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where Title has_any ("DumpLsass", "LSASS")
| project Timestamp, Title, AttackTechniques, ProcessCommandLine
```

KQL logic to learn: use `endswith` for extensions and use alert titles to translate a suspicious file into attacker behavior.

## Your Challenge

What dump file was created, and what ATT&CK sub-technique did the alert map to?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName endswith ".dmp" or FolderPath has "pid_"
| project Timestamp, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```


<details>
<summary>Full Answer And Explanation</summary>

- Dump file: `pid_976_2ztj_d6a.dmp`
- Alert: `An active 'DumpLsass' hacktool in a command line was prevented from executing`
- ATT&CK: `LSASS Memory (T1003.001)`

### How The KQL Finds It

This scenario teaches pattern hunting when filenames are random:

1. `FileName endswith ".dmp"` finds dump files without knowing the full filename.
2. `FolderPath has "pid_"` catches the AttackIQ-style dump path pattern.
3. `project Timestamp, ActionType, FileName, FolderPath, SHA256` keeps the file evidence readable.
4. The step-by-step `AlertEvidence` query provides the ATT&CK mapping: `LSASS Memory (T1003.001)`.

Checkpoint: random names require pattern logic. Extensions, folders, titles, and ATT&CK fields are all clues.

</details>

</details>

---

<details>
<summary><strong>07 - Dump Passwords Using PwDump7</strong></summary>

## What Happened

The attacker stages PwDump7. Defender prevents the hacktool, but you can still prove the attempted credential dump.

## KQL Skill

Use `AlertEvidence` to read the prevention verdict, then shape that verdict with `extend`.

## How To Think About The Query

What KQL evidence tells you the PwDump scenario was attempted but prevented?

<details>
<summary>Break Down The KQL</summary>

Use `AlertEvidence` when the important question is outcome. `Title has "PWDump"` finds Defender's prevention verdict, and `extend` can turn that wording into a simple `Outcome` column.

Why this matters: a prevented attack still produces useful telemetry. Read `Title`, `Severity`, `Outcome`, and `FileName` together.

</details>

## Build The Hunt Step By Step

Mission: prove PwDump was attempted and explain whether it ran or was blocked.

First, search file evidence with a simple keyword:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "pwdump"
| project Timestamp, FileName, FolderPath, ActionType
```

Then search the alert wording:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName has "pwdump"
| where FileName has "pwdump" or Title has "PWDump"
| project Timestamp, Title, Severity, FileName
```

KQL logic to learn: `Title` often tells you the outcome. Words like `prevented` or `blocked` change the story from execution to attempted execution.

## Your Challenge

Was PwDump executed cleanly, or was it prevented? What tells you?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName has "pwdump"
| where Title has "PWDump" or FileName has "pwdump"
| extend Outcome = iff(Title has "prevented", "Prevented", "Review")
| project Timestamp, Outcome, Title, Severity, FileName, SHA256
| order by Timestamp asc
```


<details>
<summary>Full Answer And Explanation</summary>

- Artifact: `pwdump7.zip`
- Defender alert: `'PWDump' hacktool was prevented`
- It was prevented, but the attempt is still visible.

### How The KQL Finds It

The answer comes from comparing file evidence with alert evidence:

1. `AlertEvidence | where Title has "PWDump"` finds Defender's verdict.
2. `extend Outcome = iff(...)` turns the alert wording into a simple outcome column.
3. `project Timestamp, Outcome, Title, Severity, FileName, SHA256` keeps the result readable.

The word `prevented` in the alert title matters. It tells you this was an attempted credential dump, not clean execution.

Checkpoint: the security outcome is usually in `Title`, not just `FileName`.

</details>

</details>

---

<details>
<summary><strong>08 - Dump Passwords Using gsecdump</strong></summary>

## What Happened

The attacker stages `gsecdump`. Defender does not necessarily call it by that exact name, which is the point of the lesson.

## KQL Skill

Tool names and detection names do not always match. Hunt both the staged file name and alert title.

## How To Think About The Query

Why should the query search for both `gsecdump` and `Vigorf`?

<details>
<summary>Break Down The KQL</summary>

The tool name and the detection name are not always the same. `FileName has "gsecdump"` finds the staged artifact, while `Title has_any ("Vigorf", "malware")` catches how Defender classified the threat.

Why this matters: do not assume the alert title will repeat the tool name. Pair artifact terms with detection-family terms.

</details>

## Build The Hunt Step By Step

Mission: connect the staged `gsecdump` artifact to Defender's different detection name.

Start with the tool name:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "gsecdump"
| project Timestamp, FileName, FolderPath, ActionType
```

Then search alert evidence with both artifact and detection-family terms:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName has "gsecdump"
| where FileName has "gsecdump" or Title has "Vigorf"
| project Timestamp, Title, Severity, FileName
```

KQL logic to learn: one table may show the attacker tool name while another table shows the security product's malware family name.

## Your Challenge

What did Defender call the threat, and what was the actual staged file name?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName has "gsecdump"
| where FileName has "gsecdump" or Title has "Vigorf"
| project Timestamp, Title, Severity, FileName, SHA256
| order by Timestamp asc
```


<details>
<summary>Full Answer And Explanation</summary>

- Staged file: `gsecdump-0.7-win32.zip`
- Defender alert: `'Vigorf' malware was prevented`

### How The KQL Finds It

This is a naming lesson:

1. `FileName has "gsecdump"` finds what AttackIQ staged.
2. `Title has "Vigorf"` finds what Defender called it.
3. Seeing both in the same time window connects the artifact name to the detection name.

Checkpoint: do not expect the alert title to repeat your search term. Defender may use a malware family or detection family name.

</details>

</details>

---

<details>
<summary><strong>09 - Dump Passwords Using LaZagne</strong></summary>

## What Happened

The attacker stages LaZagne, a credential recovery tool. It appears and then gets cleaned up.

## KQL Skill

Use file events to catch both `FileCreated` and `FileDeleted` for the same suspicious artifact.

## How To Think About The Query

How can KQL show that LaZagne was staged and then cleaned up?

<details>
<summary>Break Down The KQL</summary>

Query `DeviceFileEvents` for `FileName has "lazagne"`, then keep `ActionType` in the projected output. Seeing both creation and deletion actions for the same artifact shows the tool lifecycle.

Why this matters: include `ActionType` when hunting file artifacts. The action tells the story, not just the filename.

</details>

## Build The Hunt Step By Step

Mission: show that LaZagne appeared on disk and was later removed.

Start by finding every LaZagne file event:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| project Timestamp, FileName, ActionType, FolderPath
| order by Timestamp asc
```

Then summarize the lifecycle:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| summarize Actions=make_set(ActionType), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by FileName
```

KQL logic to learn: `summarize` turns many rows into one answer. `make_set(ActionType)` shows all actions seen for the file.

## Your Challenge

How do we know the tool was cleaned up after staging?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| summarize Actions=make_set(ActionType), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Paths=make_set(FolderPath) by FileName, SHA256
| order by FirstSeen asc
```


<details>
<summary>Full Answer And Explanation</summary>

- Artifact: `laZagne_windows_x64.exe`
- Evidence: the file was created and later deleted.
- Lesson: cleanup does not erase telemetry.

### How The KQL Finds It

This scenario teaches file lifecycle:

1. `FileName has "lazagne"` finds all file events for the tool.
2. `project Timestamp, ActionType, FileName, FolderPath` keeps the lifecycle visible.
3. `order by Timestamp asc` shows creation before deletion.
4. `summarize Actions=make_set(ActionType)` rolls multiple rows into one answer.

Checkpoint: `ActionType` is the column that tells you whether the file was created, deleted, or changed.

</details>

</details>

---

<details>
<summary><strong>10 - Dump Windows Passwords with Obfuscated Mimikatz</strong></summary>

## What Happened

The attacker uses a Mimikatz-style script rather than a simple `mimikatz.exe` execution. The obvious filename hunt is not enough.

## KQL Skill

When names are hidden or changed, hunt for script artifacts first. Pivot to Defender's verdict only after the artifact is found.

## How To Think About The Query

What makes the obfuscated Mimikatz query a better lesson than simply searching for `mimikatz.exe`?

<details>
<summary>Break Down The KQL</summary>

The behavior is represented by a PowerShell script artifact, not a direct `mimikatz.exe` process. `FileName =~ "mimikatz_dump_passwords_v2.ps1"` catches the staged script, while `Title has "Mimikatz credential theft tool"` catches Defender's behavioral verdict.

Why this matters: exact executable hunts are fragile. Combine artifact names with security product verdicts.

</details>

## Build The Hunt Step By Step

Mission: catch a Mimikatz-style attack that does not show up as `mimikatz.exe`.

Start with the script artifact:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "mimikatz"
| project Timestamp, FileName, FolderPath, ActionType
```

Then look for Defender's verdict, not only the filename:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName has "mimikatz"
| where Title has "Mimikatz credential theft tool" or FileName has "mimikatz"
| project Timestamp, Title, Severity, FileName, SHA256
```

KQL logic to learn: when tools are renamed, obfuscated, or wrapped in scripts, alert titles and behavior labels may be better clues than process names.

## Your Challenge

What makes this hunt different from simply looking for `mimikatz.exe`?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "mimikatz_dump_passwords_v2.ps1"
| project Timestamp, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```


<details>
<summary>Full Answer And Explanation</summary>

- Artifact: `mimikatz_dump_passwords_v2.ps1`
- Defender verdict: `Mimikatz credential theft tool`
- The hunt works even when the executable name is not `mimikatz.exe`.

### How The KQL Finds It

This scenario teaches why process names are not enough:

1. `FileName =~ "mimikatz_dump_passwords_v2.ps1"` catches the script artifact.
2. `DeviceFileEvents` shows the suspicious script even when there is no `mimikatz.exe` process name to search for.
3. The step-by-step `AlertEvidence` query catches Defender's behavior verdict after the artifact is found.

Checkpoint: a Mimikatz detection can come from a script, zip, command, memory behavior, or tool verdict. Do not rely only on `mimikatz.exe`.

</details>

</details>

---

<details>
<summary><strong>11 - Dump Windows Passwords with Original Mimikatz</strong></summary>

## What Happened

The attacker stages the classic Mimikatz package. This is the obvious Mimikatz scenario, but you still need to prove it with evidence.

## KQL Skill

Use obvious file names when available, but validate with alert evidence and hashes.

## How To Think About The Query

When the filename is obvious, why should you still project `SHA256` and alert details?

<details>
<summary>Break Down The KQL</summary>

An obvious filename is a clue, not full proof. Projecting `SHA256`, `Title`, and `Severity` gives you a durable indicator and the Defender verdict that explains why the artifact matters.

Why this matters: finish a hunt by producing evidence another analyst can validate: filename, hash, alert title, severity, time, and device.

</details>

## Build The Hunt Step By Step

Mission: validate the classic Mimikatz artifact with a filename, alert verdict, and hash.

Start with the obvious artifact:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "mimikatz-x64.zip"
| project Timestamp, FileName, FolderPath, ActionType, SHA256
```

Then collect the evidence you would put in a report:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName =~ "mimikatz-x64.zip"
| where FileName =~ "mimikatz-x64.zip" or Title has "Mimikatz credential theft tool"
| project Timestamp, Title, Severity, FileName, SHA256
```

KQL logic to learn: a good hunt answer includes the thing, the verdict, the hash, the time, and the device. That is what makes it repeatable.

## Your Challenge

Which Mimikatz artifact was blocked, and what hash identifies it in alert evidence?

Use the step-by-step queries first. After you have an answer, compare it with the full answer query and answer key below.

## Full Answer Query

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName =~ "mimikatz-x64.zip"
| where FileName =~ "mimikatz-x64.zip" or Title has "Mimikatz credential theft tool"
| project Timestamp, DeviceName, Title, Severity, FileName, SHA256
| order by Timestamp asc
```


<details>
<summary>Full Answer And Explanation</summary>

- Artifact: `mimikatz-x64.zip`
- Defender verdict: `Mimikatz credential theft tool`
- Alert evidence hash: `29a3e90d067a848bac1d7301e22d6ac7b6979c89be10373b98a47845e94c45b8`

### How The KQL Finds It

This answer teaches report-ready evidence:

1. `FileName =~ "mimikatz-x64.zip"` finds the known artifact exactly.
2. `Title has "Mimikatz credential theft tool"` confirms Defender's verdict.
3. `project ... SHA256` keeps the hash in the output so another analyst can verify the exact file.
4. Time, device, filename, verdict, and hash together make a complete CTF answer.

Checkpoint: a filename starts the hunt. A hash helps finish it.

</details>

</details>

---

<details>
<summary><strong>Validated Coverage Query</strong></summary>

Use this query to prove every scenario has evidence on the scoped workstation.

```kusto
let TargetDevice = "usm262346";
let ProcessEvidence =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
    | project Timestamp, SourceTable="DeviceProcessEvents", DeviceName, FileName, FolderPath, Detail=ProcessCommandLine, Title="", AttackTechniques="";
let FileEvidence =
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
    | project Timestamp, SourceTable="DeviceFileEvents", DeviceName, FileName, FolderPath, Detail=strcat(ActionType, " | ", InitiatingProcessCommandLine), Title="", AttackTechniques="";
let AlertEvidenceRows =
    AlertEvidence
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice or FolderPath has_any ("AppData\\Local\\Temp\\aiq", ".ghostex-cli-wd")
    | project Timestamp, SourceTable="AlertEvidence", DeviceName=iff(isempty(DeviceName), TargetDevice, DeviceName), FileName, FolderPath, Detail=ProcessCommandLine, Title, AttackTechniques;
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
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), EvidenceRows=count(), Tables=make_set(SourceTable, 5), Example=any(strcat(SourceTable, " | ", Title, " | ", FileName, " | ", Detail)) by Scenario
| order by Scenario asc
```

Expected result: all 11 scenarios appear.

</details>

## Wrap-Up Challenge

Answer these without the full query first:

1. Which scenarios produced process execution evidence?
2. Which scenarios were primarily caught through `AlertEvidence`?
3. Which scenarios left file-staging artifacts?
4. Which query operator helped most: `has`, `has_any`, `has_all`, `union`, or `project`?
5. If this were a real workstation compromise, what would you investigate next?
