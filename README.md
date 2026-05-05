# AttackIQ Scenario: Security Control Baseline - Endpoint EDR

Microsoft Defender XDR Advanced Hunting lab for an authorized AttackIQ `Security Control Baseline - Endpoint EDR` run. The story is simple: a simulated attacker ran credential-access activity on one workstation, and your job is to catch each move with KQL.

Use this target device in every scenario:

```kusto
let TargetDevice = "usm262346";
```

<details>
<summary><strong>Quick Reference: Scope, Tables, And Flow</strong></summary>

## Scope

- Product: Microsoft Defender XDR Advanced Hunting.
- Target workstation: `usm262346`.
- Beginner time filter: `Timestamp > ago(7d)`.
- Time column: `Timestamp`.

```kusto
| where Timestamp > ago(7d)
```

## Core Tables

| Table | Why it matters |
|---|---|
| `DeviceProcessEvents` | Process execution, command lines, parent processes, initiating users. |
| `DeviceFileEvents` | Tool staging, scripts, zip files, dump files, cleanup. |
| `AlertEvidence` | Defender verdicts, prevented tools, MITRE mappings, and alert-side file hashes. Use it when the question is about Defender's interpretation. |

## What Students Practice

- Scope to one workstation with `DeviceName == TargetDevice`.
- Hunt processes, files, and alerts in the right table.
- Build queries one line at a time.
- Keep final answer columns consistent with the step-by-step query.
- Use `union`, `project`, `order by`, `has`, `has_any`, `has_all`, `summarize`, and `extend`.

Each scenario follows the same learner-friendly flow:

- **What Happened**: plain-English attacker story.
- **Your Challenge**: what students need to answer.
- **KQL Skill**: table, column, or operator to learn.
- **How To Think About The Query**: the hunting idea before the syntax.
- **Break Down The KQL**: small query steps.
- **Full Answer And Explanation**: final query, answer, and why it works.

In other words: understand the move, read the challenge, build the query, then check the answer.

When a step-by-step query changes columns, the question changed too. File rows usually need `FolderPath` and `ActionType`. Alert rows usually need `Title`, `AttackTechniques`, or `Severity`. If a column matters later, the practice query should keep it or explain why it changed.

</details>

<details>
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

Beginner habit: prove **when**, **where**, **what**, and **why it matters** when the data allows it.

</details>

<details>
<summary><strong>Pre-CTF KQL Refresher</strong></summary>

## Pre-CTF KQL Refresher

Practice these KQL moves before starting the scenarios.

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

Quick note: do not write the perfect query first. Start broad, filter down, then clean up the output.

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
    | where DeviceName == TargetDevice
    | where FileName has_any ("pwdump", "gsecdump", "lazagne")
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

<details>
<summary><strong>Run Context And Scenario Coverage</strong></summary>

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
5. Read **What Happened** and **Your Challenge**.
6. Open **Break Down The KQL** when students are ready to build the hunt.
7. Open **Full Answer And Explanation** only when students need a nudge or want to check their work.

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

| # | Scenario | Primary lesson tables |
|---|---|---|
| 00 | Warm-Up: Rebuild the Attack Timeline | `DeviceProcessEvents`, `DeviceFileEvents`, `AlertEvidence` |
| 01 | Credentials In Registry Script | `AlertEvidence` |
| 02 | Dump SAM Registry Hive via `reg save` | `DeviceProcessEvents` |
| 03 | Collect Browser Data via Esentutl and PowerShell | `DeviceProcessEvents` |
| 04 | Kerberoasting using Rubeus | `DeviceFileEvents`, `AlertEvidence` |
| 05 | Kerberoasting using PowerShell Empire Invoke-Kerberoast | `DeviceFileEvents` |
| 06 | Dump LSASS Process to Minidump File | `DeviceFileEvents` |
| 07 | Dump Passwords using PwDump7 | `DeviceFileEvents`, `AlertEvidence` |
| 08 | Dump Passwords using gsecdump | `DeviceFileEvents`, `AlertEvidence` |
| 09 | Dump Passwords using LaZagne | `DeviceFileEvents` |
| 10 | Dump Windows Passwords with Obfuscated Mimikatz | `DeviceFileEvents` |
| 11 | Dump Windows Passwords with Original Mimikatz | `DeviceFileEvents`, `AlertEvidence` |

</details>

---

<details open>
<summary><strong>00 - Warm-Up: Rebuild the Attack Timeline</strong></summary>

## What Happened

Before chasing individual scenarios, rebuild the attacker timeline. This shows why one table rarely tells the whole story.

## Your Challenge

What launched the attack, what account ran it, and where did the AttackIQ runtime unpack itself?

Use the step-by-step queries first. Then open **Full Answer And Explanation** to check your work.

## KQL Skill

`let`, `union`, `project`, `order by`, workstation scoping.

## How To Think About The Query

Before writing the query, ask:

- Which one workstation should I scope to first?
- Which evidence types might each hold a different part of the story: process, file, or alert?
- What common columns do I need so separate tables read like one timeline?

<details>
<summary>Break Down The KQL</summary>

**Nugget:** Always scope to the AttackIQ workstation before adding scenario clues. The activity was deployed from `usm262346`, so every practice query should start with `let TargetDevice = "usm262346";` and include `| where DeviceName == TargetDevice`.

Endpoint investigations usually need more than one evidence type. `DeviceProcessEvents` shows execution, `DeviceFileEvents` shows staged or deleted files, and `AlertEvidence` shows Defender verdicts. `union isfuzzy=true` lets you combine those tables even when the projected columns are not identical across every source.

Why this matters: use `project` inside each branch to normalize the output columns, then `order by Timestamp asc` to turn separate tables into one readable timeline.

### Build The Hunt Step By Step

Start with the question: "What happened on this one computer during the test window?"

The beginner mistake is to search the whole tenant first. The better habit is to scope early:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| take 20
```

Now filter to likely AttackIQ clues and shape the process rows into timeline columns:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has_any (".ghostex-cli", "AppData\\Local\\Temp\\aiq", "reg save", "esentutl", "credentials_in_registry", "collect_database_webcache")
| project Timestamp, EvidenceType="Process", Action=FileName,
          Detail=ProcessCommandLine, Source=InitiatingProcessCommandLine
| order by Timestamp asc
```

Add file rows using the same story columns:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FolderPath has_any (".ghostex-cli", "AppData\\Local\\Temp\\aiq")
| where FileName has_any ("mimikatz", "lazagne", "gsecdump", "pwdump", "rubeus", "kerberoast", "credential", "webcache")
    or FileName endswith ".dmp"
| project Timestamp, EvidenceType="File", Action=ActionType,
          Detail=strcat(FolderPath, "\\", FileName), Source=InitiatingProcessCommandLine
| order by Timestamp asc
```

Add alert rows using the same story columns:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has_any ("mimikatz", "lazagne", "gsecdump", "pwdump", "rubeus", "kerberoast", "credentials_in_registry")
| project Timestamp, EvidenceType="Alert", Action=Title,
          Detail=strcat(EntityType, " | ", FileName, " | ", ProcessCommandLine), Source=ServiceSource
| order by Timestamp asc
```

Checkpoint: all three practice queries now output `Timestamp`, `EvidenceType`, `Action`, `Detail`, and `Source`. The full answer puts those same branches inside one `union`.

</details>

<details>
<summary>Full Answer And Explanation</summary>

The final query is repeated here so you can check your work.

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
    | where FileName has_any ("mimikatz", "lazagne", "gsecdump", "pwdump", "rubeus", "kerberoast", "credentials_in_registry")
    | project Timestamp, EvidenceType="Alert", Action=Title,
              Detail=strcat(EntityType, " | ", FileName, " | ", ProcessCommandLine), Source=ServiceSource
)
| order by Timestamp asc
```


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

## Your Challenge

What is the exact PowerShell script filename, and which ATT&CK technique did Defender attach to it?

## KQL Skill

Use `AlertEvidence` to connect the script filename to Defender's ATT&CK mapping.

### Start This Way

Every scenario starts by scoping to the AttackIQ workstation. Run this first and keep it as the top of each query.

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Hints and guidelines:

- Use `AlertEvidence` because the question asks what Defender attached to the script.
- Do not type the exact script name yet.
- `Title` tells you what Defender called the alert.
- `FileName` tells you what script or file Defender attached to the alert.
- `AttackTechniques` tells you the ATT&CK mapping.

<details>
<summary>Step 1 - Show The Useful Columns</summary>

Start with the scoped workstation query. Then add the columns that answer the question.

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| project Timestamp, Title, FileName, AttackTechniques, SHA256
| order by Timestamp asc
```

Read the results this way:

- `Title`: what Defender called the alert
- `FileName`: the script or file Defender attached to the alert
- `AttackTechniques`: the ATT&CK mapping

</details>

<details>
<summary>Step 2 - Reduce The Noise</summary>

Keep the same query and add one broad clue line for PowerShell, registry, or credential wording.

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where Title has_any ("PowerShell", "Registry", "Credentials") or AttackTechniques has "Credential"
| project Timestamp, Title, FileName, AttackTechniques, SHA256
| order by Timestamp asc
```

Do not type the exact script name yet. Let the results show it first.

Use the output to answer:

- What exact script name appears in `FileName`?
- What technique appears in `AttackTechniques`?

If you can explain `Title`, `FileName`, and `AttackTechniques`, you have the answer.

</details>

<details>
<summary>Full Answer</summary>

The full answer query tightens the hunt to the exact script after you discover it in Step 2.

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName =~ "credentials_in_registry.ps1"
| where Title has_any ("PowerShell", "Registry", "Credentials") or AttackTechniques has_any ("Credentials in Registry", "T1552.002")
| project Timestamp, Title, FileName, AttackTechniques, SHA256
| order by Timestamp asc
```

- Script: `credentials_in_registry.ps1`
- Alert: `A malicious PowerShell Cmdlet was invoked on the machine`
- ATT&CK: `Credentials in Registry (T1552.002)`

Why this is the answer:

- `FileName` gives the exact script.
- `Title` gives Defender's alert wording.
- `AttackTechniques` gives the ATT&CK mapping.

</details>

</details>

---

<details>
<summary><strong>02 - Dump SAM Registry Hive via reg save</strong></summary>

## What Happened

The attacker tries to copy the local SAM registry hive. The command line is the clue.

## Your Challenge

Where did the attacker try to save the SAM hive?

Use the step-by-step queries first. Then open **Full Answer And Explanation** to check your work.

## KQL Skill

Use `has_all` when multiple terms must appear together in the same command line.

## How To Think About The Query

Before hunting the output path, ask:

- Which endpoint table has process command lines?
- What command-line words must appear together to prove a registry hive export?
- Which columns will show the process, account, and exact command?

<details>
<summary>Break Down The KQL</summary>

**Nugget:** Always scope to the AttackIQ workstation before adding scenario clues. The activity was deployed from `usm262346`, so every practice query should start with `let TargetDevice = "usm262346";` and include `| where DeviceName == TargetDevice`.

`reg` by itself is too broad, and `sam` by itself can appear in unrelated paths or names. `has_all` requires both clues to exist in the same command line, which makes the result much closer to the real behavior: saving the SAM registry hive.

Why this matters: use `has_all` when the detection idea depends on a combination of words, not just one keyword.

### Build The Hunt Step By Step

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

Now keep the `cmd.exe` process filter and add the required behavior terms:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_all ("reg save", "hklm\\sam")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

Notice what stayed the same: the second query keeps `FileName =~ "cmd.exe"` and keeps `FileName` in the output. The only new idea is `has_all`.

KQL logic to learn: `has_all` is for "both of these clues must be present." That is different from `has_any`, where only one clue has to match.

</details>

<details>
<summary>Full Answer And Explanation</summary>

The final query is repeated here so you can check your work.

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

## Your Challenge

Which process launched `esentutl.exe`, and what browser/cache path was targeted?

Use the step-by-step queries first. Then open **Full Answer And Explanation** to check your work.

## KQL Skill

Follow parent and child process relationships with `InitiatingProcessCommandLine`.

## How To Think About The Query

Before choosing a final filter, ask:

- Which row shows the utility that ran?
- Which parent-process columns show who launched it?
- Which command-line clues prove this is browser/WebCache collection instead of normal Windows utility usage?

<details>
<summary>Break Down The KQL</summary>

**Nugget:** Always scope to the AttackIQ workstation before adding scenario clues. The activity was deployed from `usm262346`, so every practice query should start with `let TargetDevice = "usm262346";` and include `| where DeviceName == TargetDevice`.

Query both `FileName` and `InitiatingProcessCommandLine`. `FileName in~ ("powershell.exe", "esentutl.exe")` catches the parent and child process names, while `InitiatingProcessCommandLine has "collect_database_webcache.ps1"` ties the child process back to the script that launched it.

Why this matters: parent process fields are pivot fields. They explain why a normal Windows binary appeared in the timeline.

### Build The Hunt Step By Step

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

Now keep the same process-name filter, add the command-line clues, and include the parent process columns:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName in~ ("powershell.exe", "esentutl.exe")
| where ProcessCommandLine has_any ("collect_database_webcache.ps1", "esentutl", "WebCache")
   or InitiatingProcessCommandLine has "collect_database_webcache.ps1"
| project Timestamp, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, SHA256
```

Notice what stayed the same: the second query still keeps both process names from the first query. It only adds the WebCache clues and the parent-process columns.

KQL logic to learn: `InitiatingProcessFileName` and `InitiatingProcessCommandLine` answer "who launched this?"

</details>

<details>
<summary>Full Answer And Explanation</summary>

The final query is repeated here so you can check your work.

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

## Your Challenge

What file name and hash identify the Rubeus attempt?

Use the step-by-step queries first. Then open **Full Answer And Explanation** to check your work.

## KQL Skill

A blocked tool may not produce a clean process execution row. Hunt file staging and `AlertEvidence`.

## How To Think About The Query

Before assuming there is no event, ask:

- If Defender blocked a tool, would process execution, file staging, or alert evidence be strongest?
- Which table can prove the file appeared?
- Which table can explain how Defender classified it?

<details>
<summary>Break Down The KQL</summary>

**Nugget:** Always scope to the AttackIQ workstation before adding scenario clues. The activity was deployed from `usm262346`, so every practice query should start with `let TargetDevice = "usm262346";` and include `| where DeviceName == TargetDevice`.

Start with `DeviceFileEvents` and `AlertEvidence`. `DeviceFileEvents` can show that `Rubeus.exe` was staged on disk. `AlertEvidence` can show the Defender verdict and ATT&CK mapping even if there is no clean `DeviceProcessEvents` execution row.

Why this matters: absence of process execution is not absence of activity. Blocked tools often leave stronger evidence in file and alert tables.

### Build The Hunt Step By Step

Mission: catch Rubeus even if Defender blocked it before normal execution.

Start with file staging:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "Rubeus.exe"
| project Timestamp, EvidenceType="File", FileName,
          Detail=strcat(ActionType, " | ", FolderPath), AccountName=InitiatingProcessAccountName, SHA256
```

Why these columns: `EvidenceType` tells you which table the row came from. `Detail` keeps the file action and path together. `SHA256` identifies the file.

Then ask Defender what it thought the file meant:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "Rubeus.exe" or AttackTechniques has_any ("Kerberoasting", "T1558.003")
| project Timestamp, EvidenceType="Alert", FileName,
          Detail=strcat(Title, " | ", AttackTechniques), AccountName, SHA256
```

Notice the shape is the same now: both practice queries output `Timestamp`, `EvidenceType`, `FileName`, `Detail`, `AccountName`, and `SHA256`. The full answer simply combines them with `union`.

KQL logic to learn: when the process table is quiet, check file and alert tables before deciding nothing happened.

</details>

<details>
<summary>Full Answer And Explanation</summary>

The final query is repeated here so you can check your work.

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
    | where DeviceName == TargetDevice
    | where FileName =~ "Rubeus.exe" or AttackTechniques has_any ("Kerberoasting", "T1558.003")
    | project Timestamp, EvidenceType="Alert", FileName, Detail=strcat(Title, " | ", AttackTechniques), AccountName, SHA256
)
| order by Timestamp asc
```


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

## Your Challenge

Which two PowerShell files were staged for the Kerberoasting test?

Use the step-by-step queries first. Then open **Full Answer And Explanation** to check your work.

## KQL Skill

Use `has_any` to find both Kerberoast script files, then summarize their file events.

## How To Think About The Query

Before exact filenames, ask:

- Is this technique likely to stage one file or a pair of related scripts?
- Which broad keyword finds the family of artifacts first?
- When should I summarize file events instead of reading every row one by one?

<details>
<summary>Break Down The KQL</summary>

**Nugget:** Always scope to the AttackIQ workstation before adding scenario clues. The activity was deployed from `usm262346`, so every practice query should start with `let TargetDevice = "usm262346";` and include `| where DeviceName == TargetDevice`.

This scenario stages more than one related PowerShell file. `has_any` lets the query catch both the wrapper script and the main Kerberoast script without writing separate filters for each filename.

Why this matters: use `has_any` when a scenario may have several related artifact names and any one of them is enough to include the row.

### Build The Hunt Step By Step

Mission: find the PowerShell Kerberoasting files.

Start by searching for the family name, not one exact file:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "kerberoast"
| project Timestamp, FileName, FolderPath, ActionType, SHA256
```

Then keep those same evidence columns and summarize the expected pair of files:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has_any ("invoke-kerberoast", "call-invoke-kerberoast")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Actions=make_set(ActionType) by FileName, FolderPath, SHA256
```

Why the shape changed: `summarize` rolls several file-event rows into one row per artifact. `ActionType` becomes the `Actions` set, while `FileName`, `FolderPath`, and `SHA256` stay visible.

KQL logic to learn: `has` is good for one clue. `has_any` is good when several related clue words can identify the same scenario.

</details>

<details>
<summary>Full Answer And Explanation</summary>

The final query is repeated here so you can check your work.

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has_any ("invoke-kerberoast", "call-invoke-kerberoast")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Actions=make_set(ActionType) by FileName, FolderPath, SHA256
| order by FileName asc
```


- `call-invoke-kerberoast.ps1`
- `invoke-kerberoast.ps1`
- These file rows are the staged Kerberoast script evidence.

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

The attacker tries to dump LSASS. A dump file lands in temp with a generated name, so the filename is not obvious at first glance.

## Your Challenge

What dump file was created, and where did it land?

Use the step-by-step queries first. Then open **Full Answer And Explanation** to check your work.

## KQL Skill

Dump files are investigation gold. Hunt for `.dmp`, then broaden to folder patterns when the name is random.

## How To Think About The Query

Before trying to guess the dump name, ask:

- What file extension or folder pattern would a memory dump leave?
- Which table records file creation and deletion?
- Which columns show the file name, path, action, and hash?

<details>
<summary>Break Down The KQL</summary>

**Nugget:** Always scope to the AttackIQ workstation before adding scenario clues. The activity was deployed from `usm262346`, so every practice query should start with `let TargetDevice = "usm262346";` and include `| where DeviceName == TargetDevice`.

Look for file patterns instead of relying on one exact filename. `FileName endswith ".dmp"` catches obvious dump files, while `FolderPath has "pid_"` catches the AttackIQ-style path pattern.

Why this matters: random filenames are common, so hunt on file extension and folder pattern before adding other context.

### Build The Hunt Step By Step

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

Then broaden from only `.dmp` names to the AttackIQ dump path pattern:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName endswith ".dmp" or FolderPath has "pid_"
| project Timestamp, ActionType, FileName, FolderPath, SHA256
```

Why the columns changed: the second query keeps the same table. It adds the folder pattern and keeps `SHA256` for follow-up evidence.

KQL logic to learn: use `endswith` for extensions, and use folder patterns when the filename is random.

</details>

<details>
<summary>Full Answer And Explanation</summary>

The final query is repeated here so you can check your work.

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName endswith ".dmp" or FolderPath has "pid_"
| project Timestamp, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```


- Dump file: `pid_976_2ztj_d6a.dmp`
- File path clue: a temp path containing `pid_`

### How The KQL Finds It

This scenario teaches pattern hunting when filenames are random:

1. `FileName endswith ".dmp"` finds dump files without knowing the full filename.
2. `FolderPath has "pid_"` catches the AttackIQ-style dump path pattern.
3. `project Timestamp, ActionType, FileName, FolderPath, SHA256` keeps the file evidence readable.
4. `SHA256` is included if students want a stable file identifier.

Checkpoint: random names require pattern logic. Extensions and folders are clues too.

</details>

</details>

---

<details>
<summary><strong>07 - Dump Passwords Using PwDump7</strong></summary>

## What Happened

The attacker stages PwDump7. Defender prevents the hacktool, but you can still prove the attempted credential dump.

## Your Challenge

Was PwDump executed cleanly, or was it prevented? What tells you?

Use the step-by-step queries first. Then open **Full Answer And Explanation** to check your work.

## KQL Skill

Use `AlertEvidence` to read the prevention verdict, then shape that verdict with `extend`.

## How To Think About The Query

Before deciding it executed, ask:

- What file evidence shows the tool was staged?
- What alert wording shows whether Defender blocked it?
- Which column can turn that wording into a simple outcome?

<details>
<summary>Break Down The KQL</summary>

**Nugget:** Always scope to the AttackIQ workstation before adding scenario clues. The activity was deployed from `usm262346`, so every practice query should start with `let TargetDevice = "usm262346";` and include `| where DeviceName == TargetDevice`.

Use `AlertEvidence` when the important question is outcome. `Title has "PWDump"` finds Defender's prevention verdict, and `extend` can turn that wording into a simple `Outcome` column.

Why this matters: a prevented attack still produces useful telemetry. Read `Title`, `Severity`, `Outcome`, and `FileName` together.

### Build The Hunt Step By Step

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

Why these columns: this first pass answers, "Did a PwDump-looking file appear on disk, and what file action happened?"

Then keep the alert wording and create a simple outcome column:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "pwdump" or Title has "PWDump"
| extend Outcome = iff(Title has "prevented", "Prevented", "Review")
| project Timestamp, Outcome, Title, Severity, FileName, SHA256
```

Why the columns changed: `AlertEvidence` is where the prevention language lives. `Title` and `Severity` explain the outcome better than `FolderPath` does, and `SHA256` keeps the file identifier visible.

The full answer uses this alert query because the challenge asks whether PwDump was prevented. The file query is just the warm-up that proves a PwDump artifact existed.

KQL logic to learn: `Title` often tells you the outcome. Words like `prevented` or `blocked` change the story from execution to attempted execution.

</details>

<details>
<summary>Full Answer And Explanation</summary>

The final query is repeated here so you can check your work.

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where Title has "PWDump" or FileName has "pwdump"
| extend Outcome = iff(Title has "prevented", "Prevented", "Review")
| project Timestamp, Outcome, Title, Severity, FileName, SHA256
| order by Timestamp asc
```


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

## Your Challenge

What did Defender call the threat, and what was the actual staged file name?

Use the step-by-step queries first. Then open **Full Answer And Explanation** to check your work.

## KQL Skill

Tool names and detection names do not always match. Hunt both the staged file name and alert title.

## How To Think About The Query

Before relying on the tool name, ask:

- What if Defender uses a malware-family name instead of the tool name?
- Which evidence shows the staged artifact?
- Which evidence shows Defender's verdict?

<details>
<summary>Break Down The KQL</summary>

**Nugget:** Always scope to the AttackIQ workstation before adding scenario clues. The activity was deployed from `usm262346`, so every practice query should start with `let TargetDevice = "usm262346";` and include `| where DeviceName == TargetDevice`.

The tool name and the detection name are not always the same. `FileName has "gsecdump"` finds the staged artifact, while `Title has "Vigorf"` catches how Defender classified the threat.

Why this matters: do not assume the alert title will repeat the tool name. Pair artifact terms with detection-family terms.

### Build The Hunt Step By Step

Mission: connect the staged `gsecdump` artifact to Defender's different detection name.

Start with the tool name:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "gsecdump"
| project Timestamp, FileName, FolderPath, ActionType, SHA256
```

Then search alert evidence with both artifact and detection-family terms:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "gsecdump" or Title has "Vigorf"
| project Timestamp, Title, Severity, FileName, SHA256
```

Why the columns changed: the file query proves staging. The alert query uses `Title` because Defender calls the threat `Vigorf`, and it keeps `SHA256` for the final evidence.

KQL logic to learn: one table may show the attacker tool name while another table shows Defender's malware family name.

</details>

<details>
<summary>Full Answer And Explanation</summary>

The final query is repeated here so you can check your work.

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "gsecdump" or Title has "Vigorf"
| project Timestamp, Title, Severity, FileName, SHA256
| order by Timestamp asc
```


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

## Your Challenge

How do we know the tool was cleaned up after staging?

Use the step-by-step queries first. Then open **Full Answer And Explanation** to check your work.

## KQL Skill

Use file events to catch both `FileCreated` and `FileDeleted` for the same suspicious artifact.

## How To Think About The Query

Before answering cleanup, ask:

- Which file-action column shows creation and deletion?
- Do I need individual timeline rows first or a summarized lifecycle?
- Which grouping keeps the file name, path, and hash visible?

<details>
<summary>Break Down The KQL</summary>

**Nugget:** Always scope to the AttackIQ workstation before adding scenario clues. The activity was deployed from `usm262346`, so every practice query should start with `let TargetDevice = "usm262346";` and include `| where DeviceName == TargetDevice`.

Query `DeviceFileEvents` for `FileName has "lazagne"`, then keep `ActionType` in the projected output. Seeing both creation and deletion actions for the same artifact shows the tool lifecycle.

Why this matters: include `ActionType` when hunting file artifacts. The action tells the story, not just the filename.

### Build The Hunt Step By Step

Mission: show that LaZagne appeared on disk and was later removed.

Start by finding every LaZagne file event:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| project Timestamp, FileName, ActionType, FolderPath, SHA256
| order by Timestamp asc
```

Then summarize the lifecycle:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| summarize Actions=make_set(ActionType), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Paths=make_set(FolderPath) by FileName, SHA256
```

KQL logic to learn: `summarize` turns many rows into one answer. `ActionType` becomes `Actions`, `FolderPath` becomes `Paths`, and `SHA256` stays in the output.

</details>

<details>
<summary>Full Answer And Explanation</summary>

The final query is repeated here so you can check your work.

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| summarize Actions=make_set(ActionType), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Paths=make_set(FolderPath) by FileName, SHA256
| order by FirstSeen asc
```


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

## Your Challenge

What makes this hunt different from simply looking for `mimikatz.exe`?

Use the step-by-step queries first. Then open **Full Answer And Explanation** to check your work.

## KQL Skill

When names are hidden or changed, hunt for script artifacts first. Do not depend on seeing `mimikatz.exe` as a process name.

## How To Think About The Query

Before searching for `mimikatz.exe`, ask:

- What if the activity was wrapped in a script?
- Which table shows staged artifacts even when the process name is not obvious?
- How can I start broad, then tighten only after the artifact appears?

<details>
<summary>Break Down The KQL</summary>

**Nugget:** Always scope to the AttackIQ workstation before adding scenario clues. The activity was deployed from `usm262346`, so every practice query should start with `let TargetDevice = "usm262346";` and include `| where DeviceName == TargetDevice`.

The behavior is represented by a PowerShell script artifact, not a direct `mimikatz.exe` process. `FileName =~ "mimikatz_dump_passwords_v2.ps1"` catches the staged script exactly.

Why this matters: exact executable hunts are fragile. A beginner-friendly hunt starts with the artifact you can prove in the file table.

### Build The Hunt Step By Step

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

Then tighten to the exact script artifact used by this scenario:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "mimikatz_dump_passwords_v2.ps1"
| project Timestamp, ActionType, FileName, FolderPath, SHA256
```

Why the columns changed: the first query uses a broad keyword to find candidates. The second query uses the exact script name and adds `SHA256` because the final answer is a file-artifact answer.

KQL logic to learn: when tools are renamed, obfuscated, or wrapped in scripts, start broad, then tighten to the exact artifact you can prove.

</details>

<details>
<summary>Full Answer And Explanation</summary>

The final query is repeated here so you can check your work.

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "mimikatz_dump_passwords_v2.ps1"
| project Timestamp, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```


- Artifact: `mimikatz_dump_passwords_v2.ps1`
- `SHA256` is included for follow-up evidence.
- The hunt works because the script artifact exists even when the process name is not `mimikatz.exe`.

### How The KQL Finds It

This scenario teaches why process names are not enough:

1. `FileName =~ "mimikatz_dump_passwords_v2.ps1"` catches the script artifact.
2. `DeviceFileEvents` shows the suspicious script even when there is no `mimikatz.exe` process name to search for.
3. `SHA256` gives you a stable file identifier for reporting or follow-up hunting.

Checkpoint: a Mimikatz hunt can start from a script, zip, command, memory behavior, or tool verdict. In this scenario, the script artifact is the cleanest beginner path.

</details>

</details>

---

<details>
<summary><strong>11 - Dump Windows Passwords with Original Mimikatz</strong></summary>

## What Happened

The attacker stages the classic Mimikatz package. This is the obvious Mimikatz scenario, but you still need to prove it with evidence.

## Your Challenge

Which Mimikatz artifact was blocked, and what hash identifies it in alert evidence?

Use the step-by-step queries first. Then open **Full Answer And Explanation** to check your work.

## KQL Skill

Use obvious file names when available, but validate with alert evidence and hashes.

## How To Think About The Query

Before stopping at the obvious filename, ask:

- What extra evidence would make this report-ready?
- Which alert fields show Defender's verdict and severity?
- Which hash column identifies the exact file?

<details>
<summary>Break Down The KQL</summary>

**Nugget:** Always scope to the AttackIQ workstation before adding scenario clues. The activity was deployed from `usm262346`, so every practice query should start with `let TargetDevice = "usm262346";` and include `| where DeviceName == TargetDevice`.

An obvious filename is a clue, not full proof. Projecting `SHA256`, `Title`, and `Severity` gives you a durable indicator and the Defender verdict that explains why the artifact matters.

Why this matters: finish a hunt by producing evidence another analyst can validate: filename, hash, alert title, severity, time, and device.

### Build The Hunt Step By Step

Mission: validate the classic Mimikatz artifact with a filename, alert verdict, and hash.

Start with the known filename:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "mimikatz-x64.zip"
| project Timestamp, FileName, FolderPath, ActionType, SHA256
```

Why these columns: `FolderPath` and `ActionType` explain the file event; `SHA256` identifies the artifact even if the filename changes later.

Then collect the evidence you would put in a report:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "mimikatz-x64.zip" or Title has "Mimikatz credential theft tool"
| project Timestamp, DeviceName, Title, Severity, FileName, SHA256
```

Why the columns changed: the report answer needs Defender's verdict, so the alert query keeps `Title`, `Severity`, `DeviceName`, `FileName`, and `SHA256`.

KQL logic to learn: a good hunt answer includes the thing, the verdict, the hash, the time, and the device. That is what makes it repeatable.

</details>

<details>
<summary>Full Answer And Explanation</summary>

The final query is repeated here so you can check your work.

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "mimikatz-x64.zip" or Title has "Mimikatz credential theft tool"
| project Timestamp, DeviceName, Title, Severity, FileName, SHA256
| order by Timestamp asc
```


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
    | where DeviceName == TargetDevice
    | where FolderPath has_any ("AppData\\Local\\Temp\\aiq", ".ghostex-cli-wd") or isnotempty(FileName) or isnotempty(Title)
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
