$ErrorActionPreference = 'Stop'

$OutputPath = Join-Path $PSScriptRoot 'AttackIQ-XDR-KQL-CTF-Training.pptx'

function Add-TextBox {
    param(
        [object]$Slide,
        [double]$Left,
        [double]$Top,
        [double]$Width,
        [double]$Height,
        [string]$Text,
        [int]$Size = 20,
        [string]$Color = '111111',
        [string]$Font = 'Aptos',
        [bool]$Bold = $false
    )
    $shape = $Slide.Shapes.AddTextbox(1, $Left, $Top, $Width, $Height)
    $shape.TextFrame.MarginLeft = 8
    $shape.TextFrame.MarginRight = 8
    $shape.TextFrame.MarginTop = 4
    $shape.TextFrame.MarginBottom = 4
    $shape.TextFrame.WordWrap = -1
    $range = $shape.TextFrame.TextRange
    $range.Text = $Text
    $range.Font.Name = $Font
    $range.Font.Size = $Size
    $range.Font.Color.RGB = Convert-HexColor $Color
    if ($Bold) { $range.Font.Bold = -1 }
    return $shape
}

function Convert-HexColor {
    param([string]$Hex)
    $r = [Convert]::ToInt32($Hex.Substring(0,2),16)
    $g = [Convert]::ToInt32($Hex.Substring(2,2),16)
    $b = [Convert]::ToInt32($Hex.Substring(4,2),16)
    return $r + ($g -shl 8) + ($b -shl 16)
}

function Add-Rect {
    param(
        [object]$Slide,
        [double]$Left,
        [double]$Top,
        [double]$Width,
        [double]$Height,
        [string]$Fill,
        [string]$Line = $null
    )
    $shape = $Slide.Shapes.AddShape(1, $Left, $Top, $Width, $Height)
    $shape.Fill.ForeColor.RGB = Convert-HexColor $Fill
    if ($Line) {
        $shape.Line.ForeColor.RGB = Convert-HexColor $Line
        $shape.Line.Weight = 1
    } else {
        $shape.Line.Visible = 0
    }
    return $shape
}

function Add-Header {
    param([object]$Slide, [string]$Title, [string]$Kicker = '')
    Add-Rect -Slide $Slide -Left 0 -Top 0 -Width 960 -Height 74 -Fill '243F68' | Out-Null
    if ($Kicker) {
        Add-TextBox -Slide $Slide -Left 32 -Top 10 -Width 880 -Height 16 -Text $Kicker.ToUpperInvariant() -Size 9 -Color 'BFD7FF' -Bold $true | Out-Null
        Add-TextBox -Slide $Slide -Left 32 -Top 27 -Width 880 -Height 42 -Text $Title -Size 25 -Color 'FFFFFF' -Bold $true | Out-Null
    } else {
        Add-TextBox -Slide $Slide -Left 32 -Top 18 -Width 880 -Height 45 -Text $Title -Size 28 -Color 'FFFFFF' -Bold $true | Out-Null
    }
}

function Add-SlideBase {
    param([object]$Presentation, [string]$Title, [string]$Kicker = '')
    $slide = $Presentation.Slides.Add($Presentation.Slides.Count + 1, 12)
    Add-Rect -Slide $slide -Left 0 -Top 0 -Width 960 -Height 540 -Fill 'FFFFFF' | Out-Null
    Add-Header -Slide $slide -Title $Title -Kicker $Kicker
    return $slide
}

function Add-Bullets {
    param(
        [object]$Slide,
        [string[]]$Items,
        [double]$Left = 54,
        [double]$Top = 105,
        [double]$Width = 850,
        [double]$Height = 355,
        [int]$Size = 22
    )
    $text = ($Items | ForEach-Object { "- $_" }) -join "`r`n"
    $shape = Add-TextBox -Slide $Slide -Left $Left -Top $Top -Width $Width -Height $Height -Text $text -Size $Size -Color '111111'
    $shape.TextFrame.TextRange.ParagraphFormat.SpaceAfter = 8
    return $shape
}

function Add-CodeBox {
    param(
        [object]$Slide,
        [string]$Code,
        [double]$Left = 54,
        [double]$Top = 245,
        [double]$Width = 850,
        [double]$Height = 210,
        [int]$Size = 14
    )
    Add-Rect -Slide $Slide -Left $Left -Top $Top -Width $Width -Height $Height -Fill 'F4F7FB' -Line 'D6E0EF' | Out-Null
    $shape = Add-TextBox -Slide $Slide -Left ($Left + 12) -Top ($Top + 10) -Width ($Width - 24) -Height ($Height - 18) -Text $Code.Trim() -Size $Size -Color '0B1F3A' -Font 'Cascadia Mono'
    $null = $shape
}

function Add-Callout {
    param([object]$Slide, [string]$Text, [double]$Left, [double]$Top, [double]$Width, [double]$Height, [string]$Fill = 'EAF3FF')
    Add-Rect -Slide $Slide -Left $Left -Top $Top -Width $Width -Height $Height -Fill $Fill -Line '7FA9DA' | Out-Null
    Add-TextBox -Slide $Slide -Left ($Left + 10) -Top ($Top + 8) -Width ($Width - 20) -Height ($Height - 14) -Text $Text -Size 16 -Color '15375F' -Bold $true | Out-Null
}

function Add-Notes {
    param([object]$Slide, [string]$Text)
    try {
        $notesShape = $Slide.NotesPage.Shapes.Placeholders(2)
        $notesShape.TextFrame.TextRange.Text = $Text
    } catch {
        # Speaker notes are best-effort; deck content still carries instructor notes in visible slides.
    }
}

function Add-TitleSlide {
    param([object]$Presentation)
    $slide = Add-SlideBase -Presentation $Presentation -Title 'AttackIQ Endpoint EDR KQL CTF' -Kicker 'Microsoft Defender XDR Advanced Hunting'
    Add-TextBox -Slide $slide -Left 54 -Top 128 -Width 610 -Height 80 -Text 'Beginner-friendly hunting lab built from an authorized AttackIQ Security Control Baseline - Endpoint EDR run.' -Size 25 -Color '111111' -Bold $true | Out-Null
    Add-Callout -Slide $slide -Left 54 -Top 242 -Width 395 -Height 90 -Text "Target workstation: usm262346`nTime filter: Timestamp > ago(7d)`nMode: Learn, build, challenge, prove" -Fill 'EAF3FF'
    Add-Callout -Slide $slide -Left 484 -Top 242 -Width 365 -Height 90 -Text "Audience: beginner KQL learners`nPlatform: Defender XDR Advanced Hunting`nTheme: credential-access CTF" -Fill 'EEF7ED'
    Add-TextBox -Slide $slide -Left 54 -Top 482 -Width 850 -Height 28 -Text 'Instructor deck generated from the attackiqkqlsession README.' -Size 13 -Color '666666' | Out-Null
}

function Add-AgendaSlides {
    param([object]$Presentation)
    $slide = Add-SlideBase -Presentation $Presentation -Title 'How This Class Flows' -Kicker 'Instructor orientation'
    Add-Bullets -Slide $slide -Items @(
        'Start with KQL 101 so students understand the shape of a query.',
        'Run the pre-CTF refresher: where, project, summarize, order by, pivoting, union.',
        'Use the warm-up timeline to show the AttackIQ activity cluster.',
        'Work through each scenario in order: brief, skill, build, challenge, full query, answer.',
        'Use the optional incident pivot only if the customer has a matching XDR incident.'
    ) | Out-Null
    Add-Notes -Slide $slide -Text 'Keep the class paced. Do not start with the final full query. Let students build confidence with small query pieces first.'

    $slide = Add-SlideBase -Presentation $Presentation -Title 'The Student Mental Model' -Kicker 'CTF mindset'
    Add-Callout -Slide $slide -Left 54 -Top 116 -Width 250 -Height 95 -Text "1. Find the right table`nProcess, file, or alert" -Fill 'EAF3FF'
    Add-Callout -Slide $slide -Left 354 -Top 116 -Width 250 -Height 95 -Text "2. Filter the noise`nDevice + time + clue" -Fill 'F4F0FF'
    Add-Callout -Slide $slide -Left 654 -Top 116 -Width 250 -Height 95 -Text "3. Prove the answer`nWhen, where, what, why" -Fill 'EEF7ED'
    Add-Bullets -Slide $slide -Top 250 -Items @(
        'Every CTF answer should be evidence-backed, not guessed.',
        'The query does not need to start perfect. It should get better with each filter.',
        'If the process table is quiet, check file and alert evidence.',
        'The answer key is for explanation, not the first place students should look.'
    ) -Size 20 | Out-Null
}

function Add-KqlRefresherSlides {
    param([object]$Presentation)
    $slide = Add-SlideBase -Presentation $Presentation -Title 'KQL 101: Read Top To Bottom' -Kicker 'Before the CTF'
    Add-Bullets -Slide $slide -Left 54 -Top 108 -Width 390 -Height 300 -Items @(
        'The table name starts the query.',
        'The pipe character sends rows to the next step.',
        'where reduces noise.',
        'project chooses the evidence columns.',
        'order by makes the result readable.'
    ) -Size 19 | Out-Null
    Add-CodeBox -Slide $slide -Left 486 -Top 112 -Width 390 -Height 240 -Size 13 -Code @'
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has "reg save"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
'@
    Add-Callout -Slide $slide -Left 486 -Top 374 -Width 390 -Height 58 -Text 'Coach line: read every pipe as "and then..."' -Fill 'FFF6E5'

    $slide = Add-SlideBase -Presentation $Presentation -Title 'Query Construction Flow' -Kicker 'Data -> Filter -> Analyze -> Evidence'
    Add-Callout -Slide $slide -Left 60 -Top 130 -Width 175 -Height 82 -Text "DATA`nChoose a table" -Fill 'EAF3FF'
    Add-Callout -Slide $slide -Left 270 -Top 130 -Width 175 -Height 82 -Text "FILTER`nReduce noise" -Fill 'F4F0FF'
    Add-Callout -Slide $slide -Left 480 -Top 130 -Width 175 -Height 82 -Text "ANALYZE`nPivot or count" -Fill 'EEF7ED'
    Add-Callout -Slide $slide -Left 690 -Top 130 -Width 175 -Height 82 -Text "PRESENT`nShow proof" -Fill 'FFF6E5'
    Add-CodeBox -Slide $slide -Left 92 -Top 278 -Width 770 -Height 120 -Size 15 -Code @'
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| summarize count() by FileName
| order by count_ desc
'@
    Add-TextBox -Slide $slide -Left 95 -Top 420 -Width 760 -Height 45 -Text 'The goal is not a fancy query. The goal is a query that answers the question with evidence.' -Size 19 -Color '243F68' -Bold $true | Out-Null

    $slide = Add-SlideBase -Presentation $Presentation -Title 'Filtering With where' -Kicker 'Most important beginner operator'
    Add-Bullets -Slide $slide -Left 54 -Top 104 -Width 390 -Height 360 -Items @(
        'where keeps rows that match your condition.',
        'Use one where line per idea so beginners can read the query.',
        'Start broad, then add filters one at a time.',
        'Common filters: time, device, filename, command-line keyword.'
    ) -Size 19 | Out-Null
    Add-CodeBox -Slide $slide -Left 486 -Top 105 -Width 390 -Height 235 -Size 13 -Code @'
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
'@
    Add-Callout -Slide $slide -Left 486 -Top 363 -Width 390 -Height 72 -Text 'Ask students: which line scoped time, which line scoped device, and which line searched process name?' -Fill 'EAF3FF'

    $slide = Add-SlideBase -Presentation $Presentation -Title 'Where Patterns Students Will Use' -Kicker 'Operator cheat sheet'
    Add-Bullets -Slide $slide -Left 52 -Top 102 -Width 410 -Height 370 -Items @(
        '== exact match: DeviceName == TargetDevice',
        '=~ case-insensitive exact filename match',
        'has: one word-based clue',
        'has_any: any clue in a list can match',
        'has_all: every clue in a list must match',
        'endswith: file extensions like .dmp'
    ) -Size 18 | Out-Null
    Add-CodeBox -Slide $slide -Left 500 -Top 106 -Width 360 -Height 245 -Size 13 -Code @'
| where FileName =~ "Rubeus.exe"
| where ProcessCommandLine has "reg save"
| where FileName has_any ("mimikatz", "rubeus")
| where ProcessCommandLine has_all ("reg save", "hklm\\sam")
| where FileName endswith ".dmp"
'@
    Add-Callout -Slide $slide -Left 500 -Top 375 -Width 360 -Height 60 -Text 'Coach line: choose the operator based on how specific your clue is.' -Fill 'FFF6E5'

    $slide = Add-SlideBase -Presentation $Presentation -Title 'Presenting Evidence With project' -Kicker 'Make results readable'
    Add-Bullets -Slide $slide -Left 54 -Top 104 -Width 395 -Height 345 -Items @(
        'project keeps only the columns that answer the question.',
        'Good evidence columns: Timestamp, DeviceName, FileName, command line, SHA256.',
        'For file events, keep ActionType and FolderPath.',
        'For alerts, keep Title, Severity, AttackTechniques.'
    ) -Size 19 | Out-Null
    Add-CodeBox -Slide $slide -Left 490 -Top 112 -Width 380 -Height 210 -Size 13 -Code @'
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "mimikatz"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
'@
    Add-Callout -Slide $slide -Left 490 -Top 350 -Width 380 -Height 64 -Text 'Mini-exercise: remove SHA256, run it, then add it back. Which result is better for reporting?' -Fill 'EEF7ED'

    $slide = Add-SlideBase -Presentation $Presentation -Title 'Counting With summarize' -Kicker 'Answer how many and which ones'
    Add-Bullets -Slide $slide -Left 54 -Top 104 -Width 390 -Height 345 -Items @(
        'summarize turns many rows into an answer.',
        'count() answers how many rows matched.',
        'by chooses the grouping column.',
        'min() and max() find first and last seen.',
        'make_set() collects distinct values.'
    ) -Size 19 | Out-Null
    Add-CodeBox -Slide $slide -Left 490 -Top 104 -Width 380 -Height 255 -Size 13 -Code @'
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| summarize Events=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by FileName
| order by Events desc
'@
    Add-Callout -Slide $slide -Left 490 -Top 382 -Width 380 -Height 56 -Text 'Use summarize when the CTF asks for counts, first/last seen, or file lifecycle.' -Fill 'F4F0FF'

    $slide = Add-SlideBase -Presentation $Presentation -Title 'Pivoting Like A Hunter' -Kicker 'One clue creates the next query'
    Add-Bullets -Slide $slide -Left 54 -Top 104 -Width 380 -Height 345 -Items @(
        'Find a suspicious file.',
        'Copy the filename or hash.',
        'Search alerts for that clue.',
        'Use alert title and technique to explain why it matters.',
        'Return to file/process evidence to prove the timeline.'
    ) -Size 19 | Out-Null
    Add-CodeBox -Slide $slide -Left 474 -Top 98 -Width 410 -Height 285 -Size 12 -Code @'
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "rubeus"
| project Timestamp, FileName, FolderPath, SHA256

AlertEvidence
| where Timestamp > ago(7d)
| where FileName has "rubeus" or SHA256 == "<hash>"
| project Timestamp, Title, AttackTechniques, SHA256
'@
    Add-Callout -Slide $slide -Left 474 -Top 407 -Width 410 -Height 56 -Text 'Coach line: do not memorize every query. Learn how to pivot from a clue.' -Fill 'EAF3FF'

    $slide = Add-SlideBase -Presentation $Presentation -Title 'Combining Tables With union' -Kicker 'When one table is not enough'
    Add-Bullets -Slide $slide -Left 54 -Top 104 -Width 370 -Height 360 -Items @(
        'Use union when evidence is split across process, file, and alert tables.',
        'Each branch should project similar columns.',
        'Add EvidenceType so students know where the row came from.',
        'Sort by Timestamp to make a timeline.'
    ) -Size 18 | Out-Null
    Add-CodeBox -Slide $slide -Left 455 -Top 98 -Width 450 -Height 330 -Size 11 -Code @'
union isfuzzy=true
(
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
    | project Timestamp, EvidenceType="File", Detail=strcat(ActionType, " | ", FileName)
),
(
    AlertEvidence
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
    | project Timestamp, EvidenceType="Alert", Detail=strcat(Title, " | ", FileName)
)
| order by Timestamp asc
'@
}

$scenarios = @(
    [pscustomobject]@{
        Number='00'; Title='Warm-Up: Rebuild the Attack Timeline'; Skill='let, union, project, order by, workstation scoping';
        Brief='Before chasing individual scenarios, rebuild the AttackIQ timeline on the workstation.';
        Build=@('Scope to TargetDevice and last 7 days.','Start with DeviceProcessEvents and take 20 rows.','Project Timestamp, EvidenceType, and Detail.','Use union to combine process, file, and alert evidence.');
        Challenge='What launched the attack, what account ran it, and where did the runtime unpack?';
        Answer='Launcher: SecBase_security-control-baseline-endpoint-edr_V1_0_51_amd64_gui-sig.exe. Account: xadmin. Runtime: C:\Users\xadmin\Downloads\.ghostex-cli-wd-2170286878. Orchestrator: python.exe running attack_graph.py.';
        Query=@'
let TargetDevice = "usm262346";
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
    | project Timestamp, EvidenceType="Process", Detail=ProcessCommandLine
),
(
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
    | project Timestamp, EvidenceType="File", Detail=strcat(ActionType, " | ", FileName)
),
(
    AlertEvidence
    | where Timestamp > ago(7d)
    | where DeviceName == TargetDevice
    | project Timestamp, EvidenceType="Alert", Detail=Title
)
| order by Timestamp asc
'@
    },
    [pscustomobject]@{
        Number='01'; Title='Credentials In Registry Script'; Skill='Exact filename match plus alert technique pivot';
        Brief='The attacker uses a PowerShell script related to credentials stored in the registry.';
        Build=@('Find the script in DeviceFileEvents.','Search command lines for the script name.','Pivot to AlertEvidence for ATT&CK context.','Keep FileName, Title, AttackTechniques, and SHA256.');
        Challenge='Which script is the registry-creds clue, and which ATT&CK technique did Defender attach to it?';
        Answer='Script: credentials_in_registry.ps1. Alert: malicious PowerShell cmdlet. ATT&CK: Credentials in Registry (T1552.002).';
        Query=@'
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName =~ "credentials_in_registry.ps1"
| where Title has_any ("PowerShell", "Registry", "Credentials") or AttackTechniques has_any ("Credentials in Registry", "T1552.002")
| project Timestamp, Title, FileName, AttackTechniques, SHA256
'@
    },
    [pscustomobject]@{
        Number='02'; Title='Dump SAM Registry Hive via reg save'; Skill='has_all for multi-clue command-line behavior';
        Brief='The attacker tries to save the local SAM registry hive from the command line.';
        Build=@('Start in DeviceProcessEvents.','Search ProcessCommandLine for reg save.','Require hklm\\sam with has_all.','Read the output path from the command line.');
        Challenge='Where did the attacker try to save the SAM hive?';
        Answer='The command attempted: reg save hklm\sam C:\Users\xadmin\AppData\Local\Temp\sam. Defender also produced RegistryExfil prevention evidence.';
        Query=@'
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has_all ("reg save", "hklm\\sam")
| project Timestamp, FileName, ProcessCommandLine, AccountName
'@
    },
    [pscustomobject]@{
        Number='03'; Title='Browser Data via Esentutl and PowerShell'; Skill='Parent-child process pivots';
        Brief='PowerShell launches a script and esentutl.exe works with browser/WebCache data.';
        Build=@('Search for powershell.exe and esentutl.exe.','Look for collect_database_webcache.ps1 and WebCache.','Use InitiatingProcessCommandLine to explain who launched esentutl.exe.','Project both child and parent command lines.');
        Challenge='Which process launched esentutl.exe, and what cache path was targeted?';
        Answer='Parent: powershell.exe. Script: collect_database_webcache.ps1. Child: esentutl.exe. Target includes C:\Users\xadmin\AppData\Local\Microsoft\Windows\WebCache.';
        Query=@'
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName in~ ("powershell.exe", "esentutl.exe")
| where ProcessCommandLine has_any ("collect_database_webcache.ps1", "esentutl", "WebCache") or InitiatingProcessCommandLine has "collect_database_webcache.ps1"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
'@
    },
    [pscustomobject]@{
        Number='04'; Title='Kerberoasting Using Rubeus'; Skill='Blocked tool evidence in file and alert tables';
        Brief='Rubeus is staged for Kerberoasting, but Defender interrupts the move.';
        Build=@('Start with DeviceFileEvents for Rubeus.exe.','Pivot to AlertEvidence.','Look for Kerberoasting or T1558.003.','Use SHA256 as durable proof.');
        Challenge='What file name and hash identify the Rubeus attempt?';
        Answer='File: Rubeus.exe. Hash: 1e1fe8a1730bf8caabd867fd2f990b0e52aee0f9f8635578ff8b18c0950b616c. Technique: Kerberoasting (T1558.003).';
        Query=@'
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName =~ "Rubeus.exe"
| where FileName =~ "Rubeus.exe" or AttackTechniques has_any ("Kerberoasting", "T1558.003")
| project Timestamp, Title, FileName, AttackTechniques, SHA256
'@
    },
    [pscustomobject]@{
        Number='05'; Title='PowerShell Empire Invoke-Kerberoast'; Skill='has_any for related script artifacts';
        Brief='The attacker switches from an executable to PowerShell Kerberoasting scripts.';
        Build=@('Search DeviceFileEvents for kerberoast.','Use has_any for invoke-kerberoast and call-invoke-kerberoast.','Pivot to AlertEvidence for Defender context.','Compare wrapper script and payload script.');
        Challenge='Which two PowerShell files were staged for the Kerberoasting test?';
        Answer='call-invoke-kerberoast.ps1 and invoke-kerberoast.ps1. Defender detections were tied to invoke-kerberoast.ps1.';
        Query=@'
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has_any ("invoke-kerberoast", "call-invoke-kerberoast")
| project Timestamp, ActionType, FileName, FolderPath, SHA256
'@
    },
    [pscustomobject]@{
        Number='06'; Title='LSASS Minidump'; Skill='Pattern hunting with endswith and alert titles';
        Brief='The attacker tries to dump LSASS. A dump file appears and Defender raises DumpLsass evidence.';
        Build=@('Search DeviceFileEvents for FileName endswith .dmp.','Look for pid_ path patterns.','Search AlertEvidence for DumpLsass or LSASS.','Map to LSASS Memory T1003.001.');
        Challenge='What dump file was created, and what ATT&CK sub-technique did the alert map to?';
        Answer='Dump file: pid_976_2ztj_d6a.dmp. Alert: DumpLsass hacktool prevented. Technique: LSASS Memory (T1003.001).';
        Query=@'
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName endswith ".dmp" or FolderPath has "pid_"
| project Timestamp, ActionType, FileName, FolderPath
'@
    },
    [pscustomobject]@{
        Number='07'; Title='Dump Passwords Using PwDump7'; Skill='Prevented tool evidence';
        Brief='PwDump7 is staged and Defender prevents the credential dumping attempt.';
        Build=@('Search file events for pwdump.','Search alert titles for PWDump.','Read Title and Severity to understand outcome.','Explain attempted vs successful execution.');
        Challenge='Was PwDump executed cleanly, or was it prevented? What tells you?';
        Answer='Artifact: pwdump7.zip. Defender alert: PWDump hacktool was prevented. Outcome: attempted and prevented.';
        Query=@'
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName has "pwdump"
| where Title has "PWDump" or FileName has "pwdump"
| project Timestamp, Title, Severity, FileName, SHA256
'@
    },
    [pscustomobject]@{
        Number='08'; Title='Dump Passwords Using gsecdump'; Skill='Artifact name versus detection name';
        Brief='gsecdump is staged, but Defender may label it with a detection family rather than the tool name.';
        Build=@('Find gsecdump in DeviceFileEvents.','Search AlertEvidence for gsecdump or Vigorf.','Compare staged artifact to alert title.','Teach that product verdicts may not repeat the tool name.');
        Challenge='What did Defender call the threat, and what was the actual staged file name?';
        Answer='Staged file: gsecdump-0.7-win32.zip. Defender alert: Vigorf malware was prevented.';
        Query=@'
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName has "gsecdump"
| where FileName has "gsecdump" or Title has_any ("Vigorf", "malware")
| project Timestamp, Title, Severity, FileName
'@
    },
    [pscustomobject]@{
        Number='09'; Title='Dump Passwords Using LaZagne'; Skill='File lifecycle with ActionType and summarize';
        Brief='LaZagne appears on disk and is later cleaned up.';
        Build=@('Search FileName has lazagne.','Keep ActionType in the output.','Sort by Timestamp asc to see lifecycle.','Use summarize make_set(ActionType) for a compact answer.');
        Challenge='How do we know the tool was cleaned up after staging?';
        Answer='Artifact: laZagne_windows_x64.exe. Evidence shows it was created and later deleted. Cleanup did not erase telemetry.';
        Query=@'
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| summarize Actions=make_set(ActionType), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by FileName
'@
    },
    [pscustomobject]@{
        Number='10'; Title='Obfuscated Mimikatz'; Skill='Behavior verdict beats process-name-only hunting';
        Brief='Mimikatz-style behavior appears as a PowerShell script rather than mimikatz.exe.';
        Build=@('Search file events for mimikatz script artifacts.','Search alert titles for Mimikatz credential theft tool.','Explain why process-name-only hunts miss this.','Keep Title, Severity, FileName, SHA256.');
        Challenge='What makes this different from simply looking for mimikatz.exe?';
        Answer='Artifact: mimikatz_dump_passwords_v2.ps1. Defender verdict: Mimikatz credential theft tool. The hunt works even without mimikatz.exe execution.';
        Query=@'
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName has "mimikatz"
| where Title has "Mimikatz credential theft tool" or FileName =~ "mimikatz_dump_passwords_v2.ps1"
| project Timestamp, Title, Severity, FileName, SHA256
'@
    },
    [pscustomobject]@{
        Number='11'; Title='Original Mimikatz'; Skill='Report-ready proof with filename, verdict, and hash';
        Brief='The classic Mimikatz package is staged and Defender identifies it.';
        Build=@('Find mimikatz-x64.zip.','Pull Defender verdict from AlertEvidence.','Project SHA256 for durable evidence.','Answer with file, hash, device, time, verdict.');
        Challenge='Which Mimikatz artifact was blocked, and what hash identifies it in alert evidence?';
        Answer='Artifact: mimikatz-x64.zip. Verdict: Mimikatz credential theft tool. Hash: 29a3e90d067a848bac1d7301e22d6ac7b6979c89be10373b98a47845e94c45b8.';
        Query=@'
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(7d)
| where DeviceName == TargetDevice or FileName =~ "mimikatz-x64.zip"
| where FileName =~ "mimikatz-x64.zip" or Title has "Mimikatz credential theft tool"
| project Timestamp, Title, Severity, FileName, SHA256
'@
    }
)

function Add-ScenarioSlides {
    param([object]$Presentation, [object[]]$ScenarioList)
    foreach ($scenario in $ScenarioList) {
        $slide = Add-SlideBase -Presentation $Presentation -Title ("Scenario {0}: {1}" -f $scenario.Number, $scenario.Title) -Kicker 'Scenario brief'
        Add-Bullets -Slide $slide -Items @(
            $scenario.Brief,
            "KQL skill: $($scenario.Skill)",
            'Student flow: read the brief, learn the query idea, build it slowly, then answer the challenge.',
            'Instructor reminder: do not show the full query until students have tried the build steps.'
        ) -Size 19 | Out-Null
        Add-Callout -Slide $slide -Left 70 -Top 404 -Width 790 -Height 60 -Text ("CTF challenge: {0}" -f $scenario.Challenge) -Fill 'FFF6E5'

        $slide = Add-SlideBase -Presentation $Presentation -Title ("Scenario {0}: Build It Slowly" -f $scenario.Number) -Kicker $scenario.Title
        Add-Bullets -Slide $slide -Items $scenario.Build -Left 54 -Top 108 -Width 430 -Height 350 -Size 18 | Out-Null
        Add-CodeBox -Slide $slide -Left 520 -Top 110 -Width 355 -Height 245 -Size 11 -Code $scenario.Query
        Add-Callout -Slide $slide -Left 520 -Top 382 -Width 355 -Height 62 -Text 'Ask: which table, which filter, which proof columns?' -Fill 'EAF3FF'

        $slide = Add-SlideBase -Presentation $Presentation -Title ("Scenario {0}: Answer Key" -f $scenario.Number) -Kicker 'Check your work'
        Add-TextBox -Slide $slide -Left 54 -Top 108 -Width 820 -Height 56 -Text ("Challenge: $($scenario.Challenge)") -Size 20 -Color '243F68' -Bold $true | Out-Null
        Add-Callout -Slide $slide -Left 54 -Top 184 -Width 820 -Height 95 -Text $scenario.Answer -Fill 'EEF7ED'
        Add-Bullets -Slide $slide -Left 72 -Top 310 -Width 790 -Height 140 -Items @(
            'How the KQL finds it: start with the table most likely to hold the evidence.',
            'Use where filters to reduce to the device, time, and scenario clue.',
            'Use project to show only the columns that prove the answer.',
            'If one table is incomplete, pivot to file or alert evidence.'
        ) -Size 17 | Out-Null
    }
}

function Add-InstructorSlides {
    param([object]$Presentation)
    $slide = Add-SlideBase -Presentation $Presentation -Title 'Instructor Notes: When Students Get Lost' -Kicker 'Delivery support'
    Add-Bullets -Slide $slide -Items @(
        'Ask: which table should contain this evidence: process, file, or alert?',
        'Ask: which column contains the command line?',
        'Ask: which column contains the Defender verdict?',
        'Ask: can we reduce noise with DeviceName == TargetDevice?',
        'Ask: can we prove when, where, what, and why it matters?'
    ) -Size 20 | Out-Null
    Add-Callout -Slide $slide -Left 76 -Top 410 -Width 790 -Height 58 -Text 'Keep coming back to the same rhythm: table -> filter -> pivot -> evidence.' -Fill 'FFF6E5'

    $slide = Add-SlideBase -Presentation $Presentation -Title 'Optional XDR Incident Pivot' -Kicker 'Use only if the customer has the incident'
    Add-Bullets -Slide $slide -Left 54 -Top 102 -Width 390 -Height 360 -Items @(
        'Incident IDs are tenant-specific.',
        'Alert grouping can vary by tenant and policy.',
        'Do not make the class depend on a matching incident.',
        'If present, use the incident as a story hook, then pivot back to Advanced Hunting.',
        'Endpoint telemetry remains the ground truth for the lab.'
    ) -Size 18 | Out-Null
    Add-CodeBox -Slide $slide -Left 485 -Top 105 -Width 390 -Height 285 -Size 12 -Code @'
let IncidentIdToReview = "PUT-INCIDENT-ID-HERE";
AlertInfo
| where Timestamp > ago(7d)
| where IncidentId == IncidentIdToReview
| project Timestamp, IncidentId, AlertId, Title, Severity, AttackTechniques
| order by Timestamp asc
'@
    Add-Callout -Slide $slide -Left 485 -Top 414 -Width 390 -Height 50 -Text 'If this returns nothing, skip it and continue with scenario queries.' -Fill 'EAF3FF'

    $slide = Add-SlideBase -Presentation $Presentation -Title 'Wrap-Up Challenge' -Kicker 'End of class'
    Add-Bullets -Slide $slide -Items @(
        'Which scenarios produced process execution evidence?',
        'Which scenarios were primarily caught through AlertEvidence?',
        'Which scenarios left file-staging artifacts?',
        'Which KQL operator helped most today?',
        'If this were a real workstation compromise, what would you investigate next?'
    ) -Size 22 | Out-Null
    Add-Callout -Slide $slide -Left 74 -Top 410 -Width 795 -Height 58 -Text 'Instructor closer: the goal is not memorizing queries; the goal is learning how to ask better questions of endpoint telemetry.' -Fill 'EEF7ED'
}

$powerPoint = $null
$presentation = $null
try {
    $powerPoint = New-Object -ComObject PowerPoint.Application
    $powerPoint.Visible = 1
    $presentation = $powerPoint.Presentations.Add()
    $presentation.PageSetup.SlideWidth = 960
    $presentation.PageSetup.SlideHeight = 540

    Add-TitleSlide -Presentation $presentation
    Add-AgendaSlides -Presentation $presentation
    Add-KqlRefresherSlides -Presentation $presentation
    Add-ScenarioSlides -Presentation $presentation -ScenarioList $scenarios
    Add-InstructorSlides -Presentation $presentation

    if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }
    $presentation.SaveAs($OutputPath, 24)
    Write-Host "Created PowerPoint deck: $OutputPath"
    Write-Host "Slide count: $($presentation.Slides.Count)"
}
finally {
    if ($presentation) { $presentation.Close() }
    if ($powerPoint) { $powerPoint.Quit() }
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($presentation) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($powerPoint) | Out-Null
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}