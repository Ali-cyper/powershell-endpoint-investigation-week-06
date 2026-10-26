# Case 5 — Shadow-copy deletion by a scheduled task (W6-C5, final test)

*Synthetic data. Answer key = scenario author's design. No hints were given for this case.*

- **Alert:** SIEM "Volume Shadow Copy Deletion (Possible Ransomware)" (Critical)
- **Host:** FILE-SRV-01 (finance file server)
- **When:** Friday 03:00

## Evidence
| Time | Source | Event |
|---|---|---|
| 02:00–02:12 | Defender | Scheduled quick scan, no threats |
| 03:00:00 | Task Scheduler 200 | Task `\StorageCleanup` started as SYSTEM |
| 03:00:01 | Sysmon 1 | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\vss_cleanup.ps1`, parent `svchost.exe -k netsvcs -p -s Schedule` |
| 03:00:02 | Sysmon 1 | `vssadmin.exe list shadows` |
| 03:00:03 | Sysmon 1 | `vssadmin.exe delete shadows /for=C: /oldest /quiet` |
| 03:00:06 | Sysmon 1 | `vssadmin.exe list shadows` |
| 03:00:09 | Sysmon 11 | `C:\Scripts\vss_cleanup.log` updated |

SIEM notes: task created 24 days earlier (4698, `CORP\storage.admin`), scheduled Fridays 03:00; identical chain on the previous three Fridays; file-integrity monitoring: no change in `C:\Scripts` for 30 days; no `bcdedit`, `wbadmin delete` or `wevtutil cl`; no mass renames or new extensions; no external connections; no new tasks/services/Run keys today; script content not pulled; no ticket linked.

## IOCs
None.

## My original verdict
FP, low confidence.

## What was wrong / corrected
- Did not use the SIEM notes (task age, three-week baseline, FIM, absence of ransomware precursors).
- Persistence "not sure"; correct answer: one scheduled task, `\StorageCleanup`.
- Wrote "the user"; the actor is SYSTEM via Task Scheduler.
- "Missing evidence" unclear; real gaps: script content, approval/ticket, remaining shadow copies, same task on other servers.
- Good: asked why the alert fired this week (a real scoping question; likely a new or changed rule).
- Impact written as "none"; better: low, one old shadow copy removed, others remain, no encryption seen.

## Answer key
**FP, medium-to-high confidence.** Confirm approval and script content, then tune the rule for this task without disabling it (`/all /quiet` must still alert).

## Lessons
Read every SIEM note. Confidence should follow the strength of the evidence.

## Original report
*Verbatim as submitted (spelling errors kept). Whitespace normalized; long Base64 strings replaced with a marker. Evidence lines copied from the case are part of what I submitted.*

```
CASE ID:W6-C5
INITIAL ALERT (rule + host + time):SIEM «Volume Shadow Copy Deletion (Possible Ransomware)»، Security:Critical + host:FILE-SRV-01 time:03:00:03
TIMELINE :
02:00 – 02:12
Windows Defender.      Quick Scan
03:00:00
Task Scheduler
Task  \StorageCleanup start with pirmission  SYSTEM.
03:00:01
Child: powershell.exe
Parent(Schedule)C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule | User: SYSTEM
CommandLine:( powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\vss_cleanup.ps1)
03:00:02
Child. :C:\Windows\System32\vssadmin.exe Parent: powershell.exe | User: SYSTEM
• CommandLine: vssadmin.exe list shadows(show Backup)
03:00:03 | Sysmon 1
• Image: C:\Windows\System32\vssadmin.exe | Parent: powershell.exe | User: SYSTEM
CommandLine:
vssadmin.exe delete shadows /for=C: /oldest /quiet(delete backup )
03:00:06 | Sysmon 1
• Image: vssadmin.exe | Parent: powershell.exe | User: SYSTEM
• CommandLine: vssadmin.exe list shadows
03:00:06 | Sysmon 1
• Image: vssadmin.exe | Parent: powershell.exe | User: SYSTEM
• CommandLine: vssadmin.exe list shadows
03:00:09
• powershell.exe
C:\Scripts\vss_cleanup.log (chack)

ONE-SENTENCE STORY :the user access in Friday dawn 3:00:00 atfer that use command to show list backup and delete backup
PROCESS TREE / COMMAND LINE: Task Scheduler-> svchost.exe -> powershell.exe ->vssadmin.exe
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\vss_cleanup.ps1
vssadmin.exe delete shadows /for=C: /oldest /quiet
vssadmin.exe list shadows

PERSISTENCE :I not sure parent:svchost.exe child:powershell.exe (powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\vss_cleanup.ps1)
NETWORK:we not have any connections
WHAT I KNOW:the time the account and tge command and task the path
WHAT I ASSUME:Scheduled routine task
STRONGEST EVIDENCE : can you the command line
WEAKEST EVIDENC:the time friday dawn
MISSING EVIDENCE :the disparit the file
(We do not  have any suspicious evidence)
WHAT WOULD CHANGE MY MIND : محتوى الملف اذا كانت مهمة انشأة جديد اذا كان ينقل الbackup خارج الشركة معا حذف القديم كله  .
VERDICT: FP
CONFIDENCE (low) + IMPACT:do not have impact
RECOMMENDED RESPONSE : it is FP (لا نقوم باي اجراء يمكن بس نتأكد لي صارلها ثلاث مرات متتالية ليش بهذا السبوع طلع انذار بس اتأكد شنو السبب وهل اكو تغير بلمعومات اامهمة المجدولة وهل اكو حركة غريبة )
ENGLISH VERDICT : I assess this as false positive because  the host:FILE-SRV-01 have the schedule task every Friday dawn to take the path and access to the file and show the Backup and delete the last on  and chack
```

