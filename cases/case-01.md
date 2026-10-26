# Case 1 — Encoded PowerShell launched by the SCCM agent (W6-C1)

*Synthetic data. Answer key = scenario author's design.*

- **Alert:** SIEM "PowerShell Encoded + Hidden Window" (Medium)
- **Host / user:** FIN-PC-07 (finance), user `huda.k` logged in since 08:30
- **When:** Sunday 09:02 (working hours)

## Evidence
| Time | Source | Event |
|---|---|---|
| 09:02:11 | Sysmon 1 | `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand ...`; parent `C:\Windows\CCM\CcmExec.exe` (signed Microsoft); user SYSTEM |
| 09:02:12 | Sysmon 11 | Same process creates `C:\ProgramData\IT\inv.txt` |
| 09:02:13 | Sysmon 3 | Same process connects to `10.10.5.20:445` (`fs01.corp.local`, internal) |

SIEM notes: no new tasks/services (4698, 7045) or Run keys; no external connection from PowerShell; no Office/browser child processes; Script Block Logging (4104) not enabled on this host.

## Decoded command
Creates `C:\ProgramData\IT`, writes the names of folders under `C:\Users` to `inv.txt`, and copies the file to `\\fs01.corp.local\IT\Inventory\FIN-PC-07.txt`.

## IOCs
None established. Artifacts only: `C:\ProgramData\IT\inv.txt`, `\\fs01.corp.local\IT\Inventory\FIN-PC-07.txt`, `10.10.5.20:445`.

## My original verdict
FP (typed "FT"), low confidence. Decoded the command correctly. Reasoning leaned on "nothing was stolen / changed".

## What was wrong / corrected
- Strongest/weakest not compared with context; `-enc`/hidden/bypass are the weakest evidence (they only triggered the alert).
- "Missing evidence" left empty; real gaps: SCCM deployment record or change ticket, whether the same command ran on other hosts, share permissions, no 4104 log.
- Recommendation targeted "the account", but the account is SYSTEM.
- Initial alert should name the rule, host and time.

## Answer key
**FP, medium confidence.** Strong: parent is the SCCM agent, user SYSTEM, script only lists folder names to an internal share, no persistence or external traffic.

## Lessons
Judge the story, not `-enc` / hidden / bypass. Decode before judging.

## Original report
*Verbatim as submitted (spelling errors kept). Whitespace normalized; long Base64 strings replaced with a marker. Evidence lines copied from the case are part of what I submitted.*

```
CASE ID:5w-c1
INITIAL ALERT:in 9:02:11
EVIDENCE (C:\Windows\CCM\CcmExec.exe (perent) and C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  / powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand [long Base64 string omitted]  / connected  with ip 10.10.5.20 (internal ip )/ tiv.txt, FIN-PC-07.txt):
DECODED COMMAND : $ErrorActionPreference='Stop'
New-Item -ItemType Directory -Path C:\ProgramData\IT -Force | Out-Null
Get-ChildItem C:\Users -Directory | Select-Object -ExpandProperty Name | Out-File C:\ProgramData\IT\inv.txt
Copy-Item C:\ProgramData\IT\inv.txt \\fs01.corp.local\IT\Inventory\FIN-PC-07.txt -Force
STRONGEST EVIDENCE: the created proces (commend line) and connation with the file server (10.10.5.20).
WEAKEST EVIDENCE:created  a new file tiv.txt
MISSING EVIDENCE:  like the alert SIEM (sorry a do not find any thing to wirte).
VERDICT: FT
CONFIDENCE : low  +do not have any impact :
RECOMMENDED RESPONSE: 1- chack if this account have any suspicious action in the past or future 2- what he want to access(FIN-PC-07.txt what can steal into the file )
ENGLISH VERDICT : the acount system in 09:02:11 execution commend line this commend have hidden and bypass after one secend 09:02:12 created file and 09:02:13 connection with the file-server whose the company.
```

**Follow-up note (my words, translated):** "FT" was a spelling slip for FP. I wrote "maybe he steals" because I thought I must verify the account's activity before and after this action.

