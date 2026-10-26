# Case 6 (bonus) — Cracked installer creates a disguised scheduled task (W6-C6)

*Synthetic data. Answer key = scenario author's design.*

- **Alert:** EDR "Unsigned Executable Created Scheduled Task" (Medium), fired 10:02:41
- **Host / user:** SALES-PC-05 (sales), user `sara.n`
- **When:** Sunday 10:00–11:10

## Evidence
| Time | Source | Event |
|---|---|---|
| 10:01:12 | Sysmon 11 | `chrome.exe` creates `Downloads\Adobe_Photoshop_2026_Full_Crack.zip` (Mark of the Web; referrer `free-soft-example.test/dl/771`) |
| 10:02:30 | Sysmon 1 | `...\PS2026_Setup\Setup.exe` (**unsigned**), parent `explorer.exe` |
| 10:02:36 | Sysmon 11 | `Setup.exe` creates `...\AppData\Roaming\AdobeUpdate\svc_helper.ps1` |
| 10:02:40 | Sysmon 1 | `powershell.exe -nop -w hidden -ep bypass -enc ...`, parent `Setup.exe` |
| 10:02:41 | Sysmon 1 + 4698 | `schtasks.exe` (parent `powershell.exe`); task `AdobeAcrobatUpdateCheck` created |
| 10:15:00 | Sysmon 1 | `MicrosoftEdgeUpdate.exe /ua ...` (signed, Program Files, SYSTEM, task exists 6 months) — normal baseline |
| 10:32:41 | Sysmon 1 | `powershell.exe -w hidden -ep bypass -File ...\svc_helper.ps1`, parent `svchost.exe -k netsvcs -p -s Schedule` |
| 10:32:43 | Sysmon 22/3 + Proxy | DNS `update-adobe-example.test` → `192.0.2.55`, connection attempt `:443`, **Proxy DENIED** (newly registered domain) |
| 11:02:41 | — | Task ran again; same DNS lookup and denied connection |

SIEM notes: no AV alert; hashes of ZIP, `Setup.exe` and `svc_helper.ps1` not checked; script content and 4104 not pulled; no successful outbound connection from PowerShell.

## Decoded command
`schtasks /create /tn AdobeAcrobatUpdateCheck /tr "powershell.exe -w hidden -ep bypass -File C:\Users\sara.n\AppData\Roaming\AdobeUpdate\svc_helper.ps1" /sc minute /mo 30 /f`

## IOCs (synthetic)
`Adobe_Photoshop_2026_Full_Crack.zip`; `free-soft-example.test`; `Setup.exe`; `svc_helper.ps1`; task `AdobeAcrobatUpdateCheck`; `update-adobe-example.test` → `192.0.2.55`.

## My original verdict
TP, medium confidence; decoded the command correctly; marked persistence as one mechanism. Revised report improved "what would change my mind" (script content, hashes, task details).

## What was wrong / corrected
- Process tree for the task run: `svchost.exe` (Schedule service) → `powershell.exe`, not `schtasks.exe → powershell.exe`.
- Pasted the tree in the persistence field; should list type, name, command, creator, interval.
- Treated the blocked connection as the strongest evidence; it was an attempt, blocked by the proxy. The strongest: unsigned installer from cracked software → hidden PowerShell → masqueraded task from AppData.
- Impact "none"; better: network blocked, but code runs locally every 30 minutes and its content is unknown.
- Recommendation incomplete; first attempt of "what would change my mind" used "ask the user".

## Answer key
**TP, medium-to-high confidence.** Isolate, preserve the script/task XML, then remove the task; block the domain/IP; search the environment for the same hash/domain/task name.

## Lessons
A blocked outcome does not make the chain benign. Compare with the Edge update task: signed, Program Files, long-lived.

## Original report
*Verbatim as submitted (spelling errors kept). Whitespace normalized; long Base64 strings replaced with a marker. Evidence lines copied from the case are part of what I submitted.*

**First submission**

```
CASE ID:6W-C6
INITIAL ALERT :EDR «Unsigned Executable Created Scheduled Task.in the time 10:01:12 From user: sara.n Host:SALES-PC-05
TIMELINE : 10:01:12 (parent) chrome.exe  https://free-soft-example.test/dl/771 to created file Adobe_Photoshop_2026_Full_Crack.zip .
10:02:30 C:\Users\sara.n\Downloads\PS2026_Setup\Setup.exe (child )explorer.exe(parent).
10:02:36
Proces:  Setup.exe C:\Users\sara.n\AppData\Roaming\AdobeUpdate\svc_helper.ps1
10:02:40
 child: powershell.exe | Parent: Setup.exe
powershell.exe -nop -w hidden -ep bypass -enc [long Base64 string omitted] (after decryption: schtasks /create /tn AdobeAcrobatUpdateCheck /tr "powershell.exe -w hidden -ep bypass -File C:\Users\sara.n\AppData\Roaming\AdobeUpdate\svc_helper.ps1" /sc minute /mo 30 /f)
10:02:41
Created task in  schtasks.exe   powershell.exe
Name task is (AdobeAcrobatUpdateCheck).
10:32:41
Child  powershell.exe | Parent: svchost.exe -k netsvcs -p -s Schedule | User: sara.n
CommandLine: (powershell.exe -w hidden -ep bypass -File C:\Users\sara.n\AppData\Roaming\AdobeUpdate\svc_helper.ps1)
10:32:43
parent powershell.exe. update-adobe-example.test
Connection with 192.0.2.55
Proxy DENIED

ONE-SENTENCE STORY:the user used chrome to download file and use explorer.exe ro setup.exe to powershell.exe and created  task schtasks.exe   and connection with external ip
PROCESS TREE : 1-explorer.exe ->setup.exe
->powershell.exe --> schtasks.exe
2-schtasks.exe -> powershell.exe -> connected with external ip

DECODED COMMAND : created a new task   schtasks /create /tn AdobeAcrobatUpdateCheck /tr "powershell.exe -w hidden -ep bypass -File C:\Users\sara.n\AppData\Roaming\AdobeUpdate\svc_helper.ps1" /sc minute /mo 30 /f
PERSISTENCE :  explorer.exe ->setup.exe
->powershell.exe --> schtasks.exe   (schtasks /create /tn AdobeAcrobatUpdateCheck /tr "powershell.exe -w hidden -ep bypass -File C:\Users\sara.n\AppData\Roaming\AdobeUpdate\svc_helper.ps1" /sc minute /mo 30 /f)

NETWORK: connextion with external ip (
parent powershell.exe. update-adobe-example.test
Connection with 192.0.2.55
Proxy DENIED )
WHAT I KNOW: I know the time action and external ip and all process and the tree process and task schtasks.exe   and the name for file created .
WHAT I ASSUME (and what would prove it): it is action خبيث
STRONGEST EVIDENCE (and why):the connection with external ip 192.0.2.55(twice proxy:  Dany ) and created task schtasks.exe
WEAKEST EVIDENCE : command line (nop -w hidden -ep bypass)
MISSING EVIDENCE :file hash and this user have permission to do task
WHAT WOULD CHANGE MY MIND: the same last case 4 if it is test  (we don't have any think change my mind )  and ask the user if he do that action?and why?.
VERDICT: TP
CONFIDENCE :med + IMPAC:we don't  have impac
RECOMMENDED RESPONSE : chack  the domain and the ip if he is for normal company (google ......) or any services the my company used.  Isolation the computer and chack if the user
ENGLISH VERDICT : I assess this as a true positive because the user (look up ) created process explorer.exe ->setup.exe
->powershell.exe --> schtasks.exe   (schtasks /create /tn AdobeAcrobatUpdateCheck /tr "powershell.exe -w hidden -ep bypass -File C:\Users\sara.n\AppData\Roaming\AdobeUpdate\svc_helper.ps1" /sc minute /mo 30 /f) and used svchost.exe -k to connection with external ip put the proxy bany this action .
```

**Revised submission (after review)** — changes versus the first: initial alert time 10:02:41; process tree 2 = `svchost.exe(task) -> poweshell.exe -> svc_helper.ps1 (try with external ip 192.0.2.55)`; persistence "one mechanism" (الية واحدة); the rest below.

```
WHAT I ASSUME (and what would prove it): i think he is خبيث  نحتاج انو نربط الاحداث علمود نثبت انو خبيث
STRONGEST EVIDENCE (the proxy Deny twic try   with 192.0.2.55 and created task schtasks.exe (منتحل اسم Adobe) and used commend line with this (nop -w hidden -ep bypass)
WEAKEST EVIDENCE : The Setup.exe alone is not enough to prove malicious activity.
MISSING EVIDENCE :file hash
WHAT WOULD CHANGE MY MIND: 1-محتوى) الملف svc_helper.ps1) ه(هاش جميع الملفات) التي عدنا   تفاصيل المهمة(Task Scheduler) التي سوها شتسوي
VERDICT: TP
CONFIDENCE :(med++ )+ IMPAC:we don't  have impac
RECOMMENDED RESPONSE : chack  the domain and the ip if he is for normal company (google ......) or any services the my company used if not block the ip and domain.  Isolate the computer and remove the task and
ENGLISH VERDICT : I assess this as a true positive because the strongest evidence and suspicious action for this account like (منتحل شركة Adobe ) and create task and process.
```

*Note (translated):* I did not ignore the SYSTEM task (Edge); I judged it normal and left it. For the second one, the creation event and the process name are strange, so I wrote that it is impersonation. My English cannot express some ideas correctly. Question: when do I write the Initial Alert? I have trouble writing in English, so please be patient; I have ideas I cannot express well.

