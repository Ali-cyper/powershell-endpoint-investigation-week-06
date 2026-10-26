# Case 3 — PsExec service on a server at 02:14 (W6-C3)

*Synthetic data. Answer key = scenario author's design.*

- **Alert:** SIEM "PsExec Service Installed (Possible Lateral Movement)" (High)
- **Host:** APP-SRV-02 (application server)
- **When:** Wednesday 02:14

## Evidence
| Time | Source | Event |
|---|---|---|
| 02:13:58 | Security 4624 | Type 3 logon, `CORP\it.admin`, source `10.10.2.15` (name `ADM-JUMP-01`) |
| 02:14:03 | System 7045 | Service `PSEXESVC`, `%SystemRoot%\PSEXESVC.exe`, LocalSystem, installed by `CORP\it.admin` |
| 02:14:04 | Sysmon 1 | `C:\Windows\PSEXESVC.exe` (signed Microsoft), parent `services.exe`, SYSTEM |
| 02:14:05 | Sysmon 1 | `powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\patch_check.ps1`, parent `PSEXESVC.exe`, SYSTEM |
| 02:14:20 | Sysmon 3 | Connection to `10.10.8.30:8530` (`wsus01.corp.local`) |
| 02:14:41 | Sysmon 11 | `C:\Scripts\patch_check.log` created |
| 02:15:10 | System 7036 | `PSEXESVC` stopped and no longer in the service list |

SIEM notes: `patch_check.ps1` last modified two days earlier by `CORP\svc.deploy`; no external connection; no new tasks, persistent services or Run keys; 4104 enabled but not pulled; no AV alert; no historical baseline pulled.

## IOCs
None established. Artifacts only (see table).

## My original verdict
FP, low confidence. Reason given: "nothing stolen or changed".

## What was wrong / corrected
- Reason was negative; positive reasons: signed tool, source is an admin jump host, destination is the WSUS server, service cleaned up, no persistence, no external traffic.
- Did not identify what `wsus01` is; ignored that the script was modified two days earlier.
- Wrote that Script Block Logging was "not on"; it was enabled but the log was not pulled.
- "What would change my mind" listed items that would *confirm* FP instead of flipping it.

## Answer key
**FP, medium confidence.** Confirm with the change ticket, the script content/hash, and the last weeks' baseline.

## Lessons
Judge the context of a legitimate admin tool: who, from where, when, what it ran, what it contacted.

## Original report
*Verbatim as submitted (spelling errors kept). Whitespace normalized; long Base64 strings replaced with a marker. Evidence lines copied from the case are part of what I submitted.*

```
CASE ID:W6-C3
INITIAL ALERT (rule + host + time):PsExec Service Installed  - APP-SRV-02 - Down on Wenesday 2:14
TIMELINE :in the down on Wenesday 2:13:58 the use Access successfully for this account (Admin) and in 2:14:03 created service PSEXESVC in the path %SystemRoot%\PSEXESVC.exe (the user admin created this service ), in 2:14:03 the servecie.exe start this file  and after 1 sec the PSEXESVC open the powershell.exe(user system) to execution the command line (powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\patch_check.ps1), and (2:14:20)connected with the ip 10.10.8.30:8530 (private ip ), and created a new file in the path C:\Scripts\patch_check.log and in 2:15:10 the service PSEXESVC stop (7036)
PROCESS TREE / COMMAND LINE: C:\Scripts\patch_check.log
powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\patch_check.ps1
PERSISTENCE: don't have any key
NETWORK: connected with private ip 10.10.8.30:8530
STRONGEST EVIDENCE : this service execution powershall.exe command line and created file
WEAKEST EVIDENCE : bypass -  created service in down on Wenesday -connected with internal ip
MISSING EVIDENCE : • Script Block Logging is not on .
WHAT WOULD CHANGE MY MIND : if this service for work the company or the company have to solving the problem in 2:13 or the noticed about the created the service or this is test for the team security.
VERDICT: FP (the action is very suspicious put he do not do  a big  think like stole Date or change any thing. We have analysis more for furture  day.)
CONFIDENCE : low IMPAC: do not has effect.
RECOMMENDED RESPONSE : chack the personal account (admin ) if he access in 2:14 if yes ask him way.(If he any know the password  ) If not isolat the acount and change the password and chack if the outsider access to the company
ENGLISH VERDICT : the sameone access to the acount admin in the down on 2:13 and created a new service and this service opne powershall.exe and execution the command line after all this action  the service stop
```

