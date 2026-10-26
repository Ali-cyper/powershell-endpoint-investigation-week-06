# Week 6 Reference — Endpoint Investigation

## 1. Method
1. Read the alert: rule, host, user, time. 2. Build a timeline in your own words. 3. Start at the first event. 4. For every process ask: **who** ran it, **parent**, full **command line**, **path**, **when / does it fit**. 5. Decode anything encoded. 6. Compare with normal activity on the same host. 7. Read all SIEM notes. 8. Classify evidence. 9. One-sentence story that explains all evidence. 10. Verdict, missing evidence, what would change my mind. 11. Complete, ordered response.

*Initial alert* = the event that triggered the rule. *Timeline start* = the first event of the story. They can differ.

## 2. Normal Windows process tree
| Process | Role | Normal parent | Note |
|---|---|---|---|
| `smss.exe` | Session manager | System | starts `csrss`, `wininit`, `winlogon` |
| `wininit.exe` | System init | `smss` | starts `services`, `lsass` |
| `services.exe` | Service control | `wininit` | parent of `svchost` |
| `svchost.exe` | Hosts services | `services.exe` | always has `-k`; path `System32` |
| `lsass.exe` | Credentials | `wininit` | one instance, no children |
| `winlogon.exe` → `userinit.exe` → `explorer.exe` | Logon → desktop | — | `userinit` exits; `explorer` may show no parent |

Programs opened by hand are children of `explorer.exe`.

## 3. Suspicious parent → child (leads, not verdicts)
- Office (`WINWORD`, `EXCEL`, `OUTLOOK`) → `cmd` / `powershell` / `wscript` / `mshta`
- Browser → `powershell`; `explorer` → `.lnk` or script from Downloads
- `w3wp.exe` → `cmd` / `powershell` (webshell); `wmiprvse.exe` → `powershell` (remote WMI)
- `svchost` without `-k` or outside `System32`; `services.exe` → binary from Temp/AppData
- Common and usually normal: `explorer` → `powershell` with no arguments, opened by the user.

## 4. PowerShell options and command patterns
| Item | Meaning | Alone proves? |
|---|---|---|
| `-nop` / `-NoProfile` | skip user profile | No |
| `-w hidden` / `-WindowStyle Hidden` | hidden window | Weak signal |
| `-ep bypass` | bypass script policy (not a security boundary) | Weak signal |
| `-enc` / `-EncodedCommand` | Base64 command | Decode it |
| `iwr`, `DownloadFile`, `DownloadString` | download | Check source |
| `IEX` / `Invoke-Expression` | run text as code | Strong with download |

Three questions: does it **download**, does it **execute text as code**, does it **hide**?

## 5. Base64 / encoded commands
Not encryption. In CyberChef: **From Base64 → Decode text (UTF-16LE)**. Decoding alone is not a verdict; judge the content. Event **4104** shows the real script even if encoded (when logging is enabled and collected).

## 6. Same tool, different use
| Tool | Normal | Suspicious |
|---|---|---|
| `certutil` | `-hashfile` | `-urlcache -split -f` (download) |
| `rundll32` | exported function of a real DLL | non-DLL file (`.dat`) from Temp/AppData |
| `schtasks` | maintenance tasks | `/create` from an odd process, path in AppData |
| `PsExec` / `PSEXESVC` | admin remote execution | unexpected source host, no ticket |
| `vssadmin` | `delete shadows /oldest` housekeeping | `delete shadows /all /quiet` with ransomware signs |

## 7. Paths
System binaries: `C:\Windows\System32`. User-writable: `Temp`, `AppData`, `Users\Public`, `Downloads`. A "system" name in a user-writable folder is a masquerade. Watch typos (`svch0st`), double extensions (`.pdf.lnk`) and vendor-like names in odd paths.

## 8. Persistence
| Location | Detail | Logs |
|---|---|---|
| Run keys | `HKCU\...\CurrentVersion\Run`, `HKLM\...\Run` | Sysmon 13 |
| Scheduled tasks | Task Scheduler | 4698, TaskScheduler 200/201, Sysmon 1 (`schtasks`) |
| Services | service list | 7045 / 4697, 7036 |
| Startup folder | `...\Start Menu\Programs\Startup` | Sysmon 11 |

Ask: what runs, who created it and when, normal path, known/signed, what happened before. **One mechanism = one finding** even if it leaves several artifacts. Record: type, name, command, creator, interval.

## 9. Event IDs
| Event | Meaning |
|---|---|
| Security 4688 | process created (command line needs auditing) |
| Security 4624 | logon (type 3 network, 10 RDP, 2 interactive) |
| Security 4698 | scheduled task created |
| Security 4697 / System 7045 | service installed |
| System 7036 | service state change |
| PowerShell 4104 | script block |
| Sysmon 1 / 3 / 11 / 13 / 22 | process / network / file create / registry value set / DNS |

## 10. Evidence strength
- **Strong:** decoded content that downloads/executes or steals; known-bad indicator; abnormal parent with suspicious command; persistence tied to the same activity; (towards benign) an official change record that matches.
- **Medium:** file in Temp/AppData; unsigned; masqueraded name; odd hour with suspicious activity; (towards benign) signed known parent as SYSTEM.
- **Weak:** `-enc`, hidden, bypass, `-nop`; PowerShell use alone; creation of a text file; internal connection.
- **Noise:** routine repeating events (updaters, developer tools).
Strength depends on context; independent sources add up, repeated copies of one artifact do not.

## 11. Verdict
**TP** real threat · **FP** benign activity · **UNDETERMINED** insufficient evidence (state exactly what would decide it). Authorized test = *benign true positive*. Judge by the chain of evidence, not by damage. Confidence follows strength and independence of evidence. "What would change my mind" must oppose the verdict and be verifiable (hash, script content, domain owner, ticket); a user's denial is not verification.

## 12. Response order
**Malicious:** isolate → preserve evidence → remove the mechanism → block domain/IP → scope (same hash/domain/task across hosts and mailboxes, activity before/after) → reset credentials → escalate.
**Benign:** confirm approval → review script → close as FP → tune the rule for this task without disabling it.

## 13. Glossary
Parent/child · Command line · LOLBin (legitimate tool abused) · Persistence · Mark of the Web · IOC · Baseline · Scoping · Beacon · C2 · TP / FP / benign TP.
