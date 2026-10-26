# Week 6 — PowerShell & Endpoint Investigation

Week 6 of my self-designed 12-week SOC L1 curriculum. Focus: reading endpoint evidence (process trees, command lines, PowerShell, persistence) and defending a verdict with evidence rather than tool names.

> **Transparency.** All cases use **synthetic data** (fictional hosts, users and domains; documentation-range IPs). The scenarios were generated with an AI assistant, which also reviewed my reasoning. The "answer key" is the scenario author's design, not a real incident, and the scores are an AI reviewer's rough estimates, not an official assessment.

## Objectives
- Read parent → child process chains and command lines; separate normal from suspicious.
- Decode Base64 PowerShell (`-enc`) with CyberChef (From Base64 → UTF-16LE).
- Identify persistence: Run keys, scheduled tasks, services, Startup folder.
- Classify evidence as strong / medium / weak / noise.
- Write a verdict (TP / FP / UNDETERMINED) with confidence, missing evidence, "what would change my mind", a response plan and a 3–5 sentence English summary.

## How the week ran
- **Days 1–3:** guided explanations with practice exercises (process tree and command line; PowerShell and Base64; persistence). Exercise answers: *Not recorded.*
- **Days 4–7:** six simulated cases. Order completed: C1, C2, C3, C4 (resubmitted), C6 (bonus), C5 (final test, no hints).

## Results
| Case | Scenario | Answer key | My first verdict | First try correct | AI-reviewer score (/10) |
|---|---|---|---|---|---|
| [C1](cases/case-01.md) | SCCM-deployed encoded PowerShell | FP | FP | Yes | 6 |
| [C2](cases/case-02.md) | Word attachment → PowerShell → fake svchost | TP | TP | Yes | 7 → 8 |
| [C3](cases/case-03.md) | PsExec during maintenance window | FP | FP (low confidence) | Yes | 6.5 |
| [C4](cases/case-04.md) | ZIP → disguised .lnk → certutil → rundll32 → task | TP | FP | **No** | 4.5 → 6 |
| [C5](cases/case-05.md) | Scheduled shadow-copy cleanup (final test) | FP | FP | Yes | 6 |
| [C6](cases/case-06.md) | Cracked installer → disguised scheduled task (bonus) | TP | TP | Yes | 6.5 → 7.5 |

In C1 I typed "FT"; I meant FP (kept verbatim in the original report). 5 of 6 verdicts were right on the first try. The gap was not the verdict but the **reasoning behind it**.

## Key lessons
1. **No damage is not evidence of innocence.** I called a malicious chain a false positive because "nothing was stolen" (C4). The chain is the evidence.
2. **Same tool, different commands.** `certutil -hashfile` is routine; `certutil -urlcache -split -f` is a download.
3. **Several artifacts can be one persistence mechanism** (file + event 4698 + task runs = one scheduled task).
4. **"What would change my mind" must be verifiable and opposite to my verdict.** "Nothing" or "ask the user" is not an answer.
5. **Read every SIEM note before judging.** In C5 the baseline (same task for three weeks, task created 24 days earlier) was the strongest evidence.

## Files
- [`reference.md`](reference.md) — condensed reference
- [`mistake-log.md`](mistake-log.md) — recurring mistakes and rules
- [`templates/`](templates/) — report template and pre-submission checklist
- [`cases/`](cases/) — the six cases
- [`README.AR.md`](README.AR.md) — Arabic version

## Limitations / not recorded
- Session dates and time spent per case: *Not recorded.*
- Day 1–3 exercise answers: *Not recorded.*
- Original submissions are included verbatim in each case file (spelling errors kept; whitespace normalized; long Base64 strings omitted).
- Synthetic data is simpler than real telemetry: no volume, noise or time pressure.

## References used for study
CyberChef; SANS *Hunt Evil* poster; LOLBAS project; MITRE ATT&CK; Microsoft Learn (event IDs, Sysinternals/Sysmon).
