# Mistake Log — Week 6

| # | Mistake | Rule | Seen in |
|---|---|---|---|
| 1 | "Nothing was stolen, so FP" | Judge by the chain of evidence, not by damage. Damage may be blocked or not yet happened. | C1, C3, C4 |
| 2 | Merging two uses of one tool | Split commands: `certutil -hashfile` vs `-urlcache`. For each: parent, purpose, normal? | C4 |
| 3 | Counting every artifact as a persistence mechanism | One task = one mechanism, however many logs it leaves. Write type, name, command, creator, interval. | C4, C6 |
| 4 | "What would change my mind": "nothing" / "ask the user" | Must be opposite to my verdict and checkable (hash, script content, domain owner, ticket). A user's denial is not verification. | C2, C4, C6 |
| 5 | "Missing evidence" listing things I already have | Missing = what I do not have (hash, script content, reputation, scope, ticket). | C1, C2, C3 |
| 6 | Ignoring SIEM notes and baseline | Read every note before the verdict. | C3, C5 |
| 7 | Strongest/weakest reversed | Compare with the normal sample in the case. A fake `svchost.exe` in AppData is strong; `-enc` alone is weak. | C1, C2, C5 |
| 8 | Truncated or unordered recommendation | Isolate → preserve evidence → remove mechanism → block → scope → reset credentials → escalate. | C1, C2, C6 |
| 9 | "No impact" | Describe it: blocked / unknown / low, and why. | C1, C3, C5, C6 |
| 10 | Confidence not matching evidence | Confidence follows strength and independence of evidence. | C4, C5 |
| 11 | Process tree written as commands | Use arrows: `A → B → C`; copy names exactly. | C4, C6 |

## Language
Recurring spelling: PowerShell, registry, check, isolate, scheduled, command, parent, permission. `decode` (Base64 is not encryption). Use `at 03:00 AM`, not "dawn".
