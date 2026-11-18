# SWS405 – Lab 06: Static and Dynamic Malware Analysis

**Student:** Kinley Palden (02230287)
**Module:** SWS405 – Unit VII
**Date completed:** 19 November 2026

This repository holds my submission for the Unit VII practical. In the lab I analysed a **harmless ransomware-behaviour simulator** (`suspicious_sample.py`) on Kali Linux. The static analysis used `file`, hashing, `strings`, `xxd` and YARA without running the sample. The dynamic analysis then ran it under `strace` and compared the result against a file-system baseline, checked the network state and re-verified the sample hash.

> ⚠️ **Safety note:** the sample is a teaching simulator, not real malware. It only creates, reads and writes text files inside `./lab_workspace`. It does not encrypt, delete, persist or use the network. I reviewed its source code before running it.

## 📄 Start here

**[Lab06_Report.md](Lab06_Report.md)** is the full lab report. It covers the objective, environment, methodology, all Part A and Part B steps with screenshots, the static-vs-dynamic comparison, IOCs, answers to the 9 practical questions, limitations and the conclusion.

## Repository structure

```
.
├── README.md                     ← this file
├── Lab06_Report.md               ← full lab report (with embedded screenshots)
├── lab01.docx                    ← original lab manual / instructions
├── screenshots/                  ← evidence screenshots 1–14 (referenced by the report)
├── samplefile/                   ← files supplied by the instructor
│   ├── suspicious_sample.py      ← the training sample
│   ├── sws405_ransom_simulator.yar ← YARA detection rule
│   ├── national.exe.pdf          ← file-identification demo (really a Python script)
│   └── Part 01-Unit VII.pdf      ← unit slides
└── SWS405_MalwareLab/            ← working directory where the lab was performed
    ├── suspicious_sample.py      ← copy of the sample used for analysis
    ├── sws405_ransom_simulator.yar
    ├── national.exe.pdf
    ├── sample_hash_before.txt    ← SHA-256 recorded before execution (integrity check)
    ├── baseline.txt              ← file listing saved during an earlier test run
    ├── dynamic_trace.txt         ← strace output from the analysed run
    ├── lab_workspace/            ← files created by the sample in the analysed run
    └── lab_workspace_old/        ← output from an earlier test run (moved aside for a clean baseline)
```

## Screenshot index

| # | Step | Shows |
|---|---|---|
| 1 | A1 | `file` identifies both files as Python scripts |
| 2 | A2 | MD5, SHA-1 and SHA-256 hashes |
| 3 | A2 | Baseline hash saved and verified (`OK`) |
| 4 | A3 | Suspicious strings |
| 5 | A4 | `xxd` hex view (`#!` shebang, no `MZ` header) |
| 6 | A5 | YARA match, 3/3 markers |
| 7 | B1 | Baseline: no `lab_workspace` before execution |
| 8 | B3 | Sample executed under `strace` |
| 9 | B3 | `mkdir` / `openat` / `execve` system calls |
| 10 | B3 | No network system calls (`exit=1`) |
| 11 | B4 | Created files and the simulation note |
| 12 | B4 | Hashes of the created files |
| 13 | B5 | `ss -tunap` network sockets |
| 14 | B6 | Sample hash unchanged after execution |

## Key results

| Item | Value |
|---|---|
| File type | Python script (UTF-8 text), not a PE executable |
| SHA-256 | `7ef94bfb15c7479e209a701b40cf6994a2f9c4b0870b4576966b43050554bc26` |
| MD5 | `29feb123f1f062328b746b1fdb332612` |
| YARA | `SWS405_Harmless_Ransomware_Simulator`, 3/3 markers matched |
| Behaviour observed | Created `lab_workspace/victim_files/` with 3 dummy files, read them, wrote `READ_ME_SIMULATION.txt` and `simulation_activity.log` |
| Network activity | None observed (no `AF_INET`/`connect` calls; no sample sockets) |
| Encryption / deletion | None observed |
| Sample integrity | SHA-256 unchanged after execution |

## Reproducing the analysis

Run these on a disposable Kali VM:

```bash
sudo apt install -y file binutils xxd yara strace
cd SWS405_MalwareLab

# Part A – static (do not execute)
file suspicious_sample.py
sha256sum suspicious_sample.py > sample_hash_before.txt
strings -a suspicious_sample.py | grep -Ei 'SIMULATED|LOCKED|NOTE_CREATE|FILE_READ|LOG_WRITE|lab_workspace'
xxd -l 128 suspicious_sample.py
yara -s sws405_ransom_simulator.yar suspicious_sample.py

# Part B – dynamic
strace -f -o dynamic_trace.txt -e trace=%file,%process,%network python3 suspicious_sample.py
grep -E 'mkdir|openat|execve' dynamic_trace.txt | grep -E 'lab_workspace|execve'
grep -E 'AF_INET|connect\(' dynamic_trace.txt
find lab_workspace -type f
sha256sum -c sample_hash_before.txt
```

## Limitations

- The lab was run on a networked Kali machine, not the isolated UTM VM the manual recommends. This was acceptable only because the sample's source code was reviewed first and confirmed harmless.
- The sample is a Python script, so Windows PE analysis (headers, imports, packers) and registry persistence don't apply.
- Dynamic results describe this single run only.
