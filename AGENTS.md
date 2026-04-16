# Agent Instructions — crypto2dev

Read this file completely before touching any code. It governs how AI agents
work on this project.

---

## Enable Agent Teams

```bash
export CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1
```

Set this at the start of every non-trivial session. Without it, subagent
parallelism is unavailable and context pressure degrades output quality.

---

## Context Husbanding — The Core Discipline

Each agent context window is a finite, non-renewable resource for the session.
Loading kernel headers, wolfCrypt headers, existing source, test vectors, and
review findings into a single context is the primary failure mode.

**Rules for every agent — orchestrator and subagent alike:**

1. **Locate with Grep/Glob, never Read to browse.** Know the exact line range
   you need before calling Read. Never read a file "to see what's in it."

2. **Delegate reading to subagents.** If you need the content of a wolfCrypt
   header, a kernel header, and a test vector file, that is three subagents —
   not three Reads in the orchestrator.

3. **Return summaries, not raw contents.** Subagents extract and distill; they
   do not paste file contents back to the orchestrator.

4. **State lives in beads, not in context.** Claim the epic, file child issues,
   update status. The orchestrator can restart from `bd show <epic-id>` without
   re-reading anything.

5. **Fresh subagent per review iteration.** Never accumulate review findings in
   one long-running agent; each REVIEWER pass gets a clean context.

6. **Stop at 3 failed attempts.** If a subagent makes 3 attempts on the same
   error without progress, escalate with `bd human <id>` rather than retrying.
   Past 3 rounds the problem requires human judgment.

---

## Sources of Truth

Before implementing any registration shim or ioctl handler, read the source.
Never guess at signatures, constants, or behavior.

| What | Where |
|---|---|
| wolfCrypt crypto function signatures | `$(WOLFCRYPT_DIR)/wolfssl/wolfcrypt/*.h` |
| wolfCrypt error codes | `$(WOLFCRYPT_DIR)/wolfssl/wolfcrypt/error-crypt.h` |
| wolfCrypt FIPS status | `$(WOLFCRYPT_DIR)/wolfssl/wolfcrypt/fips.h` |
| Kernel skcipher API | `/usr/src/linux/include/crypto/skcipher.h` |
| Kernel aead API | `/usr/src/linux/include/crypto/aead.h` |
| Kernel shash API | `/usr/src/linux/include/crypto/hash.h` |
| Algorithm naming ground truth | `cat /proc/crypto` on a running kernel without crypto2dev |
| Kernel scatterlist API | `/usr/src/linux/include/linux/scatterlist.h` |
| Existing test vectors | `tests/vectors/*.h` in this repo |

---

## Standard Agent Team for Each Implementation Epic

### Phase 1 — Research (spawn all three in parallel, one message)

```
Orchestrator spawns simultaneously:

  ┌─ WOLFCRYPT-AUDITOR ───────────────────────────────────────────┐
  │  Input:  wolfCrypt header path (e.g. wolfcrypt/aes.h)        │
  │  Reads:  only that header (grep for the structs + functions) │
  │  Returns: exact function signatures, buffer size constants,  │
  │           init/free pairs, FIPS restrictions, thread-safety  │
  └───────────────────────────────────────────────────────────────┘

  ┌─ VECTOR-FINDER ───────────────────────────────────────────────┐
  │  Input:  algorithm name (e.g. "AES-CBC")                     │
  │  Reads:  tests/vectors/ in this repo; if absent, searches    │
  │          NIST CAVP publications or relevant RFC appendix      │
  │  Returns: ready-to-paste C array literals with source cited  │
  └───────────────────────────────────────────────────────────────┘

  ┌─ KERNEL-READER ───────────────────────────────────────────────┐
  │  Input:  kernel crypto API type (skcipher / aead / shash /…) │
  │  Reads:  the relevant kernel include/crypto/*.h              │
  │  Returns: callback signatures, context size rules, req       │
  │           structure fields, algorithm naming conventions      │
  └───────────────────────────────────────────────────────────────┘
```

Orchestrator waits for all three summaries, then proceeds to Phase 2.

### Phase 2 — Implementation (one subagent)

```
  ┌─ IMPLEMENTER ─────────────────────────────────────────────────┐
  │  Input:  wolfCrypt summary + vector literals + kernel API    │
  │          shape (passed in prompt — no extra file reads       │
  │          unless strictly necessary)                          │
  │  Writes: src/providers/wolfssl/wolfssl_<algo>.c (or src/cdev/) │
  │          tests/kernel/test_<algo>.c                          │
  │          tests/vectors/<algo>.h (if new vectors were found)  │
  │                                                              │
  │  Must satisfy every item in CLAUDE.md §Paranoid Checklist    │
  │  Must build with zero errors and zero new warnings           │
  │  Returns: list of files written + any open questions         │
  └───────────────────────────────────────────────────────────────┘
```

Orchestrator runs `make` after implementation. Any build failures are filed
as P0 child issues and fixed before proceeding.

### Phase 3 — Review loop (fresh subagent per iteration)

```
  ┌─ REVIEWER (iteration N) ──────────────────────────────────────┐
  │  Input:  file path list + epic beads ID                      │
  │  Reads:  only those files                                    │
  │  Does:   checks all 12 items in CLAUDE.md §Paranoid Checklist│
  │          + the hard rules below                              │
  │          files all findings as beads child issues            │
  │  Returns: list of open P0/P1/P2 issue IDs (or "none")       │
  └───────────────────────────────────────────────────────────────┘
```

**Hard rules the REVIEWER must check on every pass — automatic P0 if violated:**

- **No enums, no flag bits.** Any `typedef enum`, anonymous `enum`, `flags`
  field, or bitmask constant in any header or source file is an automatic
  reject. File as P0, label `uapi,correctness`. See CLAUDE.md §4 and
  DESIGN.md §Design Decisions for the full rationale. There are no
  exceptions. Do not accept a justification that "this set will never grow"
  — that is always what it looks like at the time.

**Loop:**
- Open P0/P1/P2 issues → orchestrator fixes them (may spawn a targeted
  IMPLEMENTER per fix), then spawns a **new** REVIEWER with a clean context
- Only bikeshedding remaining (no engineering basis) → close all child issues
  and the epic, then `make` + quality gates one final time
- Human decision needed → `bd human <id>`, stop

Never iterate more than 3 rounds on the same finding. Escalate with
`bd human <id>` instead.

---

## Parallel Workstreams Across Epics

When multiple registration files are being built in the same session, pipeline
them:

```
Session orchestrator:
  Batch 1 (parallel): spawn Phase 1 research for skcipher, aead, shash simultaneously
  Wait for all research summaries
  Batch 2 (parallel): spawn Phase 2 IMPLEMENTER for each simultaneously
  Wait for all implementations
  Sequential: make (fix any failures before continuing)
  Batch 3 (parallel): spawn Phase 3 REVIEWER for each simultaneously
  ... repeat review loop per epic independently
```

The orchestrator's own context carries only epic IDs and status — never file
contents.

---

## Subagent Prompt Templates

### WOLFCRYPT-AUDITOR

```
Read the wolfCrypt header at $(WOLFCRYPT_DIR)/wolfssl/wolfcrypt/<name>.h.
Use Grep to find the specific structs and functions listed below; then Read
only those line ranges. Do not read the full file.

Report:
1. Exact function signatures for: <list>
2. Init/free pairing for each struct
3. Buffer size constants used as parameters or return bounds
4. FIPS-only restrictions noted in comments
5. Thread-safety notes

Do not write any code.
```

### VECTOR-FINDER

```
Find authoritative test vectors for <algorithm>.
Sources in priority order:
  1. tests/vectors/<algo>.h in this repo (if it exists)
  2. NIST CAVP/ACVTS published vectors
  3. RFC appendix vectors (state RFC number and section)
  4. OpenSSL CLI: state the exact command that produced the output

Do not derive vectors from the crypto2dev implementation.
Return vectors as C array literals ready to paste into a .h file,
with source cited in a comment above each one.
```

### KERNEL-READER

```
Read the kernel crypto API header at /usr/src/linux/include/crypto/<name>.h.
Use Grep to locate the relevant struct and callback definitions; Read only
those line ranges.

Report:
1. Callback function signatures for: <list>
2. Context struct fields and how .cra_ctxsize must be set
3. How the request struct (skcipher_request, etc.) carries src/dst/iv
4. Algorithm registration struct field names and required values
5. How .cra_name and .cra_driver_name interact with the template system

Do not write any code.
```

### IMPLEMENTER

```
Implement <description> for crypto2dev.
Working directory: /home/mark/WORK/CRYPTO2DEV

You have been given these summaries — do not re-read the source files
unless a specific detail is missing:

WOLFCRYPT API:
<paste wolfcrypt-auditor output>

KERNEL API:
<paste kernel-reader output>

TEST VECTORS:
<paste vector-finder output>

Write:
- src/providers/wolfssl/wolfssl_<algo>.c  (or src/cdev/<file>.c)
- tests/kernel/test_<algo>.c
- Any new tests/vectors/<algo>.h entries

Requirements:
- Every item in CLAUDE.md §Paranoid Defensive Programming Checklist
- Build must succeed: make -C /lib/modules/$(uname -r)/build M=$(pwd) WOLFCRYPT_DIR=...
- Zero new compiler warnings

Return: list of files written + any questions that need human judgment.
```

---

## Non-Interactive Shell Commands

Always use non-interactive flags to avoid hanging:

```bash
cp -f src dst          # not: cp src dst
mv -f src dst          # not: mv src dst
rm -f file             # not: rm file
rm -rf dir             # not: rm -r dir
apt-get install -y     # not: apt-get install
```

---

## Beads Quick Reference

```bash
bd ready                  # find available work (no blockers)
bd show <id>              # read issue details
bd update <id> --claim    # claim before starting
bd close <id>             # mark complete when done
bd dolt push              # push beads to remote (always at session end)
```

- Use `bd` for ALL task tracking. Never use TodoWrite, markdown TODOs, or in-memory lists.
- Use `bd remember "..."` for persistent facts. Never write MEMORY.md files.
- Run `bd prime` for the full session protocol.
