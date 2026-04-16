#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
audit_inbuf_clear.py — mechanically audit crypto2dev_fd.c for inbuf_clear()
coverage on all exit paths that follow mutex_lock(&state->lock).

DESIGN NOTE: inbuf is the write()-before-ioctl staging buffer on UNSET fds.
It holds key material written by the caller before KEY_IMPORT or DO_KDF.
On every path that acquires state->lock and then exits the function, inbuf
must be cleared — unless the exit is intentional by design (see INTENTIONAL).

What constitutes a "bypass":
    Any goto or return that occurs at or after the first mutex_lock(), where
    the execution path leading to that exit does NOT pass through an
    inbuf_clear() call (either inline before the exit, or in the label block
    the goto lands at).

What is NOT a bypass:
    - Any goto or return that occurs BEFORE mutex_lock().  The function has
      not acquired the lock and has not touched inbuf.  These exits are
      ordinary argument-validation early-outs and are not relevant.

INTENTIONAL bypass — ioctl_init on UNSET fd:
    When INIT fails after acquiring the lock (no ops, REQUIRE_FIPS reject,
    fips_gate fail, no sess_init), the fd remains UNSET.  The inbuf must NOT
    be cleared because the caller may still call KEY_IMPORT or DO_KDF on the
    same fd using the data already in inbuf.  Clearing inbuf here would force
    the caller to re-write key material, creating a window where the fd is
    UNSET but inbuf is empty — a hard-to-reason-about state.
    The inbuf IS cleared on the success path (before sess_init, line ~757).

ioctl_do_kdf pre-lock exits (WOLFKM-con.20):
    Eight early-exit gotos (goto out_zero) fire before mutex_lock and jump
    over the lock entirely.  The copy_from_user bare return (line ~1689) is
    also pre-lock.  None of these are flagged because the function had not
    acquired the lock; inbuf is not accessible without the lock.
    The post-lock exits all flow through out_inbuf_clear, so ioctl_do_kdf
    reports CLEAR for the post-lock region.
    The pre-lock bypass of inbuf is tracked externally as WOLFKM-con.20.

BYPASS — ioctl_key_generate error exits (WOLFKM-con.18):
    Post-lock gotos (goto out) bypass the inbuf_clear() that sits only on
    the success path.  These are classified as known bypasses.

Functions that never need inbuf_clear():
    - crypto2dev_fd_poll: read-only state inspection, no inbuf modification
    - crypto2dev_fd_write: write() ADDS to inbuf on UNSET fds; it must not
      clear it, since it is populating the buffer for the subsequent ioctl
    - crypto2dev_fd_read: operates on OPERATION and KEY fds; inbuf is NULL
    - crypto2dev_fd_ioctl: dispatcher only; individual handlers own their lock
    - ioctl_require_fips: sets a flag on UNSET fds; inbuf must NOT be cleared
      because the caller may still call KEY_IMPORT/DO_KDF
    - All OPERATION fd handlers (set_iv, gen_iv, set_aad, get_tag, set_tag,
      finalize, reset): fd_type is OPERATION at entry; inbuf is always NULL
    - All KEY fd handlers (key_get_info, key_export_private, do_sign,
      do_verify, do_agree): fd_type is KEY at entry; inbuf is always NULL
    - ioctl_status, ioctl_get_state: read-only

Exit code:
    0  — no unclassified bypasses found
    1  — one or more unclassified bypasses found (new code requires attention)

Machine-readable output (greppable):
    RESULT: <function>  CLEAR
    RESULT: <function>  BYPASS:<label_or_return> (line N)  KNOWN:<ticket>
    RESULT: <function>  BYPASS:<label_or_return> (line N)  *** UNCLASSIFIED ***
    RESULT: <function>  INTENTIONAL:<label_or_return> (line N)  [<reason>]
    RESULT: <function>  NO_INBUF
    RESULT: <function>  NO_LOCK
"""

import re
import sys

# ---------------------------------------------------------------------------
# Known classification table.
# Key: (function_name, exit_target) where exit_target is the goto label name
#      or "return" for bare returns.
# ---------------------------------------------------------------------------

# Known bugs, tracked in the issue tracker.  Reported as BYPASS:KNOWN.
# Script exits non-zero only for UNCLASSIFIED bypasses, not for these.
KNOWN_BYPASSES = {
    # ioctl_key_generate: post-lock gotos that bypass the success-only
    # inbuf_clear().  WOLFKM-con.18.
    ("ioctl_key_generate", "out"): "WOLFKM-con.18",
}

# Intentional bypasses: documented design decisions, not bugs.
KNOWN_INTENTIONAL = {
    # ioctl_init: post-lock gotos leave inbuf intact so the caller can retry
    # KEY_IMPORT or DO_KDF after a failed INIT on an UNSET fd.
    ("ioctl_init", "out_unlock"): (
        "UNSET fd stays UNSET on INIT failure — inbuf persists for retry"
    ),
}

# ---------------------------------------------------------------------------
# Functions where inbuf_clear() is structurally not required.
# These are excluded from bypass analysis entirely.
# ---------------------------------------------------------------------------

NO_INBUF_EXPECTED = {
    # write() accumulates into inbuf on UNSET fds — must NOT clear it.
    "crypto2dev_fd_write",
    # read() operates on OPERATION/KEY fds; inbuf is NULL at that point.
    "crypto2dev_fd_read",
    # poll() is a read-only state query.
    "crypto2dev_fd_poll",
    # ioctl dispatcher: no lock, no inbuf; individual handlers are audited.
    "crypto2dev_fd_ioctl",
    # REQUIRE_FIPS only sets a flag; inbuf must stay intact for caller retry.
    "ioctl_require_fips",
    # OPERATION fd handlers: fd_type == OPERATION means inbuf is NULL.
    "ioctl_set_iv",
    "ioctl_gen_iv",
    "ioctl_set_aad",
    "ioctl_get_tag",
    "ioctl_set_tag",
    "ioctl_finalize",
    "ioctl_reset",
    # KEY fd handlers: fd_type == KEY means inbuf is NULL.
    "ioctl_key_get_info",
    "ioctl_key_export_private",
    "ioctl_do_sign",
    "ioctl_do_verify",
    "ioctl_do_agree",
    # Read-only helpers.
    "ioctl_status",
    "ioctl_get_state",
}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

RE_FUNC_START = re.compile(
    r'^(static\s+)?(long|void|int|ssize_t|__poll_t)\s+'
    r'(ioctl_\w+|crypto2dev_fd_\w+)\s*\('
)
RE_MUTEX_LOCK  = re.compile(r'\bmutex_lock\s*\(&state->lock\)')
RE_INBUF_CLEAR = re.compile(r'\binbuf_clear\s*\(')
RE_GOTO        = re.compile(r'\bgoto\s+(\w+)\s*;')
RE_RETURN      = re.compile(r'\breturn\b')
RE_LABEL       = re.compile(r'^\s*(\w+)\s*:\s*(\/\*.*)?$')


def parse_functions(lines):
    """
    Yield (func_name, start_lineno, body_lines) for each top-level function.
    body_lines is a list of (lineno, stripped_text) pairs.
    start_lineno is 1-based.
    """
    i = 0
    n = len(lines)
    while i < n:
        m = RE_FUNC_START.match(lines[i])
        if not m:
            i += 1
            continue

        func_name = m.group(3)
        start = i

        # Scan forward to find the matching closing brace of the body.
        j = i
        brace_depth = 0
        found_open = False
        while j < n:
            for ch in lines[j]:
                if ch == '{':
                    brace_depth += 1
                    found_open = True
                elif ch == '}':
                    brace_depth -= 1
            if found_open and brace_depth == 0:
                break
            j += 1

        body = [(start + k + 1, lines[start + k]) for k in range(j - start + 1)]
        yield func_name, start + 1, body
        i = j + 1


def audit_function(func_name, body_lines):
    """
    Analyse one function for inbuf_clear() coverage on post-lock exit paths.

    Returns a list of findings, each a dict with keys:
        kind:   'CLEAR' | 'BYPASS' | 'INTENTIONAL' | 'NO_INBUF' | 'NO_LOCK'
        exit:   label name, 'return', or None
        lineno: source line number or None
        ticket: issue ticket string or None   (BYPASS only)
        reason: explanation string or None    (INTENTIONAL only)
    """
    if func_name in NO_INBUF_EXPECTED:
        return [_finding('NO_INBUF')]

    # Find the first mutex_lock in the function body.
    lock_idx = None
    for idx, (lineno, text) in enumerate(body_lines):
        if RE_MUTEX_LOCK.search(text):
            lock_idx = idx
            break

    if lock_idx is None:
        return [_finding('NO_LOCK')]

    # Build a map: label_name -> body index of the label definition.
    label_map = {}
    for idx, (lineno, text) in enumerate(body_lines):
        m = RE_LABEL.match(text)
        if m:
            label_map[m.group(1)] = idx

    # Collect all inbuf_clear() body indices.
    clear_indices = set()
    for idx, (lineno, text) in enumerate(body_lines):
        if RE_INBUF_CLEAR.search(text):
            clear_indices.add(idx)

    def covered_by_clear(goto_idx, target_label):
        """
        Return True if the exit at goto_idx is covered by an inbuf_clear().

        Two cases:
        1. Inline clear: an inbuf_clear() appears between lock_idx and
           goto_idx (i.e. it executes unconditionally before this goto fires).
        2. Label-block clear: for a goto, the target label's block (between
           the label and the next label) contains an inbuf_clear().
        """
        # Case 1: inline clear before this exit (after lock).
        if any(lock_idx <= ci <= goto_idx for ci in clear_indices):
            return True

        # Case 2: target label block contains inbuf_clear.
        if target_label is not None and target_label in label_map:
            land_idx = label_map[target_label]
            # Find the next label after land_idx to bound the block.
            next_label_idx = len(body_lines)
            for idx2, (_, text2) in enumerate(body_lines[land_idx + 1:],
                                               start=land_idx + 1):
                if RE_LABEL.match(text2):
                    next_label_idx = idx2
                    break
            if any(land_idx <= ci < next_label_idx for ci in clear_indices):
                return True

        return False

    findings = []
    seen = set()

    for idx, (lineno, text) in enumerate(body_lines):
        # Only audit exits AFTER the lock is acquired.
        if idx < lock_idx:
            continue

        g = RE_GOTO.search(text)
        r = RE_RETURN.search(text)

        if not g and not r:
            continue

        if g:
            label = g.group(1)
            key = (func_name, label)
            dedup = ('goto', label, lineno)
            if dedup in seen:
                continue
            seen.add(dedup)

            covered = covered_by_clear(idx, label)
            if covered:
                findings.append(_finding('CLEAR', label, lineno))
            else:
                reason = KNOWN_INTENTIONAL.get(key)
                ticket = KNOWN_BYPASSES.get(key)
                if reason:
                    findings.append(_finding('INTENTIONAL', label, lineno,
                                             reason=reason))
                elif ticket:
                    findings.append(_finding('BYPASS', label, lineno,
                                             ticket=ticket))
                else:
                    findings.append(_finding('BYPASS', label, lineno))

        elif r:
            dedup = ('return', lineno)
            if dedup in seen:
                continue
            seen.add(dedup)

            key = (func_name, 'return')
            covered = covered_by_clear(idx, None)
            if covered:
                findings.append(_finding('CLEAR', 'return', lineno))
            else:
                reason = KNOWN_INTENTIONAL.get(key)
                ticket = KNOWN_BYPASSES.get(key)
                if reason:
                    findings.append(_finding('INTENTIONAL', 'return', lineno,
                                             reason=reason))
                elif ticket:
                    findings.append(_finding('BYPASS', 'return', lineno,
                                             ticket=ticket))
                else:
                    findings.append(_finding('BYPASS', 'return', lineno))

    if not findings:
        return [_finding('CLEAR')]

    # Summarise: if all non-CLEAR kinds are covered → emit single CLEAR.
    non_clear = [f for f in findings if f['kind'] != 'CLEAR']
    if not non_clear:
        return [_finding('CLEAR')]

    # Return only non-CLEAR findings for the report.
    return non_clear


def _finding(kind, exit_t=None, lineno=None, ticket=None, reason=None):
    return {'kind': kind, 'exit': exit_t, 'lineno': lineno,
            'ticket': ticket, 'reason': reason}


def format_finding(func_name, f):
    kind   = f['kind']
    exit_t = f.get('exit')
    lineno = f.get('lineno')
    ticket = f.get('ticket')
    reason = f.get('reason')

    loc = f" (line {lineno})" if lineno else ""

    if kind == 'CLEAR':
        return f"RESULT: {func_name}  CLEAR"
    if kind == 'NO_LOCK':
        return f"RESULT: {func_name}  NO_LOCK"
    if kind == 'NO_INBUF':
        return f"RESULT: {func_name}  NO_INBUF"
    if kind == 'INTENTIONAL':
        return (f"RESULT: {func_name}  INTENTIONAL:{exit_t}{loc}"
                f"  [{reason}]")
    if kind == 'BYPASS':
        suffix = f"  KNOWN:{ticket}" if ticket else "  *** UNCLASSIFIED ***"
        return f"RESULT: {func_name}  BYPASS:{exit_t}{loc}{suffix}"
    return f"RESULT: {func_name}  UNKNOWN"


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-crypto2dev_fd.c>",
              file=sys.stderr)
        sys.exit(2)

    path = sys.argv[1]
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
    except OSError as e:
        print(f"error: cannot open {path}: {e}", file=sys.stderr)
        sys.exit(2)

    lines = [l.rstrip('\n') for l in lines]

    unclassified = 0
    total_funcs  = 0
    bypass_funcs = set()

    print(f"# audit_inbuf_clear.py — {path}")
    print(f"# Lines: {len(lines)}")
    print()

    for func_name, start_lineno, body_lines in parse_functions(lines):
        total_funcs += 1
        findings = audit_function(func_name, body_lines)

        print(f"--- {func_name} (starts line {start_lineno}) ---")
        for f in findings:
            print(f"  {format_finding(func_name, f)}")
            if f['kind'] == 'BYPASS':
                bypass_funcs.add(func_name)
                if not f.get('ticket'):
                    unclassified += 1

    print()
    print(f"# Total functions analysed: {total_funcs}")
    print(f"# Functions with any bypass: {len(bypass_funcs)}")
    print(f"# Unclassified bypass exits: {unclassified}")

    if unclassified > 0:
        print()
        print("FAIL: unclassified bypass(es) require engineering review.")
        sys.exit(1)
    else:
        print()
        print("PASS: all exit paths classified (CLEAR / KNOWN / INTENTIONAL / NO_INBUF).")
        sys.exit(0)


if __name__ == '__main__':
    main()
