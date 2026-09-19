#!/usr/bin/env python3
"""Validate the ATT&CK / ATLAS technique catalogs used by modern-threat-modeling.

The catalogs (references/attack-techniques.md, references/atlas-techniques.md) are the
skill's source of truth for technique mapping. Their core promise, "every threat maps
to a VALID id, never invented", is only as good as the catalog. This script enforces
that a catalog is well-formed and internally consistent, so a defect like an empty
tactic section or a wrong header count cannot ship undetected.

It parses ONLY structured entries:
    parent:  "- **Txxxx**: Name"        (ATT&CK)   /  "- **AML.Txxxx**: Name"   (ATLAS)
    sub:     "    - Txxxx.yyy: Name"     (ATT&CK)   /  "    - AML.Txxxx.yyy: Name" (ATLAS)
Prose mentions of an id (e.g. the "do not cite T1562" deprecation note) are ignored,
because they are not entry lines.

Checks (each catalog):
  1. header counts reconcile with actual unique parent / sub counts
  2. no empty tactic section (any "## Heading" that contains zero parent entries)
  3. no orphan sub-technique (every Txxxx.yyy has a defined **Txxxx** parent)
  4. all ids well-formed; no entry-looking line that fails to parse
  5. names are consistent for a given id across cross-tactic duplicates
  6. a dated snapshot / source line is present
  7. no revoked id appears as a defined entry (per-file denylist)

Exit code 0 if every catalog passes, 1 otherwise. No third-party dependencies.

Usage:
    python3 scripts/validate_catalogs.py                 # validates both default catalogs
    python3 scripts/validate_catalogs.py path/to/file.md ...   # validate specific files
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field


# --- catalog "profiles": the only difference between ATT&CK and ATLAS is the id shape.
@dataclass
class Profile:
    name: str
    parent_re: re.Pattern      # matches a full parent entry line -> (id, name)
    sub_re: re.Pattern         # matches a full sub entry line -> (id, name)
    parent_id_re: re.Pattern   # exact parent-id shape
    sub_id_re: re.Pattern      # exact sub-id shape
    parent_token: str          # how a parent entry line begins, for "looks like an entry" detection
    sub_token_re: re.Pattern   # how a sub entry line begins (indented)
    has_tactic_sections: bool  # ATT&CK groups by "## Tactic"; ATLAS is a flat list
    revoked: set[str] = field(default_factory=set)


ATTACK = Profile(
    name="ATT&CK",
    parent_re=re.compile(r"^- \*\*(T\d{4})\*\*:\s+(.+?)\s*$"),
    sub_re=re.compile(r"^\s+- (T\d{4}\.\d{3}):\s+(.+?)\s*$"),
    parent_id_re=re.compile(r"^T\d{4}$"),
    sub_id_re=re.compile(r"^T\d{4}\.\d{3}$"),
    parent_token="- **T",
    sub_token_re=re.compile(r"^\s+- T\d"),
    has_tactic_sections=True,
    # Known revoked in the vendored version (ATT&CK v19 revoked Impair Defenses).
    # Extend this set each refresh from the release's revocation list.
    revoked={"T1562"},
)

ATLAS = Profile(
    name="ATLAS",
    parent_re=re.compile(r"^- \*\*(AML\.T\d{4})\*\*:\s+(.+?)\s*$"),
    sub_re=re.compile(r"^\s+- (AML\.T\d{4}\.\d{3}):\s+(.+?)\s*$"),
    parent_id_re=re.compile(r"^AML\.T\d{4}$"),
    sub_id_re=re.compile(r"^AML\.T\d{4}\.\d{3}$"),
    parent_token="- **AML.",
    sub_token_re=re.compile(r"^\s+- AML\.T\d"),
    has_tactic_sections=False,
    revoked=set(),
)

HEADER_COUNT_RE = re.compile(r"(\d+)\s+techniques,\s+(\d+)\s+sub-techniques")
SNAPSHOT_RE = re.compile(r"snapshot", re.IGNORECASE)


def pick_profile(path: str, first_kb: str) -> Profile:
    """Choose ATT&CK vs ATLAS from the filename or content."""
    if "atlas" in os.path.basename(path).lower() or "AML.T" in first_kb:
        return ATLAS
    return ATTACK


@dataclass
class Finding:
    ok: bool
    check: str
    detail: str = ""


def validate(path: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    text = "".join(lines)
    prof = pick_profile(path, text[:2048])
    findings: list[Finding] = []

    # --- parse structured entries ---
    parents: list[tuple[int, str, str]] = []   # (lineno, id, name)
    subs: list[tuple[int, str, str]] = []       # (lineno, id, name)
    malformed: list[str] = []

    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        # parent entry?
        if line.startswith(prof.parent_token[:6]) and line.lstrip().startswith("- **"):
            m = prof.parent_re.match(line)
            if m:
                parents.append((i, m.group(1), m.group(2).strip()))
                continue
            # looks like a bold-id entry but did not parse cleanly -> malformed
            if re.match(r"^- \*\*[A-Za-z0-9.]+\*\*", line):
                malformed.append(f"L{i}: unparseable parent entry: {line.strip()}")
            continue
        # sub entry? (indented "- <id>: ...")
        if prof.sub_token_re.match(line):
            m = prof.sub_re.match(line)
            if m:
                subs.append((i, m.group(1), m.group(2).strip()))
            else:
                malformed.append(f"L{i}: unparseable sub-technique entry: {line.strip()}")

    parent_ids = {p[1] for p in parents}
    sub_ids = {s[1] for s in subs}

    # --- check 1: header counts reconcile ---
    m = HEADER_COUNT_RE.search(text)
    if not m:
        findings.append(Finding(False, "header counts",
                                "no 'N techniques, N sub-techniques' line found"))
    else:
        claim_p, claim_s = int(m.group(1)), int(m.group(2))
        actual_p, actual_s = len(parent_ids), len(sub_ids)
        ok = claim_p == actual_p and claim_s == actual_s
        findings.append(Finding(
            ok, "header counts",
            f"header claims {claim_p}/{claim_s}, actual unique {actual_p}/{actual_s}"
            + ("" if ok else "  <-- MISMATCH")))

    # --- check 2: no empty tactic section ---
    if prof.has_tactic_sections:
        sections: list[tuple[str, int]] = []  # (heading, parent_count)
        current = None
        count = 0
        for raw in lines:
            line = raw.rstrip("\n")
            if line.startswith("## "):          # a tactic heading (H2), not the H1 title
                if current is not None:
                    sections.append((current, count))
                current = line[3:].strip()
                count = 0
            elif current is not None and prof.parent_re.match(line):
                count += 1
        if current is not None:
            sections.append((current, count))
        empties = [h for h, c in sections if c == 0]
        findings.append(Finding(
            not empties, "no empty tactic",
            "all populated" if not empties else f"EMPTY: {', '.join(empties)}"))

    # --- check 3: no orphan sub-techniques ---
    orphans = sorted({sid for sid in sub_ids if sid.rsplit(".", 1)[0] not in parent_ids})
    findings.append(Finding(
        not orphans, "no orphan subs",
        "none" if not orphans else f"{len(orphans)} orphan(s): {', '.join(orphans[:8])}"
        + (" ..." if len(orphans) > 8 else "")))

    # --- check 4: well-formed ids / no malformed entry lines ---
    bad_ids = [pid for pid in parent_ids if not prof.parent_id_re.match(pid)]
    bad_ids += [sid for sid in sub_ids if not prof.sub_id_re.match(sid)]
    prob = list(bad_ids) + malformed
    findings.append(Finding(
        not prob, "well-formed ids",
        "all valid" if not prob else "; ".join(str(x) for x in prob[:8])
        + (" ..." if len(prob) > 8 else "")))

    # --- check 5: name consistency across duplicates ---
    names: dict[str, set[str]] = {}
    for _, pid, pname in parents:
        names.setdefault(pid, set()).add(pname)
    for _, sid, sname in subs:
        names.setdefault(sid, set()).add(sname)
    inconsistent = {k: v for k, v in names.items() if len(v) > 1}
    findings.append(Finding(
        not inconsistent, "name consistency",
        "consistent" if not inconsistent
        else "; ".join(f"{k}: {sorted(v)}" for k, v in list(inconsistent.items())[:5])))

    # --- check 6: dated snapshot / source line present ---
    findings.append(Finding(
        bool(SNAPSHOT_RE.search(text)), "snapshot line",
        "present" if SNAPSHOT_RE.search(text) else "missing 'snapshot' source line"))

    # --- check 7: no revoked id defined as an entry ---
    revoked_hits = sorted(
        {pid for pid in parent_ids if pid in prof.revoked}
        | {sid for sid in sub_ids if sid.rsplit(".", 1)[0] in prof.revoked})
    findings.append(Finding(
        not revoked_hits, "no revoked ids",
        "none" if not revoked_hits else f"revoked still defined: {', '.join(revoked_hits)}"))

    return findings


def main(argv: list[str]) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    default = [
        os.path.join(here, "..", "references", "attack-techniques.md"),
        os.path.join(here, "..", "references", "atlas-techniques.md"),
    ]
    paths = argv[1:] or default

    all_ok = True
    for path in paths:
        path = os.path.normpath(path)
        label = os.path.basename(path)
        if not os.path.isfile(path):
            print(f"[FAIL] {label}: file not found ({path})")
            all_ok = False
            continue
        print(f"\n=== {label} ===")
        for f in validate(path):
            mark = "[PASS]" if f.ok else "[FAIL]"
            print(f"  {mark} {f.check:<18} {f.detail}")
            all_ok = all_ok and f.ok

    print("\n" + ("PASS: catalogs valid" if all_ok else "FAIL: fix the [FAIL] items above"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
