# Catalog Maintenance: Refreshing ATT&CK and ATLAS

The technique catalogs (`attack-techniques.md`, `atlas-techniques.md`) are the
source of truth for mapping and must stay current. MITRE revises both
periodically, and revisions are not always cosmetic: v19 split a whole tactic and
revoked T1562. Treat a refresh as a routine procedure. This file is that procedure.

## When to refresh

- **ATT&CK Enterprise** ships roughly twice a year (historically around April and
  October). Current vendored version: **v19.2**. Check
  <https://attack.mitre.org/resources/versions/> for the latest.
- **ATLAS** updates on its own cadence (no fixed calendar). Check the repo below.
- Refresh whenever a new version lands, or whenever a mapping run hits a technique
  the catalog is missing.

## Authoritative sources (never hand-type IDs)

| Catalog | Machine-readable source |
|---------|-------------------------|
| ATT&CK Enterprise | STIX bundle: <https://github.com/mitre-attack/attack-stix-data> (`enterprise-attack/enterprise-attack.json`). Human view: <https://attack.mitre.org>. Spreadsheets: attack.mitre.org/resources/attack-data-and-tools/ |
| ATLAS | YAML: <https://github.com/mitre-atlas/atlas-data> (`dist/ATLAS.yaml`). Human view: <https://atlas.mitre.org> |

Always regenerate from the STIX or YAML, not from a blog, a screenshot, or memory.

## Procedure

1. **Pick the target version** and record it (for example, ATT&CK v19.2). Note the
   release date.
2. **Pull** the STIX bundle or ATLAS YAML for that version.
3. **Filter out** anything not currently valid: objects with `revoked: true` or
   `x_mitre_deprecated: true` must be excluded. (This is how the old `T1562`
   sub-techniques drop out and the new `T1685`, `T1686`, `T1690` come in.)
4. **Group by tactic** using each technique's `kill_chain_phases`. A technique that
   maps to several tactics is listed under each (this file's existing convention).
   For ATT&CK, keep the merged **Defense Evasion** heading covering both the current
   Stealth (TA0005) and Defense Impairment (TA0112) tactics, so STRIDE Repudiation
   threats still resolve; note the split in that section's header.
5. **Emit** the markdown in the existing shape: `- **Txxxx**: Name`, with
   sub-techniques indented as `    - Txxxx.yyy: Name`.
6. **Update the header line**: the `_Source: ... vN. N techniques, N sub-techniques.
   Catalog snapshot vendored YYYY-MM ..._` line, with the new version, date, and
   counts.
7. **Run the validation checks below.** A refresh is not done until they all pass.
8. **Diff against the previous catalog** and eyeball the renames and revocations
   (for example, `T1211` changed from "Exploitation for Defense Evasion" to
   "Exploitation for Stealth"), so nothing stale survives. Use the pre-v19 name
   sweep patterns as a starting list.

## Validation checks (the safety net)

Run every one of these after a refresh. Their absence is what once let an empty
tactic ship undetected:

- **No empty tactic section:** every `## <Tactic>` has at least one `- **T...**`
  under it.
- **Counts reconcile:** the header's technique and sub-technique numbers equal the
  actual unique counts in the file:
  - parents: `grep -oE "\*\*T[0-9]{4}\*\*" attack-techniques.md | sort -u | wc -l`
  - subs: `grep -oE "T[0-9]{4}\.[0-9]{3}" attack-techniques.md | sort -u | wc -l`
  - (ATLAS: same with the `AML.T...` pattern.)
- **No revoked or deprecated IDs** present (spot-check the ones MITRE revoked this
  release).
- **No orphan sub-techniques:** every `Txxxx.yyy` has its `**Txxxx**` parent
  somewhere.
- **Well-formed IDs:** ATT&CK `Txxxx[.yyy]`, ATLAS `AML.Txxxx[.yyy]`; nothing else.
- **Snapshot line updated:** version, date, and counts all match reality.

Only when all pass is the catalog valid.

## Run the validator (machine-enforced)

These checks are scripted in `scripts/validate_catalogs.py` (no dependencies). Run
it after any edit to a catalog, and in CI:

```
python3 scripts/validate_catalogs.py              # both default catalogs
python3 scripts/validate_catalogs.py path/to.md   # a specific file
```

It parses only structured entries (so prose like the "do not cite T1562" note is
ignored), prints a pass or fail line per check, and exits non-zero on any failure.
It catches an empty tactic, a wrong header count, an orphan sub-technique, a
malformed id, a name drift across duplicates, and a revoked id defined as an entry.

**On each refresh, update the script's per-file `revoked` set** (in the `ATTACK` or
`ATLAS` profile) with the ids MITRE revoked in that release, so re-introducing a
dead id fails the build. Everything else the script derives from the file itself.
