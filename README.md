# modern-threat-modeling

A Claude skill that runs a structured STRIDE threat model of a system and returns a report you can act on: a data-flow diagram, a threat ledger, a scored and ranked risk register, and prioritized remediations. Every threat is mapped to a valid MITRE ATT&CK technique. For systems that include an LLM, threats against the LLM are additionally mapped to MITRE ATLAS.

## What it produces

- A Mermaid data-flow diagram with trust boundaries, importable into Lucidchart.
- A threat ledger: every threat, the element it targets, its STRIDE category, and its MITRE technique IDs.
- A risk register: each threat scored as Likelihood x Impact, ranked by severity.
- Remediations: preventive, detective, and corrective controls across network, application, data, endpoint, and process layers, with a prioritized roadmap.

## Inputs

Works from any one of these, or any combination:

- A written description of the system.
- An architecture diagram.
- A code folder or repository.

## How it works

The skill follows an eight-phase workflow: scope and decompose, build the DFD, enumerate STRIDE threats per element, add LLM threats when an LLM is present, map to MITRE, score and register risks, plan remediations, and assemble the report. It models adversaries and records assumptions as first-class items so every risk score is defensible and traceable back to a specific threat and element.

STRIDE is the only threat-modeling framework used. ATT&CK and ATLAS are technique catalogs used for mapping, not additional frameworks.

## Technique catalogs

Mapping draws only from the vendored catalogs in `references/`, so techniques are always valid IDs rather than guesses:

- `references/attack-techniques.md`: MITRE ATT&CK Enterprise v19.2.
- `references/atlas-techniques.md`: MITRE ATLAS.

To refresh them when MITRE ships a new version, follow
`references/catalog-maintenance.md` and run the validator:

    python3 scripts/validate_catalogs.py

## Repository layout

    SKILL.md                          Workflow, STRIDE definitions, mapping rules
    references/attack-techniques.md   Full ATT&CK Enterprise catalog
    references/atlas-techniques.md    Full ATLAS catalog
    references/templates.md           DFD, ledger, risk-register, report schemas
    references/code-recon.md          Code-first hunt checklist
    references/worked-example.md      One system taken end to end
    references/catalog-maintenance.md How to refresh the catalogs
    scripts/validate_catalogs.py      Catalog integrity checks

## Install

Copy the folder into your Claude skills directory:

    cp -R modern-threat-modeling ~/.claude/skills/

Or install the packaged `modern-threat-modeling.skill` file from a Claude client
that supports skill upload.

## Scope

Use it for a security design review of a whole system. It is not a secret scanner, a dependency/CVE scanner, an incident-response tool, or a config-hardening tool.
