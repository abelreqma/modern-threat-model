---
name: modern-threat-modeling
description: >
  Threat model a system, service, or architecture with STRIDE, then produce a
  data-flow diagram, a threat ledger, a scored and ranked risk register, and
  prioritized remediations. Every threat maps to a valid MITRE ATT&CK technique;
  MITRE ATLAS techniques are added only for LLM components in the data-flow
  diagram. Use it for a security design review of a whole system: attack surface,
  trust boundaries, which risks matter most, and how to fix them first, even when
  the user never says STRIDE or threat model. It works from a described idea, an
  architecture diagram, a code repo, or any mix, and covers LLM and agent apps
  (prompt injection, unsafe tool calls, RAG poisoning) as well as conventional
  software. It also fits asks to build a DFD, enumerate threats, or map them to
  ATT&CK and rank by risk. Not for hardening one config file, scanning for secrets
  or vulnerable dependencies, debugging a live outage or DoS, incident response
  after a breach, improving an LLM's answer quality, or a project schedule risk
  register.
---

# Modern Threat Modeling (STRIDE to ATT&CK, plus ATLAS for LLMs)

This skill turns a system description, a diagram, and/or a codebase into a
traceable STRIDE threat model in which every threat maps to a valid MITRE
technique, ending in a scored risk register and prioritized remediations.

**STRIDE is the only threat-modeling framework permitted in this skill.** Every
threat is classified as exactly one of Spoofing, Tampering, Repudiation,
Information disclosure, Denial of service, or Elevation of privilege. Do not use,
mention, offer, or blend in any other threat-modeling or threat-enumeration
framework (not PASTA, LINDDUN, DREAD, OCTAVE, Trike, VAST, attack trees, the OWASP
Top 10, kill-chain models, or any custom taxonomy), and do not invent new
categories. If a user asks for another framework, state that this skill is
STRIDE-only and continue in STRIDE. MITRE ATT&CK and ATLAS are technique catalogs
used for mapping, not threat-modeling frameworks; they are the only outside
taxonomies allowed, and only for mapping, per the Mapping rules below.

## Authorized use only

Threat modeling is defensive work. Only model systems the user owns or is
authorized to assess. Describe how a system could be attacked so it can be
defended, staying at the level of techniques, controls, and abstract attack paths.
Do not write working exploits, weaponized payloads, or step-by-step intrusion
instructions against third-party systems. Illustrative proof-of-concept sketches
are acceptable for a system the user controls. If scope or authorization is
unclear, ask before producing the model.

## Inputs: accept any combination

Determine what the user gave you and adapt. More inputs give higher fidelity, but
any one is enough to start.

| Input | What to do with it |
|-------|--------------------|
| **Idea / description** (prose) | Extract actors, assets, entry points, data stores, and trust boundaries from the narrative. Ask targeted questions only for gaps that change the threat picture (authentication model, data sensitivity, deployment surface, whether an LLM is involved). |
| **Diagram** (image, Mermaid, drawn architecture) | Read the components, flows, and boundaries directly. Reconcile against any description. Redraw as a normalized DFD. |
| **Code folder** (repo/path) | Do a code-first pass: map entry points (routes, handlers, RPC, message consumers, CLI, jobs), external calls, data stores, authN/authZ, secrets handling, deserialization, and dependencies. Ground each finding in real `file_path:line` evidence. Use `references/code-recon.md` as the hunt checklist for where each of these typically lives per stack. |

## What STRIDE fundamentally means

Each letter is the violation of one security property. This is the conceptual core
of the analysis. Apply the meaning, not a memorized list of examples.

- **Spoofing:** pretending to be another user, service, or host. Violates **authenticity**. Ask: how is each identity proven, and can that proof be stolen, forged, or replayed?
- **Tampering:** unauthorized modification of data or code, in transit, at rest, or in memory. Violates **integrity**. Ask: which data, if altered, changes a security decision, and what protects it?
- **Repudiation:** performing an action and being able to deny it, with no trustworthy evidence. Violates **non-repudiation and accountability**. Ask: is this action attributably logged, and can the actor alter or erase that record?
- **Information disclosure:** exposure of data to someone not authorized to see it. Violates **confidentiality**. Ask: what is the most sensitive data here, who can read it, and where might it leak?
- **Denial of service:** degrading or denying availability to legitimate users. Violates **availability**. Ask: what is unbounded (CPU, memory, connections, query cost, fan-out), and can one cheap request cause expensive work?
- **Elevation of privilege:** gaining capabilities beyond what is authorized. Violates **authorization**. Ask: where are authorization decisions made, and can they be bypassed, confused, or skipped?

Applicability differs by element type. Walk the categories that fit rather than
forcing all six onto everything (Y marks a category that commonly applies):

| Element type | S | T | R | I | D | E |
|--------------|---|---|---|---|---|---|
| External entity (user, third-party service) | Y | | Y | | | |
| Process (service, function, handler) | Y | Y | Y | Y | Y | Y |
| Data store (DB, cache, bucket, queue) | | Y | Y | Y | Y | |
| Data flow (request, message, stream) | | Y | | Y | Y | |

Boundary-crossing data flows carry the most threats, so prioritize them.

## When ATLAS applies (the LLM gate)

Ask whether the DFD contains an LLM element: a large-language-model call, an
LLM-backed agent or assistant, a RAG/retrieval pipeline feeding an LLM, or an LLM
inference endpoint.

- **LLM present:** map with ATT&CK and ATLAS. ATLAS applies only to the LLM
  element(s) and their immediate data flows.
- **No LLM in the DFD:** ATT&CK only. Do not use ATLAS at all; mapping conventional
  software to ATLAS is incorrect.

## Mapping rules (the only place techniques come from)

- Map every threat to one or more **valid ATT&CK Enterprise** technique IDs drawn
  from `references/attack-techniques.md`.
- For threats against an LLM element, additionally map to **valid ATLAS** technique
  IDs drawn from `references/atlas-techniques.md`.
- Use the most specific technique that fits, including a sub-technique ID when it
  is the precise match. A single threat may carry more than one technique.
- Never invent, guess, or approximate an ID. If nothing in the catalog fits, say so
  rather than fabricating one. Do not use CWE, CAPEC, or any other taxonomy; use
  ATT&CK and (for LLMs) ATLAS only.

## Workflow

Create a TodoWrite item per phase, then work them in order. Phases build on each
other, so do not enumerate threats before the DFD exists.

### Phase 1: Scope and decompose
Establish the assessment boundary, the primary assets to protect (data, funds,
availability, reputation, model/IP, safety), the actors, and the out-of-scope
items. List every **element**: external entities, processes, data stores, data
flows. Give each a stable ID (`E1`, `P1`, `DS1`, `DF1`). Identify **trust
boundaries**, meaning every place data crosses from one zone of control into
another.

Record every **assumption** the model rests on as a first-class item with an `A#`
ID (for example, `A1: end users authenticate via OIDC; sessions are bearer
tokens`). When you model from prose or a diagram you have to assume things: the
authentication model, data sensitivity, deployment surface. Make each one explicit
and give it an ID so later threats can cite it. An assumption is load-bearing: if
`A1` is wrong, every threat that references it is invalidated, and that should be
visible rather than buried. Mark assumptions you could not confirm as
**unverified** so the reader knows where to push back.

**Model the adversaries** before scoring anything, each with a stable `ADV#` ID.
Characterize three axes: **access** (anonymous internet, authenticated user,
privileged insider or operator, supply-chain or dependency, physical),
**capability** (opportunistic tooling, then funded and persistent, then
nation-state), and **motivation** (fraud, data theft, disruption, sabotage,
reputation). Three or four profiles usually cover a system; keep each to a line.
These profiles are the **basis for Likelihood in Phase 6**: a threat only a
rare-capability `ADV#` can execute is less likely than one any authenticated user
can trigger. Every Likelihood score must be defensible by naming the `ADV#` that
realizes the threat and how hard it is for them.

Modern systems are **zero-trust by default**: assume no implicit trust anywhere
and treat every boundary crossing as something to authenticate and authorize. So
mark trust boundaries, but do not label them with a trust level (no
"trusted/untrusted", "public/internal", "DMZ"). Instead note each zone's
**authorization profile**, meaning which identities are expected and authorized to
operate inside it (for example, "authenticated end users", "service identities
with role X", "operators via break-glass"). The question is never "is this side
trusted?" but "who is allowed to cross here, and is that enforced?"

### Phase 2: Data-flow diagram
Produce a Mermaid DFD with trust boundaries drawn as subgraphs, each labeled by its
authorization profile. Every element from Phase 1 appears here. Mark any LLM
element clearly, since that gates ATLAS. See `references/templates.md`.

Keep the diagram legible. Beyond roughly 12 elements a single flowchart becomes
hard to read. When the system is larger, decompose it: draw one **context diagram**
showing boundaries and the major processes, then a **per-boundary sub-diagram**
that expands the elements inside each zone. Keep element IDs identical across
diagrams so the ledger still resolves to exactly one element.

### Phase 3: STRIDE enumeration
For each element and each boundary-crossing data flow, walk the applicable STRIDE
categories and record every real threat in the **ledger** with a threat ID and the
element it targets. Be specific about actor, precondition, and effect: "attacker
replays the session token captured on the admin flow (DF3) to act as an admin" is
better than "spoofing possible". Where a threat depends on an assumption, cite it
(`A#`).

Make coverage auditable. Go element by element, and for each letter that applies to
that element type (per the applicability matrix) do exactly one of two things:
record **at least one concrete threat**, or write an explicit **N/A with a one-line
reason** (for example, "T-R-DS1: N/A, store is append-only WORM, no in-place
modification path"). Never leave an applicable cell silently blank; a blank cell is
indistinguishable from an overlooked one. You are done with an element when every
applicable letter has either a threat or a justified N/A.

### Phase 4: LLM threats (only if the DFD contains an LLM)
For LLM element(s) and their data flows, enumerate LLM-specific threats (prompt
injection including indirect via retrieved content, jailbreak, system-prompt or
data leakage, unsafe agent tool invocation, training or RAG poisoning, model
extraction or inversion, model supply chain). Add them to the same ledger with a
`T-LLM-` threat ID. Still run STRIDE (Phase 3) on the surrounding software:
gateway, tool backends, vector store, orchestration.

### Phase 5: Map to MITRE
Apply the Mapping rules above: tag every ledger threat with valid ATT&CK IDs, and
LLM threats additionally with valid ATLAS IDs, taken from the catalog files.

### Phase 6: Risk rating and register
Score each threat as **Likelihood x Impact**, each rated 1 to 5, giving a total of
1 to 25, with a one-line justification per axis. **Likelihood must reference the
adversary**: name the `ADV#` that realizes the threat and factor in their access and
capability. A threat any authenticated user can trigger scores higher than one
needing rare capability or privileged access. Bands: 1-4 Low, 5-9 Medium, 10-14
High, 15-25 Critical. Promote scored threats into the **Risk Register**, ranked by
score. Likelihood x Impact is the only scoring method used here; do not substitute
DREAD, OWASP Risk Rating, or any other scheme.

### Phase 7: Remediations and mitigations
For each risk (highest first), recommend controls, reasoning from first principles
about the specific threat rather than from a canned list. Classify each control by
function (**Preventive**, **Detective**, or **Corrective**) and by **layer**
(Network, Application, Data, Endpoint, Process). Aim for defense in depth: no single
point of failure, ideally at least one preventive and one detective control on every
High or Critical risk. State the **residual risk** after each control. Close with a
prioritized roadmap: quick wins first, then strategic items, then accept or monitor.

### Phase 8: Assemble the report
Combine everything using the report structure in `references/templates.md`. Preserve
traceability: every risk points back to its threat(s), and every threat to its
element and its MITRE technique(s). In the appendix, echo the catalog snapshot line
(the `_Source:_` line at the top of each catalog file you used) so the reader knows
the vintage of the ATT&CK/ATLAS IDs and can re-verify any ID against the live matrix
at attack.mitre.org or atlas.mitre.org.

## Traceability and IDs

- **Elements:** `E#` external entity, `P#` process, `DS#` data store, `DF#` data flow.
- **Adversaries:** `ADV#`, a threat-actor profile (access, capability, motivation). Likelihood scores cite the `ADV#` that realizes the threat.
- **Assumptions:** `A#`, a stated premise the model rests on. Threats cite the `A#` they depend on.
- **Threats (ledger):** `T-{S|T|R|I|D|E}-{elementID}-{seq}` (for example, `T-S-P1-01`); LLM threats use `T-LLM-{elementID}-{seq}`.
- **Risks (register):** `R-{seq}`, referencing one or more threats.
- **Mitigations:** `M-{seq}`, referencing one or more risks.

Sanity check before finishing: every ledger threat has at least one valid MITRE
technique and a status; every High or Critical risk has at least one mitigation;
every Likelihood score names the `ADV#` behind it. State the counts (threats
identified, risks registered, risks with mitigations, and unverified assumptions)
so any gap is visible. Call out unverified load-bearing assumptions explicitly: an
unconfirmed assumption can invalidate every threat that cites it, which is a larger
exposure than most individual findings.

## Output contract

Deliver all of the following, ideally as one Markdown report:

1. **Data-flow diagram:** Mermaid, trust boundaries as subgraphs labeled by
   authorization profile. Mermaid is chosen deliberately: it renders in Markdown and
   imports directly into Lucidchart (via Lucidchart's Mermaid import), giving an
   editable chart. Note this in the deliverable.
2. **Threat ledger:** the complete enumeration (every threat ID, element, STRIDE or
   LLM category, MITRE mapping, status).
3. **Risk register:** scored and ranked (every risk ID).
4. **Remediations and mitigations:** mapped controls, defense in depth, and a
   prioritized roadmap.

## References (load only when needed)

- `references/attack-techniques.md`: complete valid MITRE ATT&CK Enterprise catalog (the source of truth for ATT&CK mapping). Carries a dated snapshot line; echo it in the report appendix.
- `references/atlas-techniques.md`: complete valid MITRE ATLAS catalog (used only when an LLM is in the DFD). Carries a dated snapshot line; echo it in the report appendix.
- `references/code-recon.md`: code-first hunt checklist for where entry points, authN/authZ, secrets, deserialization, and data stores typically live per stack.
- `references/worked-example.md`: one small system taken end to end (scope, DFD, ledger, risk register, mitigations) as a format anchor.
- `references/templates.md`: DFD, ledger, risk-register, and report format schemas.
- `references/catalog-maintenance.md`: how to refresh the ATT&CK/ATLAS catalogs from MITRE source and validate them (not needed during a threat model; use when updating the catalogs).
