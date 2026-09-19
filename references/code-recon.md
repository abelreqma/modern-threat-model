# Code-First Recon Checklist

Use this on a **Code folder** input to build the element list and ground threats in
real `file_path:line` evidence. The goal is to recover the DFD from the code: entry
points, trust boundaries, data stores, and the security-relevant handling in
between. Grep is a starting point, not proof; open the file and confirm before
recording a finding.

## What to recover (maps to DFD element types)

| DFD target | You are hunting for | Typical locations |
|------------|---------------------|-------------------|
| **External entities / entry points** (`E#`, `P#`) | Every way input reaches the system | HTTP routes/controllers, GraphQL resolvers, gRPC/RPC services, message/queue consumers, webhooks, CLI commands, cron/scheduled jobs, event/lambda handlers |
| **Trust boundaries** | Where control changes hands | Auth middleware, API gateway config, service-to-service calls, third-party API clients, network/deploy manifests |
| **Data stores** (`DS#`) | Where state persists | ORM models/migrations, DB clients, cache clients, object-storage SDKs, message queues, local files |
| **Data flows** (`DF#`) | What crosses each boundary and its protection | Serializers/DTOs, request/response schemas, TLS/transport config |

## Security-relevant handling to locate (feeds STRIDE)

- **AuthN (Spoofing):** where identity is established (session/JWT verification,
  API-key checks, mTLS, OAuth/OIDC middleware). Note what is unauthenticated.
- **AuthZ (Elevation):** where access decisions are made (role/permission checks,
  policy engines, ownership/object-level checks). Flag any handler that trusts a
  client-supplied id or role. Missing or inconsistent checks are the most common
  source of elevation findings.
- **Secrets handling (Info disclosure):** hardcoded secrets, `.env`/config files,
  key management, logging of tokens/PII. Grep: `password|secret|api[_-]?key|token|
  private[_-]?key|BEGIN.*PRIVATE`.
- **Input handling / injection (Tampering, EoP):** raw SQL string-building, shell/
  `exec`/`eval`, template rendering, path joins from user input, redirect targets.
- **Deserialization (Tampering, EoP):** `pickle`, `yaml.load`, Java/`ObjectInputStream`,
  `Marshal`, `unserialize`, and any decode of untrusted bytes into objects.
- **Crypto and transport (Info disclosure, Tampering):** TLS enforcement, hashing of
  passwords (argon2/bcrypt/scrypt vs md5/sha1), random source (CSPRNG vs `Math.random`).
- **Logging and audit (Repudiation):** is each security-relevant action attributably
  logged, and is the log tamper-evident or append-only?
- **Resource bounds (DoS):** pagination caps, request-size limits, timeouts, rate
  limits, unbounded loops/fan-out, expensive queries, regex on user input (ReDoS).
- **Dependencies (supply chain / Tampering):** manifest plus lockfile present, pinned
  versions, known-risky packages. Note but do not run a CVE scan (out of scope).

## LLM signals (gate for Phase 4 and ATLAS)

Search for LLM/agent usage so the ATLAS gate resolves correctly. Grep:
`openai|anthropic|claude|langchain|llama|llm|embedding|vector|rag|retrieval|
tool[_-]?call|agent|prompt`. If any LLM call, agent, or RAG/retrieval pipeline feeds
a model, mark that element in the DFD and run Phase 4.

## Method

1. Enumerate entry points first; they define the attack surface and the process list.
2. For each entry point, trace inward to the data store it touches, noting every
   boundary crossing and its protection as a `DF#`.
3. Record what you could not determine from code as an `A#` assumption (see SKILL.md
   Phase 1) rather than guessing.
4. Anchor every finding to `file_path:line`. A threat with no code evidence on a code
   input is a hypothesis; mark it `Needs-info`.
