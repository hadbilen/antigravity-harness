---
name: mistake-proofing
description: >-
  Poka-yoke design for code: shapes interfaces, data models, and state machines so mistakes are prevented at compile or
  parse time (Fit, Completeness, Order), and eliminates whole hazard classes after a recurring bug. Invoke with
  /mistake-proofing, when designing APIs around money, permissions, deletion, or migrations, or when a bug recurs
  ("yine aynı hata", "bir daha olmasın", "tekrar etti"). Not for read-only security boundary audits (use '/audit --boundary').
---

# Mistake-Proofing: Make the Mistake Impossible to Express

People and models will keep making mistakes. The goal of mistake-proofing (poka-yoke) is to prevent a mistake from becoming a defect by changing the shape of the code so that the wrong action cannot be written, or cannot go unnoticed.

## 1. What Counts as a Fix

A comment, a docstring, a naming convention, a checklist item, or a sentence in an instructions file that says "do not do X" is not a mistake-proofing fix. It relies on human or agent memory, which decays. A **device** does not rely on memory: a type that cannot represent the invalid state, a database constraint, a required keyword argument, or a mechanical check that fails the build.

"Add validation", "be careful with this function", and "document the invariant" are where the work starts, not where it ends. Each has a structural device behind it; naming and implementing that device is the task.

## 2. Two Questions for Every Finding

**Question 1: What happens when the mistake is made?** State which enforcement level the code is at today and which level the proposed device reaches:

| Level | Meaning | Examples |
|---|---|---|
| **Prevented** | The wrong action cannot be expressed or compiled | Distinct branded/newtype types, database `CHECK`/`UNIQUE` constraints, required keyword arguments, typestate transitions |
| **Announced** | It can be written, and fails immediately when checked or executed | Strict compiler/linter error, startup schema parse failure, runtime invariant assertion |
| **Found later** | It executes, and is discovered downstream | Unit tests, logs, monitoring alerts, code review |
| **Asked not to** | Authors are told to be careful | Comments, docstrings, conventions |

"Found later" is sometimes the highest level a language can reach, but a proposal that stops there must state so honestly and never call detection "prevention".

**Question 2: How would a device notice?** Inspect interfaces, schemas, and write paths through three lenses:

- **Fit:** Can the wrong value be passed where the right value belongs? Two adjacent parameters of the same primitive type; a free-form string that should be a closed union; money represented as IEEE 754 floating-point; a numeric duration without a unit.
- **Completeness:** Can an incomplete or unbounded set slip through? A `switch`/`match` over a closed union without an exhaustiveness check; a `DELETE` or `UPDATE` whose filter predicate can be empty; a silent default where no default is safe; required configuration looked up lazily inside a request handler instead of parsed at startup.
- **Order:** Can steps execute in the wrong sequence, or be skipped? An `init()`/`connect()` method that must be called before use; multi-step writes without a transaction; a retried external side effect without an idempotency key; a resource acquired on one path and not released on error paths.

Read [hazards.md](./hazards.md) for the recurring hazard catalog across Fit, Completeness, and Order, and read [languages.md](./languages.md) for what TypeScript, Python, Go, and Rust can and cannot enforce mechanically.

## 3. Designing Something New

A structural device costs least before an interface has callers; afterwards every device is a migration. Design from the call site first: a signature that looks clean in isolation often invites parameter swaps at the call site.

Five core moves, ordered by leverage:

1. **Make invalid states unrepresentable.** Replace bags of optional fields (`{status, data?, error?, retry_at?}`) where only certain combinations are valid with a discriminated/tagged union of the exact legal variants.
2. **Parse at the boundary once, don't validate repeatedly.** Convert unstructured boundary input into a validated domain type at the edge so downstream functions receive proof of validity in the type itself.
3. **Give distinct concepts distinct types (or keyword-only parameters)** so swapping `source_id` and `target_id` fails at compile time or cannot be written positionally.
4. **Encode execution order in types or scope.** Have step 1 return the token/handle required by step 2, and bind resource release to lexical scope (`with`, `defer`, `using`).
5. **Make destructive operations narrower than safe ones.** Require an explicit scope type for deletions and updates; never allow an empty filter to default to "all rows".

Conclude every new design with two explicit lists: **what the design now makes impossible**, and **what was deliberately left possible, and why** (`GEMINI.md` Rule 8).

## 4. Auditing Existing Code for Available Mistakes

When inspecting existing modules, ask not "where is the bug" but **"which mistakes are easy, silent, and look plausible?"**

- Walk the public functions, data models, and write paths through the three lenses (Fit, Completeness, Order).
- Rank findings by `Consequence × Ease of Mistake`: an unchecked primitive reaching a payment, deletion, permission check, or database write outranks an internal helper that crashes loudly.
- For each finding, report: the exact coordinate (`file:line`, symbol), the mistake available, its runtime consequence, the current level (`Asked not to` / `Found later`), and the proposed structural device with its target level (`Announced` / `Prevented`).
- Report the 3–5 highest-leverage hazards rather than padding a list. If no structural hazard qualifies, apply Constitution Rule 8's Null-Action Invariant.

## 5. After a Bug Recurred

Separate three layers, because the durable fix belongs to the third:

- the **defect**: the visible failure the user observed;
- the **mistake**: the wrong action the author or caller took;
- the **hazard**: the property of the interface or schema that made that mistake easy to make.

Fixing the mistake repairs one instance; fixing the hazard eliminates the class. After installing the device, search the repository for sibling occurrences of the same hazard shape and list them.

## 6. Guardrails & Prohibitions

- **Never accept "asked not to" (comments/docs) as a mistake-proofing fix** when a type, schema, or lint device is available.
- **Never weaken existing tests to fit a new device (`GEMINI.md` Rule 9).** Existing test assertions are never edited or deleted without explicit user authorization (`## Authorized Test Modifications` in `tasks.md`).
- **Size interface-changing devices by the `harness` 3-Tier Execution Ladder:** changing a public signature affects every caller and requires blast-radius mapping (`skills/harness/SKILL.md` §1).

<!-- Parts of this file and of hazards.md and languages.md are adapted from third-party work under the MIT License and were changed for this harness; see THIRD_PARTY_NOTICES.md. -->
