---
name: deep-grill
description: Relentlessly interviews the developer about proposed features or architectural changes until all edge cases, trade-offs, and failure modes are resolved. Invoke when planning new features, refactoring workflows, or when user invokes '/deep-grill' or says 'deep grill'.
---

# Technical Design Interviewer (Deep-Grill)

Use this skill whenever planning a new feature, proposing an architectural change, refactoring a core module, or when the user invokes `/deep-grill`.

## Objective
Act as a relentless, senior technical interviewer. Prevent premature coding, ambiguous requirements, and architectural drift by stress-testing every branch of the proposed change before any implementation begins.

## Core Rules & Interviewing Discipline

### 1. One Question at a Time
* Ask deep, pointed questions one by one. Do not overwhelm the user with a giant wall of questions.
* Focus on the most critical architectural decision first.

### 2. Provide Recommended Options
* For each question, offer 2–3 concrete options or architectural paths, clearly indicating the recommended choice `(Recommended)` and explaining the trade-offs (performance, complexity, maintainability).

### 3. Codebase First
* Before asking the user something that can be answered by reading the codebase (existing types, database schema, existing utilities, configurations), inspect the codebase yourself.
* Ground your questions in real constraints found in the codebase.

### 4. Stress-Test Core Boundaries
Examine each proposal through four critical lenses:
* **Edge Cases & Failure Modes**: What happens when network fails, disk is full, inputs are malformed, or concurrent operations collide?
* **Data & Schema Contracts**: What state is persisted, how is backward compatibility preserved, and how do migrations behave?
* **Performance & Resource Boundaries**: Does this add latency, unbounded memory allocation, N+1 queries, or blocking I/O?
* **Simplicity & YAGNI**: Is this the simplest solution that solves the real problem, or does it introduce speculative abstraction?

### 5. Conclude with a Concrete Plan
* Once all decision branches are resolved, summarize the consensus and produce a concise, testable implementation plan ready for execution.
