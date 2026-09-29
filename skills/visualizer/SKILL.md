---
name: visualizer
description: >-
  Decides HOW to visualize a logical structure so a person understands it quickly: picks the lens (structure, flow,
  state/rules, or user journey), the abstraction level and the medium, then renders simple cases as Mermaid and hands
  interactive ones to the built-in generative_ui skill. Invoke when the user asks to visualize or diagram a
  specification, architecture, codebase, game or business loop, or user journey, or invokes /visualizer.
  Not for UI mockups or visual design (use antislop / generative_ui directly) and not for raster images.
---

# Visualizer — Comprehension-First Diagramming

The job is to choose what to draw, not to draw everything. Rendering belongs to Mermaid (simple cases) or the built-in `generative_ui` skill (interactive cases); this skill decides the lens, the grouping and what stays out of the picture.

## 1. Pick the lens (one primary, at most one secondary)

| Lens | Question it answers | Typical inputs | Flag |
|---|---|---|---|
| Structure | What are the parts and what depends on what? | architectures, module/import graphs, data models | `--arch`, `--code` |
| Flow | In what order do things happen for one trigger? | request lifecycles, pipelines, CI/CD | `--flow` |
| State & rules | Under which condition does the system move to which state? | specs, permission/pricing rules, game or growth loops | `--spec`, `--loop` |
| Journey | What does a user action trigger behind the screen? | onboarding, checkout, report generation | `--journey` |

Without a flag, choose the lens from the user's question, say which one you chose in one line, and offer the others.

## 2. Grounding

* **Code (`--code`):** never infer dependencies from memory. Run a small script in scratch (`ast`/import scan or directory walk) that emits the real graph as JSON, and draw from that data.
* **Specs:** every node, state and transition cites the clause it comes from; a rule you cannot cite is marked as an assumption.

## 3. Keep it readable (defaults, not hard caps)

* Aim for at most about 9 top-level nodes per view; group larger systems into 4–7 clusters and let the reader expand a cluster. Keep a flat view when grouping would hide the point (e.g. a strictly linear 12-step pipeline).
* A node carries a short title and one tag; details (clauses, payloads, file paths) go into a side panel or a list below the diagram.
* Colour encodes meaning only (e.g. success path, waiting/limit, error/blocked, inactive), with the same meaning across all views and WCAG AA contrast (see `DESIGN.md`).

## 4. Choose the medium

* **Simple** (roughly ≤ 9 nodes, one scenario): a Mermaid `flowchart`, `sequenceDiagram` or `stateDiagram-v2` in the answer.
* **Several scenarios or layered detail:** hand a compact interactive view to `generative_ui` (tabs or a step control for happy path / edge case / failure).
* **Large systems** (C4-style layers, full spec simulators): a standalone interactive artifact built with `generative_ui`, with the diagram on one side and the selected node's details on the other.
* Never use generated raster images for logical diagrams: labels and arrows must be exact.

## 5. Delivery

State the lens and scope in one line, deliver the diagram, then list anything deliberately left out or assumed. If the structure was too large for one view, name the clusters and offer to open one.
