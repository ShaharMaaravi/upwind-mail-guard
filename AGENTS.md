# Working on Upwind Mail Guard

## Goal and context

This repository supports an Upwind Security Analyst take-home assignment. The candidate must understand the implementation, architecture, tradeoffs, and alternatives well enough to explain and modify the solution during an interview. Optimize for a small, complete, explainable product.

Read README.md first. It contains the assignment requirements and proposed architecture, milestones, security boundaries, alternatives, and references. Those proposals are not evidence that features are implemented. Inspect the actual files and git status before continuing.

## Current handoff

At the initial handoff on 2026-11-16, only the planning README and these instructions have been committed. There is no implementation, running backend, Gmail deployment, or executed test suite.

Next step: begin milestone 0, proving an installed Gmail add-on can call an authenticated HTTPS backend. First add appropriate ignore rules and example-only configuration, inspect available Python/Node tooling, then create the smallest integration scaffold. Establish actual Gmail scope and field availability before committing to extraction details. Do not silently mark a simulated API test as a successful Gmail integration.

The assignment PDF was read in full during planning. Its essential requirements are in the README. Do not publish the original private PDF or personal email content.

## Collaboration style

- Implement in small, coherent milestones; avoid a single large unexplained code dump.
- Before a meaningful design choice, explain the problem, chosen approach, a realistic alternative, and the cost of the choice. Proceed with routine work within the user's requested scope.
- After each milestone, trace one concrete example through the code and summarize relevant tests, remaining limitations, and likely interview questions.
- Maintain docs/decisions.md and docs/progress.md as implementation proceeds. Distinguish planned, implemented, automated-tested, and live-verified behavior.
- Keep the README accurate and reviewer-facing. Replace planning-only material with tested setup/run/demo instructions before submission.
- Use clear English for code and project documentation. Follow the user's chosen language for explanations.

## Engineering constraints

- The Gmail add-on is the product, with a separate backend. A CLI or separate web dashboard does not replace it.
- Prefer Apps Script/CardService and a modular Python/FastAPI backend unless evidence supports a change.
- Keep the analysis core deterministic and independent of Gmail/UI/network code.
- Treat all message data and external responses as untrusted. Bound inputs, escape rendered evidence, and avoid fetching message URLs or opening attachment contents.
- Keep Gmail tokens in the add-on and secrets outside source control. Use only synthetic fixtures. Inspect logs and error responses for accidental content exposure.
- Missing data, partial analysis, and backend failures must not be presented as a safe verdict.
- A heuristic score is not a calibrated probability. Document provisional weights and thresholds.
- Authentication-Results requires a justified trust boundary; a matching header string alone is insufficient.
- Prefer focused tests of observable behavior and important security boundaries. Record what was actually run.
- Do not add databases, queues, LLMs, reputation providers, or microservices without a concrete benefit that justifies their complexity.
- A public repository is authorized. Publishing private data, incurring hosting charges, and sending a submission to the recruiter are separate actions; do not infer those from repository creation.
