# Research history

## 1. Bubblewrap: start from inexpensive isolation

We investigated whether Linux isolation could be created, destroyed and organized more flexibly. Bubblewrap already supplied mature construction primitives, so we built prototypes and measured cost rather than designing another sandbox from scratch. Application initialization often cost more than domain creation, moving attention toward the programs inside.

## 2. Worker Pool: preserve programs that are ready

We built fixed NumPy and clangd workers inside persistent domains, compared fresh/reused execution, tested static shared/separate layouts and measured retained memory. Reuse helped on repeated controlled requests. Complete Workers consumed memory and carried application state; SAND and FaasCache also provided close precedents for organization and retention.

The next question was whether only shared initialization could survive, independently of each application Worker and domain.

## 3. Zygote: share initialized state across independent domains

We implemented Z → S → W without execing Python in descendants, repaired lifecycle and restricted fork runtime compatibility, admitted a fixed NumPy CPU recipe, then compared G0–G4. Additional experiments covered COW, initialization levels, concurrency, memory pressure and template switching. These experiments found real performance boundaries rather than one universally winning layout.

Real-agent investigation followed within this direction: public trajectories, executor source review, private-VM replay/process observation, multi-session qualification and dependency diagnostics. Persisting a container was already common; many commands still created new processes, but legal heap-sharing coverage remained unproven. Ordinary caches also removed some repeated initialization.

Cross-domain Zygotes, dependency trees and warming/cache/routing had substantial overlap with SOCK/OpenLambda, Forklift, FaasCache and Archipelago. Single-spawn permission studies and protocol simplifications did not establish a distinct whole-system improvement under the original contract. A complete automatic joint scheduler was never built.

## 4. Transparent CLI: explore automatic admission

Agent commands such as `python test.py` and `python -m pytest` motivated a lightweight classifier selecting native execution or a warm path without changing the command. We studied fresh-process semantics, mutable project code, callback authority, invalidation and side effects, and examined pyforkexec, pytest-fast, Zygo and Containerless.

No new transparent CLI classifier or execution system was implemented, and no corresponding performance result was obtained. Existing work covered many constituent mechanisms while preserving arbitrary CLI behavior remained expensive. The project lead paused new core implementation on these directions, retaining the prototypes, qualified results and negative evidence. This is a research allocation decision, not a proof that warming is impossible or an announcement of a new primary direction.
