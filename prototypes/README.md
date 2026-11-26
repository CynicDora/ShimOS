# Prototype source index

Sources retain study-relative locations rather than being merged into an invented production API.

| Role | Source | Status |
|---|---|---|
| B-strict persistent-domain substrate | [baseline](../research/shimos_worker_pool/experiments/baseline) | Frozen strong lifecycle composition, not an arbitrary persistent Shell adapter |
| NumPy/clangd Worker protocol | [workers](../research/shimos_worker_pool/experiments/workers) | Trusted serial fixed application requests |
| Original cross-domain experiment | [cross_domain_zygote](../research/shimos_worker_pool/cross_domain_zygote/prototype) | Historical raw-runtime mechanism; **not the corrected performance baseline** |
| Lifecycle repair A | [reliability_fix](../research/shimos_worker_pool/reliability_fix/prototype) | Independent history; superseded for runtime compatibility |
| **Main compact Zygote reference** | [integration_ab](../research/shimos_worker_pool/integration_ab/prototype) | A + full candidate-D wrapper, 29 bounded attempts |
| Validated PING merge | [ping_merged](../research/shimos_worker_pool/cost_breakdown/ping_merged) | Combines template check with FORGOTTEN, preserves checks |
| NumPy admission | [numpy_admission](../research/shimos_worker_pool/numpy_admission/prototype) | Fixed trusted CPU profile |
| G0/G1/G2 | [round1](../research/shimos_worker_pool/architecture_comparison_round1/prototype) | Independent-domain comparison |
| G2/G3/G4 and bounded concurrency | [full](../research/shimos_worker_pool/architecture_comparison_full/prototype) | Qualified research variants, not general scheduler |
| Tool execution follow-up | [followup](../research/shimos_worker_pool/exec_support_followup/prototype) | Separate private receipts and H recovery contract |

Every directory includes historical guest/test code that must run only inside its declared private VM. Source presence does not mean a complete runtime image is included. Inspect [reproduction](../docs/reproduction.md) before executing a runner. The original unrelated root-level native MVP G1/G2/G3 vocabulary was not imported; here G0–G4 refers to the architecture research modes only.
