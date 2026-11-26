# Execution architecture and responsibilities

## Which source to read

The primary compact mechanism reference is [integration_ab/prototype](../research/shimos_worker_pool/integration_ab/prototype). It combines the reliability repair with candidate D. The later [architecture_comparison_full/prototype](../research/shimos_worker_pool/architecture_comparison_full/prototype) contains the G0–G4 experiments, not a replacement production API. [Prototype index](../prototypes/README.md).

## Persistent domains and Workers

The early B-strict implementation separates a domain from its business process groups. A controller creates a task cgroup and a control leaf. Bubblewrap starts the domain owner/PID 1. Each business group has a guardian/subreaper and an application leader atomically created in its resource leaf. The collector receives output FDs through private inherited sockets.

A valid application response can arrive while a reused Worker remains alive. This is different from group completion. Strict completion requires real waits, output EOF and an empty cgroup. A shared domain is suitable only for the same trust/workspace/policy class; it is not an isolation boundary between its Workers. The frozen source is [experiments/baseline](../research/shimos_worker_pool/experiments/baseline) and the application protocol is [experiments/workers](../research/shimos_worker_pool/experiments/workers).

## Cross-domain process relationships

```text
H: independent trusted supervisor
└─ R: controller
   ├─ Bubblewrap monitor → target PID 1
   └─ Z: clean, trusted, initialized Python template
      └─ S: transition / actual parent and waiter of W
         └─ W: target-domain business Worker
```

The target PID 1 and namespaces exist before Z spawns S. Target namespace FDs and a root-directory reference are transported over private Unix sockets using SCM_RIGHTS and bound to an attempt identity. Entering a namespace, belonging to a cgroup and becoming a child are independent operations.

In the qualified path S enters the target Base user namespace, mount/network/IPC/UTS namespaces and selects the target PID namespace for children; changes root/cwd; then enters the Inner user namespace. It permanently drops capabilities, sets no_new_privs and installs the retained policy before the second fork. See [bridge_d.c](../research/shimos_worker_pool/integration_ab/prototype/bridge_d.c). The existing process S cannot migrate its own active PID namespace. Its next child W obtains the selected PID identity. The target PID 1 maintains that namespace's lifetime; it is not automatically W's Unix parent.

Z itself must remain in a permission/topology position that can construct descendants. Moving it irreversibly into a target user or mount namespace is not a free simplification. The [single-spawn review](../research/shimos_worker_pool/single_spawn_feasibility/reports/checkpoint-c.md) separates the original permission failure from a different legally constructed diagnostic topology. Neither is a complete, equivalent one-fork ShimOS integration.

## Memory and the fork runtime

Both fork edges preserve initialized memory through normal inheritance/COW. Z's initial startup uses exec; S and W do not exec Python. A later exec of an external tool replaces this memory and must not be described as NumPy heap reuse.

Raw clone3 was found insufficient for the preserved Python runtime: native atfork callbacks, thread identity and robust mutex bookkeeping matter. Candidate D changes a pinned glibc source build to preserve the full fork wrapper while using clone3(CLONE_INTO_CGROUP), with CPython before/after hooks around it. The [bridge](../research/shimos_worker_pool/integration_ab/prototype/bridge_d.c) refuses a missing vendor entry instead of falling back to an incompatible path. Stock libc is used for H/R; D's loader/libc/DSO closure is explicitly verified for Z/S/W.

Callbacks execute before the final business gate and can see management state/FDs. Admission is therefore a trust decision about the actual initialization and callbacks, not a consequence of single-thread settings or caps=0 alone. Only fixed trusted templates have passed relevant qualification.

## Authorization, wait and cleanup

Per-attempt nonces bind the protocol to protected kernel-object references. SPAWN/PREPARED/COMMIT and the Worker/business gates separate preparation from permission to execute. Cancellation first closes future permission, then stops existing work. cgroup.kill is not a durable prohibition on a late fork.

S really waits W; Z really waits S; R manages the monitor/domain; H can survive R's death, stop creators, reap legally adopted descendants and release registered resources. A pidfd gives stable observation/signaling, not general permission to wait an unrelated process. Business result, spawn knowledge and resource-release status are separate. Lost results can remain UNKNOWN even after cleanup succeeds; incomplete cleanup must not be called RELEASED.

The [A+B report](../research/shimos_worker_pool/integration_ab/integration-report.md) documents 29 attempts covering budget refusal, missing receipts, cancellation, Z/PID 1 failures and H takeover. Its contract assumes H survives. Later Tool Exec follow-up tests cover additional supervisor scenarios under a distinct, still bounded contract; they do not upgrade every earlier prototype automatically.

## Resources and security

The qualified child-creation path places S/W into their designated cgroups at birth. Existing shared pages do not acquire a new independent physical charge for every descendant. Root cgroup accounting is hierarchical: do not add a parent usage value to its children. PSS snapshots, private dirty pages and memcg peaks answer different questions; none alone proves net physical-memory savings.

The experiments retain target filesystem views, namespaces, capability reduction, no_new_privs, seccomp, FD cleanup and execution gates. The retained policy is a research denylist, not a general production allowlist. Identical seccomp mode numbers do not establish equivalent safety. G4's known-state reset also does not recreate a fresh process.
