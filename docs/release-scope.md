# Distribution selection and redaction

The original research directory is unchanged and is not a Git repository. This release starts a new Git history; it does not pretend the research has historical Git commits.

Included: selected project-authored prototype and runner source, licensed zlib fixture, glibc patch with notices, final reports, numeric result exports and safe offline inspection tools. The main reference is A+B; later experimental variants are indexed separately.

Excluded by default: raw run logs/serial traces, VM images/disks/initramfs, generated binaries, dependency bundles/wheels, full Linux/glibc/CPython source trees, cloned Agent/related-work repositories, original benchmark workspaces, public/private trajectories, Feishu content and attachments, credentials, private service details, caches and unrelated newer architecture-discovery branches.

Sanitized snapshots replace the original user's home prefix with `/path/to/research-host`, omit private Feishu URLs and private-network addresses, and mark links to omitted run artifacts. Numeric result values are not changed. Do not interpret sanitized paths as portable deployment configuration. `docs/source-manifest.json` records both original-file and released-file SHA256 values. Omitted raw evidence prevents complete independent requalification from this checkout alone.

Reports are mostly in their original Chinese; the README and navigation documents are English. Historical reports retain dated scope and open issues; later results do not retroactively certify earlier paths.
