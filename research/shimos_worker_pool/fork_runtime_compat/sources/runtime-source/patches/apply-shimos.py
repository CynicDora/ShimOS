from pathlib import Path
root = Path(__file__).resolve().parents[1] / 'glibc-2.35-ubuntu'
p = root / 'posix/fork.c'
s = p.read_text()
if 'shimos_fork_into_cgroup' in s:
    raise SystemExit('source already patched; refusing duplicate application')
for rel, original in [('posix/fork.c', 'fork.c.original'), ('sysdeps/nptl/_Fork.c', '_Fork.c.original'), ('posix/Versions', 'Versions.original')]:
    if (root / rel).read_bytes() != (Path(__file__).resolve().parent / original).read_bytes():
        raise SystemExit('unexpected source bytes: ' + rel)
s = s.replace('pid_t\n__libc_fork (void)\n{', '''/* Research-only Linux extension.  A source-level integration preserves the
   native fork wrapper.  No external caller accesses glibc private symbols. */
extern pid_t __shimos_Fork_into_cgroup (int, int *) attribute_hidden;

static pid_t
shimos_libc_fork_common (bool into_cgroup, int cgfd, int *pidfd)
{''')
s = s.replace('pid_t pid = _Fork ();', '''pid_t pid = into_cgroup ? __shimos_Fork_into_cgroup (cgfd, pidfd)
                          : _Fork ();''')
s = s.replace('weak_alias (__libc_fork, __fork)', '''pid_t
__libc_fork (void)
{
  return shimos_libc_fork_common (false, -1, NULL);
}

/* Nonstandard API, supported only by this pinned experimental libc build. */
pid_t
shimos_fork_into_cgroup (int cgfd, int *pidfd)
{
  return shimos_libc_fork_common (true, cgfd, pidfd);
}
weak_alias (__libc_fork, __fork)''')
p.write_text(s)
p = root / 'sysdeps/nptl/_Fork.c'
s = p.read_text().replace('#include <pthreadP.h>', '#include <pthreadP.h>\n#include <clone3.h>\n#include <stdint.h>\n\n#ifndef CLONE_INTO_CGROUP\n# define CLONE_INTO_CGROUP 0x200000000ULL\n#endif')
s = s.replace('pid_t\n_Fork (void)\n{\n  pid_t pid = arch_fork (&THREAD_SELF->tid);', '''/* Same-stack fork semantics: no CLONE_VM, CLONE_THREAD or CLONE_SETTLS. */
static pid_t
shimos_arch_fork_cgroup (int cgfd, int *pidfd)
{
  struct clone_args args = {
    .flags = CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID
             | CLONE_INTO_CGROUP | CLONE_PIDFD,
    .child_tid = (uintptr_t) &THREAD_SELF->tid,
    .pidfd = (uintptr_t) pidfd,
    .exit_signal = SIGCHLD,
    .cgroup = (unsigned int) cgfd
  };
  /* Fail closed: never silently fall back to fork or cgroup migration. */
  return INLINE_SYSCALL_CALL (clone3, &args, sizeof (args));
}

static pid_t
shimos_Fork_common (bool into_cgroup, int cgfd, int *pidfd)
{
  pid_t pid = into_cgroup ? shimos_arch_fork_cgroup (cgfd, pidfd)
                          : arch_fork (&THREAD_SELF->tid);''')
s = s.replace('libc_hidden_def (_Fork)', '''pid_t
_Fork (void)
{
  return shimos_Fork_common (false, -1, NULL);
}
libc_hidden_def (_Fork)

pid_t __shimos_Fork_into_cgroup (int, int *) attribute_hidden;
pid_t
__shimos_Fork_into_cgroup (int cgfd, int *pidfd)
{
  return shimos_Fork_common (true, cgfd, pidfd);
}''')
p.write_text(s)
p = root / 'posix/Versions'
s = p.read_text().replace('  GLIBC_2.35 {\n', '  GLIBC_2.35 {\n    shimos_fork_into_cgroup;\n')
p.write_text(s)
