"""Fixed, trusted NumPy 2.2.6 CPU workload. No arbitrary imports or user code.

Executed only in the private VM. Observations are not a general fork guarantee.
"""
import os, sys, json, time, hashlib, ctypes, signal, resource
from pathlib import Path

PACKAGE = Path('/opt/shimos-numpy')
THREAD_ENV = {k: '1' for k in ('OPENBLAS_NUM_THREADS', 'OMP_NUM_THREADS',
                              'MKL_NUM_THREADS', 'BLIS_NUM_THREADS',
                              'VECLIB_MAXIMUM_THREADS', 'NUMEXPR_NUM_THREADS')}
NP = None
DATA = None
ORIGIN = None
LEVEL = 'none'
INITIAL = None
BLAS_HANDLE = None


def blas_state(mapped_files):
    """Query the already-loaded fixed backend; never load it before NumPy.

    get_num_threads reports the configured BLAS team size, not an observed
    Linux thread count. /proc/self/task and external thread history remain
    separate admission evidence. Keep one NOLOAD reference per process image.
    """
    global BLAS_HANDLE
    if NP is None:
        return {'status': 'NOT_LOADED', 'observed_num_threads': None}
    paths = [p for p in mapped_files
             if p.endswith('/numpy.libs/libscipy_openblas64_-56d6093b.so')]
    if len(paths) != 1:
        raise RuntimeError('fixed OpenBLAS mapping missing or ambiguous', paths)
    if BLAS_HANDLE is None:
        BLAS_HANDLE = ctypes.CDLL(paths[0], mode=os.RTLD_NOLOAD | os.RTLD_LOCAL)
    count = BLAS_HANDLE.scipy_openblas_get_num_threads64_
    count.argtypes = []; count.restype = ctypes.c_int
    parallel = BLAS_HANDLE.scipy_openblas_get_parallel64_
    parallel.argtypes = []; parallel.restype = ctypes.c_int
    config = BLAS_HANDLE.scipy_openblas_get_config64_
    config.argtypes = []; config.restype = ctypes.c_char_p
    return dict(status='OBSERVED', mapped_path=paths[0],
                observed_num_threads=count(), parallel_backend=parallel(),
                configuration=config().decode('ascii'),
                count_semantics='backend configured team size; not OS thread count',
                query='existing DSO via RTLD_NOLOAD; no backend setter')


def emit(event, **fields):
    print(json.dumps(dict(event=event, monotonic_ns=time.monotonic_ns(),
                         pid_namespace_local=os.getpid(), **fields)), flush=True)


def memory(pid='self'):
    result = {'pid': str(pid), 'monotonic_ns': time.monotonic_ns()}
    try:
        rows = Path('/proc/' + str(pid) + '/smaps_rollup').read_text().splitlines()
        result['KiB'] = {k: int(v.split()[0]) for line in rows if ':' in line
                         for k, v in [line.split(':', 1)] if v.strip().endswith('kB')}
    except OSError as error:
        result['error'] = repr(error)
    if pid == 'self':
        u = resource.getrusage(resource.RUSAGE_SELF)
        result['usage'] = dict(user_s=u.ru_utime, system_s=u.ru_stime,
                               minflt=u.ru_minflt, majflt=u.ru_majflt, maxrss_KiB=u.ru_maxrss)
    return result


def audit():
    try:
        function = ctypes.CDLL(None).shimos_numpy_audit_snapshot
    except AttributeError:
        return {'status': 'NOT_LOADED', 'callback_registration_observed': False}
    function.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    function.restype = ctypes.c_int
    buf = ctypes.create_string_buffer(262144)
    result = function(buf, len(buf))
    if result:
        raise RuntimeError('numpy atfork audit export failed', result)
    return json.loads(buf.value)


def snapshot(label):
    fds = {}
    for name in os.listdir('/proc/self/fd'):
        try:
            st = os.fstat(int(name))
            fds[name] = dict(target=os.readlink('/proc/self/fd/' + name), dev=st.st_dev, ino=st.st_ino)
        except OSError:
            pass  # the already closed listdir FD is not a persistent FD
    maps = Path('/proc/self/maps').read_text()
    files = {}
    for line in maps.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and fields[5].startswith('/'):
            path = fields[5]
            files[path] = {'dev': fields[3], 'inode': int(fields[4])}
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    nnp = libc.prctl(39, 0, 0, 0, 0)  # PR_GET_NO_NEW_PRIVS
    if nnp < 0:
        raise OSError(ctypes.get_errno(), 'PR_GET_NO_NEW_PRIVS')
    seccomp = libc.prctl(21, 0, 0, 0, 0)  # PR_GET_SECCOMP
    if seccomp < 0:
        raise OSError(ctypes.get_errno(), 'PR_GET_SECCOMP')
    security = dict(uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid(),
                    resuid=list(os.getresuid()), resgid=list(os.getresgid()),
                    capabilities={k: status.get(k, '').strip()
                                  for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')},
                    nnp=nnp, seccomp=seccomp,
                    proc_no_new_privs=status.get('NoNewPrivs', '').strip(),
                    proc_seccomp=status.get('Seccomp', '').strip())
    return dict(label=label, monotonic_ns=time.monotonic_ns(), pid_namespace_local=os.getpid(),
                threads=sorted(os.listdir('/proc/self/task')), fds=fds,
                environment=dict(os.environ), signals={k: status.get(k, '').strip() for k in ('SigBlk', 'SigIgn', 'SigCgt')},
                signal_handlers={str(int(s)): str(signal.getsignal(s)) for s in (signal.SIGCHLD, signal.SIGINT, signal.SIGTERM, signal.SIGPIPE)},
                maps=files, memory=memory(), audit=audit(), security=security,
                blas=blas_state(files))


def fixed_arrays():
    # The inputs are recreated from a fixed mathematical definition, not RNG.
    x = NP.arange(1024, dtype=NP.float64).reshape(32, 32)
    a = (NP.arange(128 * 128, dtype=NP.float64).reshape(128, 128) % 31) / 17
    b = (NP.arange(128 * 128, dtype=NP.float64).reshape(128, 128) % 23) / 13
    return x, a, b


def outputs():
    x, a, b = fixed_arrays()
    return {'slice': x[::3, 1::4].copy(),
            'broadcast': (x[:4, :8] + NP.arange(8, dtype=NP.float64)).copy(),
            'sums': NP.array([x.sum(), x[:, ::2].sum()], dtype=NP.float64),
            'matmul': a @ b}


def fingerprint():
    if NP is None:
        return {'level': 'none', 'numpy_loaded': False}
    return dict(level=LEVEL, numpy_loaded=True, version=NP.__version__,
                module_id=id(NP), origin_pid=ORIGIN, geterr=NP.geterr(),
                data_id=id(DATA) if DATA is not None else None,
                data_sha256=hashlib.sha256(memoryview(DATA).cast('B')).hexdigest() if DATA is not None else None,
                data_writeable=bool(DATA.flags.writeable) if DATA is not None else None,
                data_bytes=int(DATA.nbytes) if DATA is not None else 0)


def initialize(level, location):
    global NP, DATA, ORIGIN, LEVEL, INITIAL
    assert level in ('import', 'data', 'blas') and NP is None
    start = time.monotonic_ns(); cpu = time.process_time_ns(); before = snapshot('before_import')
    old = dict(os.environ)
    os.environ.update(THREAD_ENV)
    if str(PACKAGE) not in sys.path:
        sys.path.insert(0, str(PACKAGE))
    try:
        import numpy
        NP = numpy
        assert NP.__version__ == '2.2.6' and Path(NP.__file__).is_relative_to(PACKAGE)
        imported = snapshot('imported_with_thread_configuration')
        imported_ns = time.monotonic_ns()
        if level in ('data', 'blas'):
            DATA = NP.arange(1024 * 1024, dtype=NP.float64)
            DATA.flags.writeable = False
        if level == 'blas':
            x, a, b = fixed_arrays()
            answer = a @ b
            assert NP.isfinite(answer).all()
        initialized_ns = time.monotonic_ns()
    finally:
        os.environ.clear(); os.environ.update(old)
    ORIGIN = os.getpid(); LEVEL = level; INITIAL = fingerprint()
    after = snapshot('initialized')
    # These are explicit admission checks, not claims about all NumPy operations.
    checks = dict(single_before=len(before['threads']) == 1,
                  single_imported=len(imported['threads']) == 1,
                  single_after=len(after['threads']) == 1,
                  fds_unchanged=before['fds'] == after['fds'],
                  signals_unchanged=before['signals'] == after['signals'],
                  environment_restored=before['environment'] == after['environment'])
    record = dict(location=location, level=level, before=before, imported=imported, after=after,
                  checks=checks, fingerprint=INITIAL, start_ns=start,
                  import_ready_ns=imported_ns, initialized_ns=initialized_ns,
                  complete_ns=time.monotonic_ns(), cpu_ns=time.process_time_ns()-cpu)
    emit('NP_ADMISSION', **record)
    if not all(checks.values()):
        raise RuntimeError('NumPy preload denied', checks)
    return record


def page_flags():
    """Pagemap flags only; no PFN or exact COW-page-count claim."""
    if DATA is None:
        return {'status': 'NO_PRELOADED_DATA'}
    import struct
    page = os.sysconf('SC_PAGE_SIZE'); address = int(DATA.__array_interface__['data'][0])
    first = address // page; last = (address + DATA.nbytes - 1) // page
    try:
        with open('/proc/self/pagemap', 'rb', buffering=0) as f:
            f.seek(first * 8); raw = f.read((last-first+1)*8)
        values = struct.unpack('<' + 'Q' * (len(raw)//8), raw)
        return dict(status='OBSERVED', pages=len(values), present=sum(bool(v & (1<<63)) for v in values),
                    exclusive=sum(bool(v & (1<<56)) for v in values), soft_dirty=sum(bool(v & (1<<55)) for v in values),
                    interpretation='exclusive/soft-dirty flags, not a count of newly copied pages; no clear_refs',
                    data_address=address, page_size=page)
    except OSError as e:
        return {'status': 'UNAVAILABLE', 'error': repr(e)}


def execute(req):
    nonce=req['nonce']; level=req['numpy_level']; baseline=req['numpy_baseline']
    start=time.monotonic_ns(); cpu=time.process_time_ns()
    inherited = NP is not None
    if baseline == 'cold':
        assert not inherited
        initialize(level, 'W_cold')
    else:
        assert inherited and LEVEL == level and ORIGIN != os.getpid()
    before = snapshot('W_numpy_before'); before_fp=fingerprint(); before_pages=page_flags()
    compute_begin=time.monotonic_ns()
    actual=outputs()
    compute_end=time.monotonic_ns()
    source=Path('/src/numpy-reference.npz')
    with NP.load(source, allow_pickle=False) as expected:
        comparisons = {k: dict(ok=bool(NP.allclose(v, expected[k], rtol=1e-12, atol=1e-10)),
                               max_abs_error=float(NP.max(NP.abs(v-expected[k]))), shape=list(v.shape))
                       for k,v in actual.items()}
    NP.savez('/work/numpy-output.npz', **actual)
    computation_failure = None
    if req.get('numpy_case') == 'compute_failure':
        try:
            NP.ones((2,3)) @ NP.ones((4,2))
        except ValueError as e:
            computation_failure = {'type':'ValueError','message':str(e),'actual_operation':'incompatible-shape matmul'}
        else:
            raise AssertionError('expected NumPy shape failure absent')
    # One bounded COW write in the normal workload, full-page sensitivity separately.
    cow_bytes=0
    if DATA is not None:
        DATA.flags.writeable=True
        if req.get('numpy_case') == 'cow_all':
            DATA[::512] += 1; cow_bytes=int(DATA.nbytes)
        else:
            DATA[0] += 1; cow_bytes=8
        DATA.flags.writeable=False
    after_pages=page_flags(); after=snapshot('W_numpy_after')
    checks=dict(numerical=all(x['ok'] for x in comparisons.values()),
                single_thread=len(before['threads'])==len(after['threads'])==1,
                fds_restored=before['fds']==after['fds'],
                signals_unchanged=before['signals']==after['signals'],
                env_unchanged=before['environment']==after['environment'],
                inherited=(inherited and ORIGIN!=os.getpid()) if baseline=='hot' else not inherited,
                expected_failure=computation_failure is not None if req.get('numpy_case')=='compute_failure' else True)
    record=dict(nonce=nonce, baseline=baseline, level=level, inherited_preload=inherited,
                initial_fingerprint=before_fp, after_cow_fingerprint=fingerprint(),
                before=before, after=after, pages_before=before_pages, pages_after=after_pages,
                requested_cow_write_bytes=cow_bytes, numerical=comparisons,
                reference_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                output_sha256=hashlib.sha256(Path('/work/numpy-output.npz').read_bytes()).hexdigest(),
                checks=checks, computation_failure=computation_failure,
                call_start_ns=start, compute_begin_ns=compute_begin, compute_end_ns=compute_end,
                done_ns=time.monotonic_ns(), cpu_ns=time.process_time_ns()-cpu,
                initialized_in_this_worker=baseline=='cold')
    emit('NP_RESULT', **record)
    if not all(checks.values()):
        raise RuntimeError('NumPy worker validation failed',checks)
    return record
