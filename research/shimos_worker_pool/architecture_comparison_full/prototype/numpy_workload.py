"""Fixed, trusted NumPy 2.2.6 CPU workload. No arbitrary imports or user code.

Executed only in the private VM. Observations are not a general fork guarantee.
"""
import os, sys, json, time, hashlib, ctypes, signal, resource
from pathlib import Path
import profile_spec

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
PROFILE = profile_spec.parse(os.environ.get('FULL_PROFILE', 'legacy'))
NUMPY_ORIGIN = None
DATA_ORIGIN = None
LAST_MUTATION = None
LAST_BEFORE_FINGERPRINT = None


def profile_config():
    return dict(PROFILE) if PROFILE is not None else None


def bind_profile(token):
    """Bind once before initialization; never switch an initialized template."""
    global PROFILE
    selected = profile_spec.parse(token)
    if PROFILE != selected:
        if PROFILE is not None or NP is not None or LEVEL != 'none':
            raise RuntimeError('request/profile mismatch', profile_config(), token)
        PROFILE = selected
    return profile_config()


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
    if PROFILE is not None:
        return dict(level=LEVEL, profile=profile_config(), numpy_loaded=NP is not None,
                    version=NP.__version__ if NP is not None else None,
                    module_id=id(NP) if NP is not None else None, origin_pid=ORIGIN,
                    numpy_origin_pid=NUMPY_ORIGIN, data_origin_pid=DATA_ORIGIN,
                    geterr=NP.geterr() if NP is not None else None,
                    data_id=id(DATA) if DATA is not None else None,
                    data_sha256=hashlib.sha256(memoryview(DATA).cast('B')).hexdigest() if DATA is not None else None,
                    data_writeable=bool(DATA.flags.writeable) if DATA is not None else None,
                    data_bytes=int(DATA.nbytes) if DATA is not None else 0)
    if NP is None:
        return {'level': 'none', 'numpy_loaded': False}
    return dict(level=LEVEL, numpy_loaded=True, version=NP.__version__,
                module_id=id(NP), origin_pid=ORIGIN, geterr=NP.geterr(),
                data_id=id(DATA) if DATA is not None else None,
                data_sha256=hashlib.sha256(memoryview(DATA).cast('B')).hexdigest() if DATA is not None else None,
                data_writeable=bool(DATA.flags.writeable) if DATA is not None else None,
                data_bytes=int(DATA.nbytes) if DATA is not None else 0)


def _legacy_initialize(level, location):
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


def initialize(level, location):
    """A profile level is preparation placement; business always completes it.

    The legacy branch is unchanged for existing G0/G1/G2 comparisons.
    """
    global NP, DATA, ORIGIN, LEVEL, INITIAL, NUMPY_ORIGIN, DATA_ORIGIN
    if PROFILE is None:
        return _legacy_initialize(level, location)
    if level not in profile_spec.LEVELS:
        raise ValueError('unknown fixed initialization level', level)
    if LEVEL not in ('none', *profile_spec.LEVELS):
        raise RuntimeError('incompatible prior initialization')
    rank = lambda value: -1 if value == 'none' else profile_spec.LEVELS.index(value)
    if rank(level) < rank(LEVEL):
        raise RuntimeError('cannot downgrade initialized state')
    if location == 'Z' and level != PROFILE['preload']:
        raise RuntimeError('Z preload level/profile mismatch')
    start=time.monotonic_ns(); cpu=time.process_time_ns(); old_level=LEVEL
    before=snapshot('before_profile_initialization'); imported=before
    imported_ns=None; stages=[]; old=dict(os.environ)
    os.environ.update(THREAD_ENV)
    try:
        if ORIGIN is None:
            ORIGIN=os.getpid()
        if LEVEL == 'none':
            LEVEL='base'; stages.append('base_python_state')
        if rank(level) >= rank('import') and NP is None:
            if str(PACKAGE) not in sys.path: sys.path.insert(0,str(PACKAGE))
            import numpy
            NP=numpy
            assert NP.__version__=='2.2.6' and Path(NP.__file__).is_relative_to(PACKAGE)
            NUMPY_ORIGIN=os.getpid(); LEVEL='import'; stages.append('numpy_import')
            imported=snapshot('imported_with_thread_configuration'); imported_ns=time.monotonic_ns()
        if rank(level) >= rank('data') and DATA is None:
            DATA=NP.arange(PROFILE['array_elements'],dtype=NP.float64)
            DATA.flags.writeable=False; DATA_ORIGIN=os.getpid()
            LEVEL='data'; stages.append('fixed_array_allocation')
        if rank(level) >= rank('blas') and LEVEL != 'blas':
            _,a,b=fixed_arrays(); answer=a@b
            assert NP.isfinite(answer).all()
            LEVEL='blas'; stages.append('fixed_128x128_blas_warmup')
        initialized_ns=time.monotonic_ns()
    finally:
        os.environ.clear();os.environ.update(old)
    INITIAL=fingerprint();after=snapshot('profile_initialized')
    checks=dict(single_before=len(before['threads'])==1,
                single_imported=len(imported['threads'])==1,
                single_after=len(after['threads'])==1,
                fds_unchanged=before['fds']==after['fds'],
                signals_unchanged=before['signals']==after['signals'],
                environment_restored=before['environment']==after['environment'])
    record=dict(location=location,level=level,previous_level=old_level,profile=profile_config(),
                preparation_stages=stages,numpy_import_performed='numpy_import' in stages,
                before=before,imported=imported,after=after,checks=checks,fingerprint=INITIAL,
                start_ns=start,import_ready_ns=imported_ns,initialized_ns=initialized_ns,
                complete_ns=time.monotonic_ns(),cpu_ns=time.process_time_ns()-cpu,
                scope='bounded trusted preparation plus explicit snapshots/hash; base does not import NumPy')
    emit('NP_ADMISSION',**record)
    if not all(checks.values()):raise RuntimeError('profile initialization denied',checks)
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


def _legacy_execute(req):
    global LAST_MUTATION, LAST_BEFORE_FINGERPRINT
    nonce=req['nonce']; level=req['numpy_level']; baseline=req['numpy_baseline']
    start=time.monotonic_ns(); cpu=time.process_time_ns()
    inherited = NP is not None
    persistent=req.get('numpy_persistent') is True
    if baseline == 'cold':
        assert not inherited
        initialize(level, 'W_cold')
    else:
        assert inherited and LEVEL == level and (persistent or ORIGIN != os.getpid())
    before = snapshot('W_numpy_before'); before_fp=fingerprint(); before_pages=page_flags()
    compute_begin=time.monotonic_ns()
    actual=outputs()
    compute_end=time.monotonic_ns()
    source=Path('/src/numpy-reference.npz')
    with NP.load(source, allow_pickle=False) as expected:
        comparisons = {k: dict(ok=bool(NP.allclose(v, expected[k], rtol=1e-12, atol=1e-10)),
                               max_abs_error=float(NP.max(NP.abs(v-expected[k]))), shape=list(v.shape))
                       for k,v in actual.items()}
    output=Path('/work')/profile_spec.output_name(req.get('numpy_output_name'))
    NP.savez(output, **actual)
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
    LAST_MUTATION=None; LAST_BEFORE_FINGERPRINT=before_fp
    if DATA is not None:
        DATA.flags.writeable=True
        if req.get('numpy_case') == 'cow_all':
            DATA[::512] += 1; cow_bytes=int(DATA.nbytes)
            LAST_MUTATION=dict(start=0,step_elements=512,elements=(DATA.size+511)//512)
        else:
            DATA[0] += 1; cow_bytes=8
            LAST_MUTATION=dict(start=0,step_elements=int(DATA.size),elements=1)
        DATA.flags.writeable=False
    after_pages=page_flags(); after=snapshot('W_numpy_after')
    checks=dict(numerical=all(x['ok'] for x in comparisons.values()),
                single_thread=len(before['threads'])==len(after['threads'])==1,
                fds_restored=before['fds']==after['fds'],
                signals_unchanged=before['signals']==after['signals'],
                env_unchanged=before['environment']==after['environment'],
                inherited=(inherited and (persistent or ORIGIN!=os.getpid())) if baseline=='hot' else not inherited,
                expected_failure=computation_failure is not None if req.get('numpy_case')=='compute_failure' else True)
    record=dict(nonce=nonce, baseline=baseline, level=level, inherited_preload=inherited,
                initial_fingerprint=before_fp, after_cow_fingerprint=fingerprint(),
                before=before, after=after, pages_before=before_pages, pages_after=after_pages,
                requested_cow_write_bytes=cow_bytes, numerical=comparisons,
                reference_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                output_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                output_name=output.name,reuse_model='persistent' if persistent else 'fork' if baseline=='hot' else 'cold',
                checks=checks, computation_failure=computation_failure,
                call_start_ns=start, compute_begin_ns=compute_begin, compute_end_ns=compute_end,
                done_ns=time.monotonic_ns(), cpu_ns=time.process_time_ns()-cpu,
                initialized_in_this_worker=baseline=='cold')
    emit('NP_RESULT', **record)
    if not all(checks.values()):
        raise RuntimeError('NumPy worker validation failed',checks)
    return record


def _profile_outputs():
    n=PROFILE['matrix_dimension']; repetitions=PROFILE['repetitions']
    x=NP.arange(1024,dtype=NP.float64).reshape(32,32)
    a=(NP.arange(n*n,dtype=NP.float64).reshape(n,n)%31)/17
    b=(NP.arange(n*n,dtype=NP.float64).reshape(n,n)%23)/13
    repeated=NP.empty(repetitions,dtype=NP.float64)
    for i in range(repetitions):
        answer=a@b
        answer[0,0]+=i/1024
        repeated[i]=answer.sum()
    return dict(slice=x[::3,1::4].copy(),
                broadcast=(x[:4,:8]+NP.arange(8,dtype=NP.float64)).copy(),
                sums=NP.array([x.sum(),x[:,::2].sum()],dtype=NP.float64),
                matmul=answer,repeat_sums=repeated)


def execute(req):
    global LAST_MUTATION, LAST_BEFORE_FINGERPRINT
    # G0 receives this only after the original nonce-bound trusted bootstrap.
    # Z/S/W compare it to the profile captured before environment sanitization.
    bind_profile(req.get('full_profile','legacy'))
    if PROFILE is None:
        return _legacy_execute(req)
    nonce=req['nonce'];baseline=req['numpy_baseline'];level=req['numpy_level']
    if level != PROFILE['preload'] or baseline not in ('cold','hot'):
        raise RuntimeError('request profile initialization contract mismatch')
    if req.get('numpy_case','normal') not in ('normal','compute_failure'):
        raise RuntimeError('profile write mode is explicit; legacy cow_all is not admitted here')
    persistent=req.get('numpy_persistent') is True
    start=time.monotonic_ns();cpu=time.process_time_ns()
    prior_level=LEVEL;inherited_numpy=NP is not None and NUMPY_ORIGIN!=os.getpid()
    inherited_data=DATA is not None and DATA_ORIGIN!=os.getpid()
    inherited_template=ORIGIN is not None and ORIGIN!=os.getpid()
    if baseline=='cold':
        if NP is not None or ORIGIN is not None:
            raise RuntimeError('cold reference worker already initialized')
    elif ORIGIN is None or (not persistent and not inherited_template):
        raise RuntimeError('hot worker did not inherit an admitted template')
    completion=initialize('blas','W_cold' if baseline=='cold' else 'W_completion') if LEVEL!='blas' else None
    before=snapshot('W_numpy_before');before_fp=fingerprint();before_pages=page_flags()
    LAST_MUTATION=None;LAST_BEFORE_FINGERPRINT=before_fp
    compute_begin=time.monotonic_ns();compute_cpu=time.process_time_ns()
    actual=_profile_outputs()
    compute_end=time.monotonic_ns();compute_cpu_ns=time.process_time_ns()-compute_cpu
    mutation_start=time.monotonic_ns();mutation_cpu=time.process_time_ns()
    old_total=float(DATA.sum())
    address=int(DATA.__array_interface__['data'][0])
    plan=profile_spec.write_plan(PROFILE,os.sysconf('SC_PAGE_SIZE'),address)
    if plan['elements']:
        DATA.flags.writeable=True
        try:
            DATA[plan['start']::plan['step_elements']]+=1
        finally:
            DATA.flags.writeable=False
        LAST_MUTATION={k:plan[k] for k in ('start','step_elements','elements')}
    actual['state_summary']=NP.array([DATA.size,old_total,float(DATA.sum()),
                                     plan['elements'],float(DATA[0]),float(DATA[-1])],dtype=NP.float64)
    mutation_end=time.monotonic_ns();mutation_cpu_ns=time.process_time_ns()-mutation_cpu
    source=Path('/src/numpy-reference.npz')
    reference=json.loads(Path('/src/numpy-reference.json').read_text())
    if reference.get('profile')!=profile_config():
        raise RuntimeError('oracle/profile mismatch')
    with NP.load(source,allow_pickle=False) as expected:
        if set(expected.files)!=set(actual):
            raise RuntimeError('oracle/output fields mismatch')
        comparisons={k:dict(ok=bool(v.shape==expected[k].shape and NP.allclose(v,expected[k],rtol=1e-12,atol=1e-10)),
                            max_abs_error=float(NP.max(NP.abs(v-expected[k]))),shape=list(v.shape))
                     for k,v in actual.items()}
    output=Path('/work')/profile_spec.output_name(req.get('numpy_output_name'))
    NP.savez(output,**actual)
    computation_failure=None
    if req.get('numpy_case')=='compute_failure':
        try:NP.ones((2,3))@NP.ones((4,2))
        except ValueError as error:
            computation_failure=dict(type='ValueError',message=str(error),actual_operation='incompatible-shape matmul')
        else:raise AssertionError('expected shape rejection absent')
    after_pages=page_flags();after=snapshot('W_numpy_after')
    checks=dict(numerical=all(x['ok'] for x in comparisons.values()),
                single_thread=len(before['threads'])==len(after['threads'])==1,
                fds_restored=before['fds']==after['fds'],signals_unchanged=before['signals']==after['signals'],
                env_unchanged=before['environment']==after['environment'],profile_binding=reference['profile']==profile_config(),
                inherited=(inherited_template or persistent) if baseline=='hot' else not inherited_template,
                data_readonly_after=not DATA.flags.writeable,
                expected_failure=computation_failure is not None if req.get('numpy_case')=='compute_failure' else True)
    record=dict(nonce=nonce,baseline=baseline,level=level,profile=profile_config(),
                reuse_model='persistent' if persistent else 'fork' if baseline=='hot' else 'cold',
                inherited_preload=inherited_numpy,inherited_template_state=inherited_template,
                inherited_numpy=inherited_numpy,inherited_data=inherited_data,template_level=prior_level,
                completed_level=LEVEL,completion_stages=completion['preparation_stages'] if completion else [],
                initial_fingerprint=before_fp,after_cow_fingerprint=fingerprint(),
                before=before,after=after,pages_before=before_pages,pages_after=after_pages,
                requested_cow_write_bytes=plan['logical_store_bytes'],write_plan=plan,
                numerical=comparisons,reference_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                output_name=output.name,output_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                checks=checks,computation_failure=computation_failure,call_start_ns=start,
                compute_begin_ns=compute_begin,compute_end_ns=compute_end,compute_cpu_ns=compute_cpu_ns,
                mutation_begin_ns=mutation_start,mutation_end_ns=mutation_end,mutation_cpu_ns=mutation_cpu_ns,
                done_ns=time.monotonic_ns(),cpu_ns=time.process_time_ns()-cpu,
                initialized_in_this_worker=completion is not None,
                semantics='preload level changes location of initialization, never final task; mutation includes array reductions, not pure page-copy cost')
    emit('NP_RESULT',**record)
    if not all(checks.values()):raise RuntimeError('profile worker validation failed',checks)
    return record


def reset_persistent(expected_fingerprint, nonce=None):
    """Undo this fixed task's known mutation, not arbitrary application state.

    Caller must also check FD/thread/signal/environment state and include this
    synchronous work before the request completion/ACK. Failure retires W.
    """
    global LAST_MUTATION, LAST_BEFORE_FINGERPRINT
    start=time.monotonic_ns();cpu=time.process_time_ns();before=fingerprint()
    if LAST_BEFORE_FINGERPRINT is None or expected_fingerprint!=LAST_BEFORE_FINGERPRINT:
        raise RuntimeError('reset identity is not the completed fixed request')
    if LAST_MUTATION is not None:
        DATA.flags.writeable=True
        try:DATA[LAST_MUTATION['start']::LAST_MUTATION['step_elements']]-=1
        finally:DATA.flags.writeable=False
    if NP is not None and expected_fingerprint.get('geterr') is not None:
        NP.seterr(**expected_fingerprint['geterr'])
    after=fingerprint();restored=after==expected_fingerprint
    record=dict(nonce=nonce,profile=profile_config(),before=before,after=after,
                expected=expected_fingerprint,checks={'fixed_state_restored':restored},
                start_ns=start,end_ns=time.monotonic_ns(),cpu_ns=time.process_time_ns()-cpu,
                scope='only invert known fixed DATA stores and restore NumPy geterr; no generic sanitization')
    emit('NP_RESET',**record)
    if not restored:raise RuntimeError('persistent worker state could not be restored')
    LAST_MUTATION=None;LAST_BEFORE_FINGERPRINT=None
    return record
