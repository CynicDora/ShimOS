"""G2 mixed-profile control: one-slot clean-template cache, fixed routing.

Not two simultaneously resident templates, not an adaptive scheduler. Misses
pay real STOP/wait/removal followed by new initialization. Oracles are fixed
per profile before the supervised session and mounted read-only per request.
"""
import os,json,time,hashlib,subprocess,shutil
from pathlib import Path
from run import Controller as BaseController,R,P,O,CG,dump,event
import profile_spec
import cost

DEFAULT_PROFILES=['v1:import:8:readonly:light','v1:blas:8:readonly:light']


def profiles():
    tokens=json.loads(os.environ.get('FULL_MIX_PROFILES_JSON',json.dumps(DEFAULT_PROFILES)))
    if not isinstance(tokens,list) or len(tokens)!=2 or len(set(tokens))!=2:
        raise ValueError('exactly two distinct fixed profile strings required')
    parsed=[profile_spec.parse(x) for x in tokens]
    if any(x is None for x in parsed):raise ValueError('legacy profile not admitted for mixed routing')
    # Only preload placement differs in this first experiment. Numerical task,
    # array/write/CPU/thread budgets stay the same across both request types.
    business=[{k:v for k,v in p.items() if k not in ('token','preload')} for p in parsed]
    if business[0]!=business[1]:raise ValueError('mixed preload experiment requires identical business semantics')
    return tokens,parsed


def reference_dir(index):
    if index not in (0,1):raise ValueError('profile index')
    return R/'src'/'mixed-templates'/('p'+str(index))


def prepare_references(reference_argv,reference_env,reference_identity):
    """Root VM fixture hook, before H launch; never a privileged NumPy import.

    The caller supplies the existing candidate-D cold-reference argv and the
    existing UID/GID=65534 + NNP preexec. This only repeats that same independent
    oracle with a different fixed profile into a separate fresh directory.
    """
    assert os.getuid()==0 and Path('/run/native-benchmark-lab').read_text().strip()=='private-stock-linux-benchmark-vm'
    tokens,parsed=profiles();parent=R/'src'/'mixed-templates';parent.mkdir()
    os.chown(parent,65534,65534);rows=[]
    for index,(token,profile) in enumerate(zip(tokens,parsed)):
        target=reference_dir(index);target.mkdir();os.chown(target,65534,65534)
        (target/'input').write_text('readonly-input\n')
        env=dict(reference_env);env['FULL_PROFILE']=token;env['NP_LEVEL']=profile['preload']
        argv=[*reference_argv[:-1],str(target)]
        with (O/('mixed-reference-'+str(index)+'.log')).open('wb') as out:
            subprocess.run(argv,env=env,preexec_fn=reference_identity,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=30)
        metadata=json.loads((target/'numpy-reference.json').read_text())
        assert metadata['profile']==profile
        sha=hashlib.sha256((target/'numpy-reference.npz').read_bytes()).hexdigest()
        assert metadata['sha256']==sha
        for name in ('numpy-reference.json','numpy-reference.npz'):
            shutil.copyfile(target/name,O/('mixed-reference-'+str(index)+'-'+name))
        rows.append(dict(index=index,profile=profile,argv=argv,uid=65534,nnp=1,
                         source=str(target),reference_sha256=sha,metadata=metadata))
    dump('mixed-reference-manifest.json',dict(profiles=rows,phase='common fixture before H/session clock',
         numerical_task_same=True,privileged_numpy_import=False,performance_sample=False))


class Controller(BaseController):
    def __init__(self,supervisor):
        super().__init__(supervisor)
        self.active_profile=None;self.active_reference=None;self.cache_records=[]
        self.mix_tokens,self.mix_profiles=profiles()
        for index,profile in enumerate(self.mix_profiles):
            root=reference_dir(index)
            metadata=json.loads((root/'numpy-reference.json').read_text())
            assert metadata['profile']==profile and metadata['sha256']==hashlib.sha256((root/'numpy-reference.npz').read_bytes()).hexdigest()
            assert (root/'input').read_text()=='readonly-input\n'

    def bwrap(self,work,nonce):
        argv=super().bwrap(work,nonce)
        if self.active_reference is None:raise RuntimeError('no profile-bound read-only reference')
        matches=[i for i,x in enumerate(argv) if x==str(R/'src')]
        assert len(matches)==1
        i=matches[0];assert argv[i-1]=='--ro-bind' and argv[i+1]=='/src'
        argv[i]=str(self.active_reference)
        return argv

    def plan(self):
        explicit=os.environ.get('FULL_MIX_SEQUENCE_JSON')
        n=int(os.environ.get('COST_REQUESTS','16'))
        if n<2:raise ValueError('mixed requests require at least two calls')
        pattern=os.environ.get('FULL_MIX_PATTERN','alternating')
        if explicit:
            sequence=json.loads(explicit)
            if not isinstance(sequence,list) or not sequence or any(type(x) is not int or x not in (0,1) for x in sequence):
                raise ValueError('mix sequence must be a fixed list of profile indices')
            if len(sequence)!=n:raise ValueError('explicit sequence length must equal COST_REQUESTS')
            pattern='explicit'
        elif pattern=='grouped':sequence=[0]*((n+1)//2)+[1]*(n//2)
        elif pattern=='alternating':sequence=[i%2 for i in range(n)]
        elif pattern=='skewed':sequence=[1 if i%8==7 else 0 for i in range(n)]
        else:raise ValueError('unknown fixed mixed pattern')
        if set(sequence)!={0,1}:raise ValueError('this experiment must actually use both profile types')
        return pattern,sequence

    def run(self):
        if os.environ.get('NP_BASELINE','hot')!='hot':raise ValueError('clean-template cache uses hot Z')
        if int(os.environ.get('COST_WARMUP','0')):raise ValueError('all mixed calls charged; no hidden warmup')
        if os.environ.get('ARCH_GROUP','G2')!='G2':raise ValueError('mixed candidate is G2')
        pattern,sequence=self.plan();hits=0;misses=0
        dump('mixed-case-plan.json',dict(mode='G2_MIXED',capacity=1,profiles=self.mix_profiles,
             pattern=pattern,sequence=sequence,routing='fixed; no prediction or adaptive selection',
             trace_origin='synthetic sensitivity; not natural Agent frequencies'))
        cost.record('mixed_batch_begin',force=True,requests=len(sequence),capacity=1)
        for index,profile_index in enumerate(sequence):
            cost.context('R',None,repeat=index,warmup=False);cost.record('numpy_call_begin',force=True,call_index=index)
            begin=time.monotonic_ns();old=self.active_profile;hit=self.z is not None and old==profile_index
            before_pid=self.z['pid'] if self.z else None
            if hit:hits+=1
            else:
                misses+=1
                if self.z is not None:self.stop_z()
                assert self.z is None and not (CG/'template').exists()
                self.active_profile=profile_index;self.active_reference=reference_dir(profile_index)
                os.environ['FULL_PROFILE']=self.mix_tokens[profile_index]
                os.environ['NP_LEVEL']=self.mix_profiles[profile_index]['preload']
                self.start_z()
            after_pid=self.z['pid'];row=self.domain('normal')
            record=dict(index=index,nonce=row['nonce'],profile_index=profile_index,profile=self.mix_profiles[profile_index],
                        hit=hit,previous_profile=old,previous_pid=before_pid,current_pid=after_pid,
                        start_ns=begin,complete_ns=time.monotonic_ns(),capacity=1,
                        source=str(self.active_reference),includes_eviction_and_initialization=not hit)
            if hit:assert before_pid==after_pid
            row['mixed_template_cache']=record;dump('attempt-'+row['nonce']+'.json',row);dump(str(index)+'-normal.json',row)
            self.cache_records.append(record);event({'event':'MIXED_TEMPLATE_REQUEST_COMPLETE',**record})
            cost.record('numpy_call_complete',force=True,call_index=index,cache_hit=hit,profile_index=profile_index)
        if self.z is not None:self.stop_z()
        self.reap();assert self.nochildren
        dump('mixed-cache-ledger.json',dict(capacity=1,simultaneous_templates=1,hits=hits,misses=misses,
             initialized_templates=misses,requests=self.cache_records,final_template_removed=not (CG/'template').exists(),
             routing='fixed declared sequence, not an optimization algorithm'))
        dump('summary.json',dict(all_passed=True,case=os.environ.get('RELIABILITY_CASE','performance'),
             architecture_group='G2',execution_mode='G2_MIXED',cache_capacity=1,cache_hits=hits,cache_misses=misses,
             controller_echild=True,wait_records=self.wait_records,
             rows=[{k:r.get(k) for k in ('case','nonce','outcome','business','s_state','w_state','resources','qualification','zygote_pid','mixed_template_cache')} for r in self.rows]))
        self.rpc_supervisor({'op':'DONE'});cost.context('R');cost.record('session_end',force=True)
        cost.usage('controller_final_usage');cost.memory('controller_final_memory')
