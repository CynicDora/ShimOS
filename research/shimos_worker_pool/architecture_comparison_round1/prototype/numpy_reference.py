"""Cold Python numerical reference, private VM only, no inherited Python state."""
import os, sys, json, time, hashlib
from pathlib import Path
assert Path('/run/native-benchmark-lab').read_text().strip()=='private-stock-linux-benchmark-vm'
assert os.getuid()==65534, 'never import candidate dependency as root'
import numpy_workload as task
started=time.monotonic_ns()
task.initialize('import','cold_reference')
values=task.outputs()
target=Path(sys.argv[1]);target.mkdir(exist_ok=True)
task.NP.savez(target/'numpy-reference.npz',**values)
record={'event':'NP_COLD_REFERENCE','pid':os.getpid(),'python':sys.version,
        'numpy':task.NP.__version__,'started_ns':started,'finished_ns':time.monotonic_ns(),
        'sha256':hashlib.sha256((target/'numpy-reference.npz').read_bytes()).hexdigest(),
        'rtol':1e-12,'atol':1e-10,'shapes':{k:list(v.shape) for k,v in values.items()},
        'snapshot':task.snapshot('cold_reference_computed')}
(target/'numpy-reference.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record),flush=True)
