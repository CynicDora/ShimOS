"""Private-VM-only fixture install of the frozen candidate-04 bundle."""
import hashlib,json,shutil
from pathlib import Path
assert Path('/run/native-benchmark-lab').read_text().strip()=='private-stock-linux-benchmark-vm'
o=Path('/evidence');bundle=Path('/opt/shimos-glibc')
assert not bundle.exists()
shutil.copytree(o/'candidate-runtime',bundle,symlinks=True)
expected=json.loads((o/'candidate-runtime-sha.json').read_text())
assert all(hashlib.sha256((bundle/name).read_bytes()).hexdigest()==value for name,value in expected.items())
(o/'candidate-runtime-install.json').write_text(json.dumps({'location':str(bundle),'verified_sha256':expected,'inventory_is_stock_collector':True},indent=2)+'\n')
