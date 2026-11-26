#!/usr/bin/env python3
"""Use the actual historical pure-Python oracle, without spawning a workload."""
import json,sys
sys.dont_write_bytecode=True
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'research/shimos_worker_pool/experiments/workers'
sys.path.insert(0,str(p))
import client,protocol
request=protocol.requests('numpy',1)[0]
expected=client.numpy_oracle(request['input'])
print(json.dumps({'scope':'request/oracle inspection only; no Worker or sandbox started',
                  'request':request,'expected':expected},indent=2))
