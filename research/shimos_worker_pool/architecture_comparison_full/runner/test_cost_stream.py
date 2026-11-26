#!/usr/bin/env python3
"""Small host-side diagnostic-buffer unit checks; no VM/isolation test claim."""
import importlib.util
import json
import os
from pathlib import Path
import types


def load(name):
    path=Path(__file__).resolve().parents[1]/'prototype/cost.py'
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    chunks=[];pid=[1234]
    module.os=types.SimpleNamespace(getpid=lambda:pid[0],write=lambda fd,data:(chunks.append(bytes(data)) or len(data)))
    module.context('Z','attempt-a')
    return module,chunks,pid


def decode(chunks):
    return [json.loads(line) for line in b''.join(chunks).splitlines()]


def main():
    c,chunks,pid=load('stream_test_enabled');c.ENABLED=True
    for i in range(1000):c.record('probe',value=i)
    assert len(c.ROWS)+len(c.WAIT_AGGREGATES)<128
    c.flush();rows=decode(chunks)
    assert [r['value'] for r in rows if r['name']=='probe']==list(range(1000))
    assert len({(r['pid'],r['seq']) for r in rows})==len(rows)
    assert all(r['max_buffered_rows']<=128 for r in rows if r['name']=='diagnostic_stream_flush')
    for i in range(300):
        c.context('Z','attempt-'+str(i));c.finish('waitpid_poll',c.mark(),waited_pid=0)
    c.flush();rows=decode(chunks)
    assert sum(r['count'] for r in rows if r['name']=='waitpid_poll')==300
    c.record('parent_only');pid[0]=4321;c.record('child_only');c.flush();rows=decode(chunks)
    assert not any(r['pid']==4321 and r['name']=='parent_only' for r in rows)
    child=[r for r in rows if r['pid']==4321]
    assert child[0]['name']=='child_only' and child[0]['seq']==0
    # Parent's COW buffer is not emitted by child. This is a simulated PID
    # switch, not a runtime/fork-safety qualification.
    c,chunks,pid=load('stream_test_disabled');c.ENABLED=False
    for i in range(300):c.record('forced',force=True,value=i);c.record('disabled')
    c.flush();rows=decode(chunks)
    assert len(rows)==300 and [r['value'] for r in rows]==list(range(300))
    c,chunks,pid=load('stream_test_error');c.ENABLED=True
    good_write=c.os.write
    c.os.write=lambda fd,data:(_ for _ in ()).throw(BrokenPipeError('injected'))
    for i in range(600):c.record('probe',value=i)
    assert len(c.ROWS)+len(c.WAIT_AGGREGATES)<128 and c.STREAM_UNCONFIRMED_RECORDS>0
    c.os.write=good_write;c.flush();rows=decode(chunks)
    assert any(r['kind']=='measurement_error' and r['unconfirmed_records']>0 for r in rows)
    print(json.dumps(dict(status='PASS',scope='diagnostic buffer only; simulated write/PID, no security or runtime qualification',
                         checks=['bounded_records','bounded_wait_keys','no_duplicate_sequence','fork_buffer_identity_reset',
                                 'disabled_forced_records','broken_stdout_bounded_and_reported'])))


if __name__=='__main__':main()
