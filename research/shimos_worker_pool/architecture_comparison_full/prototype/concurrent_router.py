"""Single-threaded nonce router for one Z; never starts or cleans a process.

There is exactly one reader of the real Z socket. Per-attempt private response
channels make the unchanged select()/recvmsg() protocol shape usable by a
cooperative Controller. Descriptor ownership is transferred, never borrowed
across attempts. Unexpected/retired identities fail the entire router closed.
"""
import errno
import json
import os
import select
import socket
import time
from common import recv, send
import concurrent_faults


class Endpoint:
    def __init__(self, router, nonce, client, writer, control=False):
        self.router=router;self.nonce=nonce;self.client=client;self.writer=writer
        self.control=control;self.timeout=None;self.closed=False
        self.client.setblocking(False);self.writer.settimeout(5)

    def fileno(self):return self.client.fileno()
    def settimeout(self, timeout):self.timeout=timeout
    def setblocking(self, enabled):self.timeout=None if enabled else 0.0
    def gettimeout(self):return self.timeout

    def sendmsg(self, buffers, ancdata=(), flags=0, address=None):
        if address is not None:raise ValueError('connected private channel only')
        if self.closed:raise OSError(errno.EPIPE,'retired attempt endpoint')
        raw=b''.join(buffers);message=json.loads(raw)
        op=message.get('op')
        if self.control:
            if op not in ('PING','STOP') or (op=='PING' and message.get('nonce')!=self.nonce):
                raise RuntimeError('invalid global control operation')
        elif message.get('nonce')!=self.nonce or op not in ('SPAWN','COMMIT','CANCEL','QUERY','FORGET'):
            raise RuntimeError('attempt router identity/operation mismatch')
        return self.router.forward(raw,ancdata,flags,message)

    def recvmsg(self, bufsize, ancbufsize=0, flags=0):
        deadline=None if self.timeout is None else time.monotonic()+self.timeout
        while True:
            try:return self.client.recvmsg(bufsize,ancbufsize,flags)
            except BlockingIOError:
                if self.timeout==0:raise
                if deadline is not None and time.monotonic()>=deadline:
                    raise socket.timeout('private attempt response timeout')
                self.router.pump(min(.01,max(0,deadline-time.monotonic())) if deadline else .01)

    def close(self):
        if self.closed:return
        self.closed=True;self.client.close();self.writer.close()


class Router:
    def __init__(self, real_socket, event):
        if len(os.listdir('/proc/self/task'))!=1:
            raise RuntimeError('concurrent candidate requires single-threaded R')
        self.real=real_socket;self.real.setblocking(False);self.event=event
        self.endpoints={};self.used=set();self.control=None;self.failed=None
        self.sent=0;self.received=0;self.forwarded=0
        self.test_fault=concurrent_faults.configured();self.test_injected=False

    def endpoint(self, nonce, control=False):
        if self.failed:raise RuntimeError('router already failed',self.failed)
        if nonce in self.used:raise RuntimeError('router nonce reuse')
        if control and self.control is not None:raise RuntimeError('duplicate global control endpoint')
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        result=Endpoint(self,nonce,a,b,control)
        self.endpoints[nonce]=result;self.used.add(nonce)
        if control:
            self.control=result
        return result

    def forward(self, raw, ancillary, flags, message):
        if self.failed:raise OSError(errno.EPIPE,'Z router failed')
        deadline=time.monotonic()+5
        while True:
            try:
                written=self.real.sendmsg([raw],ancillary,flags)
                if written!=len(raw):raise RuntimeError('partial seqpacket command')
                self.sent+=1
                self.event({'event':'ROUTER_TO_Z','nonce':message.get('nonce'),'operation':message.get('op'),
                            'bytes':written,'physical_socket_owner':'single Router'})
                return written
            except BlockingIOError:
                if time.monotonic()>=deadline:
                    self.fail('Z send timeout');raise socket.timeout('Z send timeout')
                self.pump(.01)
            except BaseException:
                self.fail('Z send failed');raise

    def pump(self, timeout=0):
        if self.failed:return
        if not select.select([self.real],[],[],timeout)[0]:return
        while True:
            descriptors=[]
            injected=None
            try:
                message,descriptors,_=recv(self.real)
                if (not self.test_injected and self.test_fault in ('reply_unknown_nonce','reply_retired_nonce')
                        and message.get('event')=='TRANSITION_CREATED' and descriptors):
                    retired=sorted(self.used-set(self.endpoints))
                    if self.test_fault=='reply_unknown_nonce' or retired:
                        original=message.copy()
                        if self.test_fault=='reply_retired_nonce':replacement=retired[0]
                        else:
                            replacement=os.urandom(16).hex()
                            while replacement in self.used:replacement=os.urandom(16).hex()
                        objects=[]
                        for fd in descriptors:
                            st=os.fstat(fd)
                            objects.append(dict(fd=fd,device=st.st_dev,inode=st.st_ino,
                                target=os.readlink('/proc/self/fd/'+str(fd))))
                        message=dict(message,nonce=replacement);self.test_injected=True
                        injected=dict(kind=self.test_fault,original=original,replacement_nonce=replacement,
                                      replacement_was_retired=replacement in retired,received_fd_objects=objects)
                        self.event({'event':'CONCURRENT_TEST_REPLY_NONCE_CHANGED',**injected})
                self.received+=1;nonce=message.get('nonce')
                endpoint=self.control if nonce is None and message.get('event') in ('ZYGOTE_STOP','STOP_REJECTED') else self.endpoints.get(nonce)
                if endpoint is None or endpoint.closed:
                    raise RuntimeError('unknown or retired response nonce',nonce,message.get('event'))
                send(endpoint.writer,message,descriptors);self.forwarded+=1
                self.event({'event':'ROUTER_FROM_Z','nonce':nonce,'message':message.get('event'),
                            'passed_fds':len(descriptors),'response_channel_nonce':endpoint.nonce})
            except BlockingIOError:return
            except BaseException as error:
                self.fail(repr(error));return
            finally:
                for fd in descriptors:os.close(fd)
                if injected:
                    closed=[]
                    for obj in injected['received_fd_objects']:
                        try:os.fstat(obj['fd']);closed.append(False)
                        except OSError as error:closed.append(error.errno==errno.EBADF)
                    self.event({'event':'CONCURRENT_TEST_REJECTED_REPLY_FDS_CLOSED',
                                'kind':self.test_fault,'replacement_nonce':injected['replacement_nonce'],
                                'objects':injected['received_fd_objects'],'actual_EBADF':closed,
                                'all_received_fds_closed':bool(closed) and all(closed),
                                'router_failed':self.failed})
                    if not closed or not all(closed):raise RuntimeError('fault reply FD cleanup failed')
            if not select.select([self.real],[],[],0)[0]:return

    def retire(self, nonce):
        endpoint=self.endpoints.pop(nonce)
        if select.select([endpoint.client],[],[],0)[0]:
            self.fail('unconsumed response at endpoint retirement')
            endpoint.close();raise RuntimeError('unconsumed response at endpoint retirement')
        endpoint.close()

    def fail(self, reason):
        if self.failed:return
        self.failed=reason
        self.event({'event':'ROUTER_FAILED','reason':reason})
        # Closing response writers delivers EOF; it never synthesizes a wait,
        # CANCEL_ACK, successful result or resource-release acknowledgement.
        for endpoint in self.endpoints.values():endpoint.writer.close()

    def close(self):
        for endpoint in self.endpoints.values():endpoint.close()
        self.endpoints.clear();self.control=None
        # Real Z channel belongs to the Controller, including final STOP/wait.
        self.real.settimeout(5)

    def evidence(self):
        return dict(real_Z_commands=self.sent,real_Z_responses=self.received,
                    private_response_packets=self.forwarded,failed=self.failed,
                    test_fault=self.test_fault,test_fault_injected=self.test_injected,
                    process_model='one R thread and one Z event loop; no helper process')
