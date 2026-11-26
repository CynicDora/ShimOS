#!/usr/bin/env python3
"""Read JSON as data only. Never import source projects or execute recorded commands.

Conservative syntactic classification, not a shell emulator. Exact action boundaries
and raw strings survive unchanged. Ambiguous shell constructs stay visible in the
parser_warnings field rather than becoming claims about runtime processes.
"""
import argparse, ast, collections, csv, datetime, hashlib, json, re, shlex, warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parents[3]
HIST = PROJECT / 'experiments/worker_reuse_screening/sources'
EXP_COMMIT = '40f164d5b8f1d249bf95a6df8b74b577fd8e519d'
MINI_COMMIT = 'a2b0efee5fd9c1d3bc9fdfc6fe88036a2235d74d'
OH_COMMIT = 'a86275e288087bc7833bc79b0b691ed2ec223205'
ACI_INSPECT = {'open','search_file','search_dir','find_file','goto','scroll_up','scroll_down','ls','pwd','cat','sed','grep','rg','find','head','tail','wc'}
PY = re.compile(r'^(?:python(?:\d+(?:\.\d+)*)?|pypy(?:\d+)?)$')
ASSIGN = re.compile(r'^[A-Za-z_][A-Za-z_0-9]*=')

def sha(x):
    return hashlib.sha256(x if isinstance(x, bytes) else x.encode()).hexdigest()

def text(content):
    if isinstance(content, str): return content
    if isinstance(content, list): return '\n'.join(x.get('text','') for x in content if isinstance(x,dict))
    return ''

def imports(code):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore',SyntaxWarning)
            tree = ast.parse(code)
    except (SyntaxError, ValueError): return []
    names=[]
    for n in ast.walk(tree):
        if isinstance(n,ast.Import): names += [x.name.split('.')[0] for x in n.names]
        if isinstance(n,ast.ImportFrom) and n.module: names.append(n.module.split('.')[0])
    return sorted(set(names))

def remove_payloads(command):
    """Remove heredoc and SWE-ACI edit payloads from shell entry detection."""
    lines=command.splitlines(keepends=True); kept=[]; payloads=[]; i=0
    while i<len(lines):
        line=lines[i]; kept.append(line); i+=1
        if re.match(r'^\s*edit(?:\s|$)',line):
            body=[]
            while i<len(lines) and lines[i].strip()!='end_of_edit':body.append(lines[i]);i+=1
            if i<len(lines):i+=1
            payloads.append({'kind':'edit_text','header':line.strip(),'body':''.join(body)})
            continue
        matches=list(re.finditer(r'<<(-)?\s*([\'"]?)([A-Za-z_][A-Za-z_0-9]*)\2',line))
        for m in matches:
            body=[];terminator=m.group(3)
            while i<len(lines) and (lines[i].strip() if m.group(1) else lines[i].rstrip('\r\n'))!=terminator:
                body.append(lines[i]);i+=1
            if i<len(lines):i+=1
            payloads.append({'kind':'heredoc','header':line.strip(),'body':''.join(body)})
    return ''.join(kept),payloads

def shell_segments(command, depth=0):
    clean,payloads=remove_payloads(command)
    try:
        lex=shlex.shlex(clean,posix=True,punctuation_chars=';&|()<>\n')
        lex.whitespace=' \t\r';lex.whitespace_split=True;lex.commenters='#'
        ts=list(lex)
    except ValueError as e:return [],payloads,['shlex:'+str(e)]
    segments=[];current=[];warnings=[]
    for t in ts+['\n']:
        if t and all(c in ';&|()\n' for c in t):
            if current:segments.append(current);current=[]
        else:current.append(t)
    entries=[]
    for s in segments:
        while s and (ASSIGN.match(s[0]) or s[0] in {'then','do','else','!','time','command','exec'}):s=s[1:]
        if not s:continue
        if s[0] in {'for','while','if','case','function','fi','done','esac'}:
            warnings.append('compound_shell_not_evaluated');continue
        cmd=Path(s[0]).name
        if cmd=='env':
            s=s[1:]
            while s and (s[0].startswith('-') or ASSIGN.match(s[0])):s=s[1:]
            if not s:continue
            cmd=Path(s[0]).name
        if cmd=='timeout' and len(s)>2:
            s=s[1:]
            while s and s[0].startswith('-'):s=s[1:]
            s=s[1:]
            if not s:continue
            cmd=Path(s[0]).name
        if cmd in {'bash','sh','zsh'} and any(x in s[1:3] for x in ['-c','-lc']) and depth<2:
            k=next(i for i,x in enumerate(s) if x in ['-c','-lc'])
            if k+1<len(s):
                ee,pp,ww=shell_segments(s[k+1],depth+1);entries+=ee;payloads+=pp;warnings+=ww
        entries.append({'executable':cmd,'argv':s})
    return entries,payloads,sorted(set(warnings))

def classify(command, tool='bash', args=None):
    args=args or {}; signals=set();deps=[];py_targets=[]
    if tool=='str_replace_editor':
        op=args.get('command');signals.add('inspect' if op=='view' else 'edit_request')
        code=args.get('new_str',args.get('file_text',''))
        for d in imports(code):deps.append({'module':d,'context':'edited_code_only','evidence':'Candidate'})
        return {'signals':sorted(signals),'entries':[],'python_targets':[], 'dependency_candidates':deps,'parser_warnings':[]}
    if tool in {'execute_ipython_cell','IPythonRunCellAction','ipython'}:
        signals.add('ipython_cell');signals.add('python_entry')
        for d in imports(command):deps.append({'module':d,'context':'submitted_ipython_code','evidence':'Candidate'})
        return {'signals':sorted(signals),'entries':[],'python_targets':['ipython_cell'], 'dependency_candidates':deps,'parser_warnings':[]}
    entries,payloads,warnings=shell_segments(command)
    for e in entries:
        n=e['executable'];a=e['argv'][1:]
        if n in ACI_INSPECT:signals.add('inspect')
        if n in {'edit','create','apply_patch','patch','touch','mkdir','rm','mv','cp'} or (n=='sed' and any(x.startswith('-i') for x in a)):signals.add('edit_request')
        if n=='git':signals.add('git')
        if n in {'gcc','g++','clang','clang++','make','ninja','cmake','bazel'}:signals.add('build_entry')
        if n in {'pylint','ruff','flake8','mypy'}:signals.add('analysis_entry')
        if n in {'sphinx-build','cythonize'}:signals.add('build_entry')
        if n in {'pytest','py.test','tox'}:signals.add('test_entry')
        if n in {'pip','pip3','conda','apt','apt-get','npm','yarn'} and any(x in a for x in ['install','update','create']):signals.add('dependency_setup')
        if n in {'cd','source','export','conda'} or n=='.':signals.add('environment_or_cwd')
        if n in {'curl','wget','ssh','scp'}:signals.add('network_entry')
        if PY.match(n):
            signals.add('python_entry');target=None
            if '-m' in a:
                k=a.index('-m');target='module:'+a[k+1] if k+1<len(a) else 'module:missing'
                if target in {'module:pytest','module:unittest'}:signals.add('test_entry')
                if target=='module:pip' and 'install' in a:signals.add('dependency_setup')
            elif '-c' in a:
                k=a.index('-c');target='inline'
                if k+1<len(a):
                    code=a[k+1]
                    for d in imports(code):deps.append({'module':d,'context':'submitted_python_inline','evidence':'Candidate'})
                    if re.search(r'\b(?:write_text|write_bytes|write|writelines)\s*\(',code):signals.add('edit_request')
            else:
                target=next((x for x in a if x.endswith('.py')),'stdin_or_interactive')
            py_targets.append(target)
            if target and re.search(r'(?i)(?:test|reproduc|check|verify|debug)',Path(target).name):signals.add('test_or_reproducer_candidate')
        if n=='submit' or 'MICRO_SWE_AGENT_FINAL_OUTPUT' in a:signals.add('submit')
    for p in payloads:
        if p['kind']=='edit_text':signals.add('edit_request');context='edited_code_only'
        elif re.search(r'(?:^|[;&|]\s*)\s*(?:\S*/)?python[0-9.]*\b',p['header']):context='submitted_python_stdin'
        else:context='file_payload_only';signals.add('edit_request')
        for d in imports(p['body']):deps.append({'module':d,'context':context,'evidence':'Candidate'})
    # A quoted echo/cat redirection is a file write request, not a Python launch.
    if re.search(r'(?:^|\s)(?:>|>>)\s*[^&\s]',remove_payloads(command)[0]):signals.add('edit_request')
    return {'signals':sorted(signals),'entries':entries,'python_targets':py_targets,'dependency_candidates':deps,'parser_warnings':warnings}

def returncode(observation):
    patterns=[r'<returncode>(-?\d+)</returncode>',r'\[Command finished with exit code (-?\d+)\]']
    for p in patterns:
        m=re.search(p,observation)
        if m:return int(m.group(1))
    return None


# Frozen classifier derived from historical analysis; no parse_public execution.
