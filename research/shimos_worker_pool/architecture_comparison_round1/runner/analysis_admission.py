"""Bind presentation to an explicit final, independently verified matrix.

This helper checks report bindings, not the execution mechanisms themselves.
It never chooses a matrix by timestamp and never changes PASS/FAIL/BLOCKED.
"""
import hashlib
import json
from pathlib import Path


STUDY=Path(__file__).resolve().parents[1]


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def load_admission(path, run_paths):
    path=Path(path).resolve();path.relative_to(STUDY)
    matrix=json.loads(path.read_text())
    if matrix.get('scope')!='FINAL_PREREGISTERED_PERFORMANCE_MATRIX' or matrix.get('complete_driver') is not True:
        raise ValueError('an explicit final preregistered performance matrix is required')
    result={};reports=[]
    for block in matrix['blocks']:
        for row in block['sessions']:
            report_path=(STUDY/row['report']).resolve();report_path.relative_to(STUDY)
            if digest(report_path)!=row['sha256']:raise ValueError(('changed admission report',str(report_path)))
            report=json.loads(report_path.read_text())
            if report.get('run')!=row['session'] or report.get('status')!=row['status']:
                raise ValueError(('admission identity/status mismatch',row['session']))
            run=(STUDY/'runs'/row['session']).resolve();run.relative_to(STUDY/'runs')
            if str(run) in result:raise ValueError(('duplicate admission session',str(run)))
            result[str(run)]={'status':row['status'],'architecture_group':row['architecture_group'],
                              'block_status':block['status'],'report':row['report'],'sha256':row['sha256']}
            reports.append({'path':row['report'],'sha256':row['sha256']})
    expected={str(Path(p).resolve()) for p in run_paths}
    missing=sorted(set(result)-expected)
    if expected-set(result) or any(result[p]['status']=='PASS' for p in missing):
        raise ValueError({'missing_admission':sorted(expected-set(result)),
                          'PASS_admission_without_analysis':[p for p in missing if result[p]['status']=='PASS']})
    return result,{'path':str(path.relative_to(STUDY)),'sha256':digest(path),'scope':matrix['scope'],
                   'status':matrix['status'],'reports':reports,'qualification_recomputed':False,
                   'nonPASS_sessions_without_exported_analysis':missing}
