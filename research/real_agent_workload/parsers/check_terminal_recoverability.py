#!/usr/bin/env python3
"""Check frozen third-party TB2 exports; never evaluate RSC or execute actions."""
import csv
import hashlib
import json
import re
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'trajectories/terminal_recoverability'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def walk(value, pointer=''):
    if isinstance(value, str) and re.fullmatch(r'\$[0-9a-fA-F]+', value):
        yield pointer, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, pointer + '/' + key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, pointer + '/' + str(index))


def keys(value):
    if isinstance(value, dict):
        yield from value
        for child in value.values():
            yield from keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from keys(child)


def main():
    OUT.mkdir(exist_ok=True)
    rows, refs = [], []
    for path in sorted((ROOT / 'trajectories/raw/terminal').rglob('*.json')):
        data = json.loads(path.read_text())
        rr = list(walk(data))
        kk = set(keys(data))
        bindings = [token for _, token in rr if token[1:] in kk]
        rows.append({'task_id': data['task_name'], 'trial_id': data['trial_id'],
                     'agent': data['agent_name'], 'model': data['model'],
                     'path': str(path.relative_to(ROOT)), 'sha256': sha(path),
                     'reference_shaped_fields': len(rr), 'same_json_matching_keys': len(bindings),
                     'contains_original_response_payload': False,
                     'recoverability': 'UNKNOWN: RSC target text not in exported ATIF object; not admitted as complete transcript'})
        refs.extend({'trial_id': data['trial_id'], 'task_id': data['task_name'], 'pointer': pointer,
                     'unresolved_token': token, 'original_field_available': False} for pointer, token in rr)
    archive = ROOT / 'sources/trajectory_corpus/terminal-thirdparty-v0.1.tar.gz'
    with tarfile.open(archive) as tf:
        names = tf.getnames()
    raw_payloads = [name for name in names if name.endswith(('.html', '.rsc', '.txt'))]
    official = OUT / 'official-tb2-hub.html'
    old_receipt = ROOT / 'sources/trajectory_corpus/terminal-original-trial-check.html.receipt.json'
    metadata = {'export_count': len(rows), 'exports_with_unresolved_reference_shapes': sum(bool(x['reference_shaped_fields']) for x in rows),
                'reference_shaped_fields': len(refs), 'same_JSON_key_matches': sum(x['same_json_matching_keys'] for x in rows),
                'archive_sha256': sha(archive), 'archive_members': len(names), 'original_response_payload_files': raw_payloads,
                'previous_official_trial_attempt': json.loads(old_receipt.read_text()),
                'current_explicit_TB2_hub': {'path': str(official.relative_to(ROOT)), 'sha256': sha(official),
                    'trial_occurrences_in_HTML': official.read_text().count('trial'),
                    'contains_ATIF_schema_version': 'schema_version' in official.read_text()},
                'main_corpus_122_modified': False,
                'conclusion': 'No complete same-response RSC binding table recovered. Official old trial redirects; current TB2 hub page contains no actual trial payload. Keep all40 outside primary corpus.',
                'no_authentication_or_model_calls': True, 'no_oracle_substitution': True,
                'scope': 'bounded read-only source and export diagnosis; not proof that official full trajectories do not exist elsewhere'}
    (OUT / 'summary.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2)+'\n')
    (OUT / 'exports.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2)+'\n')
    (OUT / 'unresolved-fields.json').write_text(json.dumps(refs, ensure_ascii=False, indent=2)+'\n')
    with (OUT / 'exports.csv').open('w', newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    example = next((x for x in refs if '/observation/' in x['pointer']), refs[0])
    report = f'''# Terminal-Bench 2.0补充轨迹恢复检查

结论：当前40份第三方镜像仍不具备完整轨迹资格，没有修改冻结的122条主样本。它们共有{len(refs)}个RSC引用形状字段，同一JSON里没有对应ID键；release的{len(names)}个成员没有HTML、RSC或原始response文本，所以不能仅凭镜像恢复被引用的内容。

具体例子：task `{example['task_id']}`、trial `{example['trial_id']}` 的 `{example['pointer']}` 只保存了 `{example['unresolved_token']}`。它不是可直接当作工具输出的完整文本。本检查保留字段指针，不把缺失内容当动作、不用模型猜补，也不把其他试次中相同编号当绑定值。RSC引用属于各自响应，跨文件拼接不成立。

第三方scraper的`extract_trajectory()`只从一个Next.js script字符串截取`trajectory`对象，未解析完整响应的引用表，也没有保存原HTML。这给出了缺失的具体来源。冻结源码见`../../sources/trajectory_corpus/terminal-scraper-source.py`，其内容仅读取，未执行。

原tbench trial URL实际HTTP200但最终重定向到首页，收据已保留。2026-10-20再次读取明确的[官方TB2页面](https://hub.harborframework.com/datasets/terminal-bench/terminal-bench-2/latest?leaderboard=2-0&tab=leaderboard)，返回loading页面，不含trial或ATIF payload；不能改用latest其他版本的排行榜假装恢复TB2。

另只读检查Harbor冻结commit `96ff9c6db90cc015f0fc0987d896670c9c5f1fad`：`src/harbor/hub/client.py`的`get_trial_detail()`调用经认证客户端的RPC；`src/harbor/download/downloader.py`的`download_trial()`先查trial及archive_path，无archive_path会明确拒绝。没有尝试登录、读取本地密钥或调用需要新授权的API；旧trial ID是否已迁移、是否存在合法公开archive仍为UNKNOWN，不能把代码支持下载当作已取得数据。

可复现入口：`python3 research/real_agent_workload/parsers/check_terminal_recoverability.py`。原字段、导出身份及HTTP收据分别见`unresolved-fields.json`、`exports.csv`、`summary.json`。如果以后取得相同trial的官方完整response或ATIF，应另建补充语料核对任务、Agent、模型、试次及真实工具观察，再决定纳入；当前不据残缺文本增加自然样本量。
'''
    (OUT/'README.md').write_text(report)
    print(json.dumps({k:metadata[k] for k in ['export_count','reference_shaped_fields','same_JSON_key_matches','original_response_payload_files']},ensure_ascii=False))


if __name__ == '__main__':
    main()
