#!/usr/bin/env python3
"""Read public metadata without printing configuration values or running actions."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]


def main():
    bias, credentials = [], []
    for path in sorted((ROOT / 'trajectories/raw/pro').glob('*.traj')):
        data = json.loads(path.read_text())
        config = json.loads(data['replay_config'])
        agent = config['agent']
        templates = agent.get('templates', {})
        instance = templates.get('instance_template', '')
        model = agent['model']
        key = model.get('api_key')
        masked = key in (None, '') or (isinstance(key, str) and bool(key) and set(key) == {'*'})
        credentials.append({
            'path': str(path.relative_to(PROJECT)),
            'api_key_field_present': 'api_key' in model,
            'credential_value_masked_or_empty': masked,
        })
        # Do not include key values, even when rejecting a newly changed source.
        if not masked:
            raise RuntimeError('Unmasked explicit credential field; do not publish or log source content')
        bias.append({
            'task_id': path.stem,
            'python_repo_prompt': 'python code repository' in instance.lower(),
            'python_reproducer_prompt': 'python <filename.py>' in instance,
            'deployment': config['env']['deployment']['type'],
            'swe_agent_hash': data['info'].get('swe_agent_hash'),
        })
    (ROOT / 'workload_analysis/pro-scaffold-bias.json').write_text(
        json.dumps(bias, ensure_ascii=False, indent=2) + '\n')
    (ROOT / 'sources/trajectory_corpus/credential-field-audit.json').write_text(
        json.dumps({
            'scope': 'public replay_config explicit api_key field only; values never logged; not full arbitrary-secret detector',
            'results': credentials,
        }, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'Pro_runs_audited': len(bias),
                      'python_repository_prompt': sum(x['python_repo_prompt'] for x in bias),
                      'python_reproducer_prompt': sum(x['python_reproducer_prompt'] for x in bias),
                      'explicit_keys_masked_or_empty': all(x['credential_value_masked_or_empty'] for x in credentials)}))


if __name__ == '__main__':
    main()
