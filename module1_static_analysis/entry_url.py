
import sys
import os
import json
import argparse
import subprocess
import tempfile
import shutil

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'scripts')


def run_predator_pipeline(working_dir: str, output_dir: str, target: str) -> dict:
    targets_csv = os.path.join(working_dir, 'targets.csv')
    with open(targets_csv, 'w') as f:
        f.write(target.strip() + '\n')

    os.makedirs(output_dir, exist_ok=True)

    result = subprocess.run(
        ['conda', 'run', '-n', 'autocyper', 'python', '__main__.py',
         '-w', os.path.abspath(working_dir),
         '-o', os.path.abspath(output_dir)],
        cwd=SCRIPTS_DIR,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print('[entry_url] pipeline stderr:', result.stderr[-500:], file=sys.stderr)
        raise RuntimeError(f'Predator pipeline failed (exit {result.returncode})')

    request_data_path = os.path.join(output_dir, 'request_data.json')
    if not os.path.exists(request_data_path):
        raise FileNotFoundError(f'request_data.json not found at {request_data_path}')

    with open(request_data_path) as f:
        return json.load(f)


def format_output(request_data: dict) -> dict:
    entries = []
    for key, req in request_data.get('requestsFound', {}).items():
        entry = {
            'url':            req.get('_url', ''),
            'method':         req.get('_method', 'GET'),
            'pivotal_params': req.get('_pivotal_input_set', []),
            'post_data':      req.get('_postData', ''),
        }
        entries.append(entry)

    return {
        'entries':   entries,
        'input_set': request_data.get('inputSet', []),
    }


def main():
    parser = argparse.ArgumentParser(description='VIPER entry URL identification (v1)')
    parser.add_argument('--working-dir', required=True,
                        help='Dir with nodes.csv / rels.csv / cpg_edges.csv')
    parser.add_argument('--output-dir', required=True,
                        help='Dir to write instr-info.csv / request_data.json etc.')
    parser.add_argument('--target', required=True,
                        help='CVE sink location, format: file/path.php:lineno')
    args = parser.parse_args()

    print(f'[entry_url] running Predator pipeline for target: {args.target}',
          file=sys.stderr)

    request_data = run_predator_pipeline(
        args.working_dir,
        args.output_dir,
        args.target
    )

    result = format_output(request_data)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
