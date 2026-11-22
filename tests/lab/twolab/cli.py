"""Command line: run | preflight | cleanup. No option can weaken a safety property (there is no skip/insecure flag)."""
import argparse
import json
import os
import re
import sys
from pathlib import Path

from .capacity import CapacityError, check_capacity
from .config import ConfigError, parse_inputs
from .lab import Lab, real_hostinfo
from .resources import Ledger, Names
from .vm import kill_owned_qemu

RUN_ID = re.compile(r'[0-9a-f]{8}')


def safe_out(value):
    path = Path(value or '')
    if not value or path.is_absolute() or '..' in path.parts:
        raise argparse.ArgumentTypeError('output directory must be a relative path without ..')
    return value


def build_parser():
    p = argparse.ArgumentParser(prog='twolab', description='Guardian two-VM NS8 acceptance lab')
    sub = p.add_subparsers(dest='command', required=True)
    run = sub.add_parser('run')
    run.add_argument('--out', type=safe_out, default='lab-out')
    sub.add_parser('preflight')
    clean = sub.add_parser('cleanup', help='release the resources of a crashed run, from its ledger')
    clean.add_argument('--run-id', required=True)
    clean.add_argument('--workdir', required=True)
    return p


def main(argv=None, env=None):
    env = dict(os.environ if env is None else env)
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exit_:
        raise SystemExit(2 if exit_.code else 0)
    if args.command == 'run':
        out = Path(env.get('LAB_ROOT', '.')) / args.out
        try:
            parse_inputs(env)
        except ConfigError as error:
            print('invalid input: %s' % error, file=sys.stderr)
            return 1
        lab = Lab(env=env, out_dir=str(out), repo_root=env.get('LAB_REPO', '.'), workbase=env.get('RUNNER_TEMP'))
        return lab.run()
    if args.command == 'preflight':
        try:
            cfg = parse_inputs(env)
            info = json.loads(env['LAB_FAKE_HOST']) if env.get('LAB_FAKE_HOST') else real_hostinfo()
            if info.get('disk_free_bytes') is None:
                import shutil
                info['disk_free_bytes'] = shutil.disk_usage(env.get('RUNNER_TEMP') or '/tmp').free
            print(json.dumps(check_capacity(info['meminfo_text'], info['disk_free_bytes'], info['cpus'], info['kvm'], cfg), indent=2))
            return 0
        except (CapacityError, ConfigError) as error:
            print('preflight failed: %s' % error)
            return 1
    if args.command == 'cleanup':
        if not RUN_ID.fullmatch(args.run_id) or ('gl-' + args.run_id) != Path(args.workdir).name:
            print('workdir must be .../gl-<run-id>', file=sys.stderr)
            return 2
        names = Names(args.run_id, args.workdir)
        if not Path(args.workdir, 'ledger.json').exists():
            print('no ledger: nothing owned to clean', file=sys.stderr)
            return 2
        try:
            ledger = Ledger.load(names)
        except (OSError, ValueError, RuntimeError) as error:
            print('refusing invalid ownership ledger: %s' % error, file=sys.stderr)
            return 2

        def runner(argv):
            if argv and argv[0] == '@kill-qemu':
                return kill_owned_qemu(argv[1], argv[2])
            import subprocess
            done = subprocess.run(argv, capture_output=True, text=True, timeout=120)
            return done.returncode, done.stdout
        failures = ledger.cleanup(runner)
        print(json.dumps({'registered': len(ledger.entries), 'failures': failures}))
        return 1 if failures else 0
    return 2


if __name__ == '__main__':
    sys.exit(main())
