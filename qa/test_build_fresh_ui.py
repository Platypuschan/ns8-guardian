"""Run the production packager with controlled external tool boundaries."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class FreshUIBuild(unittest.TestCase):
    def test_preexisting_dist_is_rebuilt_before_packaging(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / 'ui/dist').mkdir(parents=True)
            (base / 'ui/dist/stale').write_text('old bundle')
            (base / 'imageroot/pypkg/__pycache__').mkdir(parents=True)
            (base / 'imageroot/pypkg/module.py').write_text('# source')
            (base / 'imageroot/pypkg/__pycache__/module.pyc').write_bytes(b'old bytecode')
            (base / 'imageroot/pypkg/orphan.pyo').write_bytes(b'old bytecode')
            (base / 'sdk').mkdir()
            (base / 'sdk/report_auth.py').write_text('# fixture')
            (base / 'CATALOG_VERSION').write_text('0.2.0-rc.2\n')
            shutil.copy2(root / 'build-images.sh', base)
            tools = base / 'tools'
            tools.mkdir()
            commands = {
                'git': "import sys\nif sys.argv[1] == 'rev-parse': print('a' * 40)\n",
                'node': "print('4.18.0')\n",
                'npm': "from pathlib import Path\nimport os,sys\nwith open(os.environ['BUILD_COMMAND_LOG'],'a') as f: f.write(' '.join(sys.argv[1:])+'\\n')\nif sys.argv[-1] == 'build': Path('dist/rebuilt').write_text('fresh')\n",
                'buildah': "from pathlib import Path\nimport sys,tarfile\na=sys.argv[1:]\nif a[:2] == ['from','scratch']: print('fixture-builder')\nif a[:1] == ['add'] and a[-1] == '/imageroot':\n if '--exclude' in a or not tarfile.is_tarfile(a[-2]):\n  print('portable filtered archive required',file=sys.stderr); sys.exit(1)\n with tarfile.open(a[-2]) as archive: names=archive.getnames()\n assert './pypkg/module.py' in names\n assert not any('__pycache__' in n or n.endswith(('.pyc','.pyo')) for n in names)\nif a[:1] == ['add'] and a[-2:] == ['ui/dist','/ui'] and not Path('ui/dist/rebuilt').exists():\n print('stale UI build supplied',file=sys.stderr); sys.exit(1)\n",
            }
            for name, body in commands.items():
                script = tools / name
                script.write_text('#!' + sys.executable + '\n' + body)
                script.chmod(0o755)
            log = base / 'commands'
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                       CROWDSEC_IMAGE='localhost/fixture-engine:unchanged',
                       REPOBASE='localhost/fixture', BUILD_COMMAND_LOG=str(log))
            result = subprocess.run(['bash', 'build-images.sh'], cwd=base, env=env,
                                    text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = log.read_text().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertIn('--package=@yarnpkg/cli-dist@4.18.0 -- yarn install --immutable', lines[0])
            self.assertIn('--package=@yarnpkg/cli-dist@4.18.0 -- yarn build', lines[1])
            self.assertEqual((base / 'ui/dist/rebuilt').read_text(), 'fresh')


if __name__ == '__main__':
    unittest.main()
