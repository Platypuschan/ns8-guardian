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
            (base / 'imageroot').mkdir()
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
                'buildah': "from pathlib import Path\nimport sys\na=sys.argv[1:]\nif a[:2] == ['from','scratch']: print('fixture-builder')\nif a[:1] == ['add'] and a[-2:] == ['imageroot','/imageroot'] and not all(p in a for p in ['**/__pycache__', '**/*.pyc', '**/*.pyo']):\n print('Python bytecode not excluded', file=sys.stderr)\n sys.exit(1)\nif a[:1] == ['add'] and a[-2:] == ['ui/dist','/ui'] and not Path('ui/dist/rebuilt').exists():\n print('stale UI build supplied', file=sys.stderr)\n sys.exit(1)\n",
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
