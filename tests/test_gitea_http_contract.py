"""Contract between Guardian's Gitea rules and the real Gitea image.

The Traefik-log rules rely on HTTP semantics of Gitea: a failed web login or
second-factor post answers 200, success 303, a rejected API/git credential 401.
Replay fixtures are hand-written, so this runs the pinned image and checks the
statuses. Needs podman and network access: RUN_GITEA_CONTRACT=1, optional
GITEA_TEST_IMAGE (default: the image pinned by ns8-gitea-reworked).
"""
import base64, hashlib, hmac, http.cookiejar, os, re, shutil, struct, subprocess
import time, unittest, urllib.error, urllib.parse, urllib.request, uuid

IMAGE = os.environ.get("GITEA_TEST_IMAGE", "docker.gitea.com/gitea:28.3.0")
PORT = 13000 + os.getpid() % 1000
PASSWORD = "Contract-Pass-12345"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def totp(secret):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    off = mac[-1] & 15
    return "%06d" % ((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10**6)


@unittest.skipUnless(os.environ.get("RUN_GITEA_CONTRACT") == "1" and shutil.which("podman"),
                     "set RUN_GITEA_CONTRACT=1 (needs podman and network)")
class GiteaHttpContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.name = "guardian-gitea-contract-" + uuid.uuid4().hex[:8]
        env = {"GITEA__security__INSTALL_LOCK": "true", "GITEA__database__DB_TYPE": "sqlite3",
               "GITEA__server__DISABLE_SSH": "true", "GITEA__server__ROOT_URL": "http://127.0.0.1:%d/" % PORT}
        args = ["podman", "run", "-d", "--name", cls.name, "-p", "127.0.0.1:%d:3000" % PORT]
        for k, v in env.items():
            args += ["-e", "%s=%s" % (k, v)]
        subprocess.run(args + [IMAGE], check=True, capture_output=True)
        for _ in range(60):
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/user/login" % PORT, timeout=2)
                break
            except OSError:
                time.sleep(2)
        subprocess.run(["podman", "exec", "-u", "git", cls.name, "gitea", "admin", "user", "create", "--admin",
                        "--username", "adm", "--password", PASSWORD, "--email", "a@example.test",
                        "--must-change-password=false"], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["podman", "rm", "-f", cls.name], capture_output=True)

    def session(self):
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)

    def call(self, op, path, data=None, headers=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (PORT, path), body, headers or {})
        try:
            r = op.open(req)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def login(self, op, password):
        self.call(op, "/user/login")
        return self.call(op, "/user/login", {"user_name": "adm", "password": password})[0]

    def test_web_login_statuses(self):
        self.assertEqual(self.login(self.session(), "wrong"), 200)
        self.assertEqual(self.login(self.session(), PASSWORD), 303)

    def test_api_and_git_credentials_are_401(self):
        op = self.session()
        bad = {"Authorization": "Basic " + base64.b64encode(b"adm:bad").decode()}
        self.assertEqual(self.call(op, "/api/v1/user")[0], 401)
        self.assertEqual(self.call(op, "/api/v1/user", headers=bad)[0], 401)
        self.assertEqual(self.call(op, "/adm/none.git/info/refs?service=git-upload-pack", headers=bad)[0], 401)

    def test_second_factor_statuses(self):
        op = self.session()
        self.assertEqual(self.login(op, PASSWORD), 303)
        secret = re.search(r"secret: ([A-Z2-7]+)", self.call(op, "/user/settings/security/two_factor/enroll")[1]).group(1)
        self.assertEqual(self.call(op, "/user/settings/security/two_factor/enroll", {"passcode": totp(secret)})[0], 303)
        op2 = self.session()
        self.assertEqual(self.login(op2, PASSWORD), 303)          # now redirects to the second step
        self.assertEqual(self.call(op2, "/user/two_factor")[0], 200)
        self.assertEqual(self.call(op2, "/user/two_factor", {"passcode": "000000"})[0], 200)
        self.assertEqual(self.call(op2, "/user/two_factor", {"passcode": totp(secret)})[0], 303)


if __name__ == "__main__":
    unittest.main()
