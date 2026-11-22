"""Redaction of logs and refusal of secret-bearing evidence keys."""
import re

REDACTED = '[REDACTED]'
FORBIDDEN_KEY = re.compile(r'(token|secret|passw|authorization|bearer|private_?key|bouncer_key|api_?key|credential)', re.I)
PATTERNS = [
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', re.S), REDACTED),
    (re.compile(r'(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+'), r'\1' + REDACTED),
    (re.compile(r'csc[0-9]\.[A-Za-z0-9_=-]{8,}'), REDACTED),
    (re.compile(r'(?i)(redis://[^:/@\s]*:)[^@\s]+(@)'), r'\1' + REDACTED + r'\2'),
    (re.compile(r'(?i)("?[A-Za-z0-9_.-]*(?:secret|passw(?:or)?d|token|api_?key|credential|_pass|_key)[A-Za-z0-9_.-]*"?\s*[:=]\s*)("[^"]*"|\'[^\']*\'|[^\s,;&}]+)'),
     lambda m: m.group(1) + REDACTED),
    (re.compile(r'(?i)(AUTH\s+)\S+'), r'\1' + REDACTED),
]


class UnsafeEvidence(ValueError):
    pass


class Sanitizer:
    def __init__(self):
        self._known = set()

    def register(self, value):
        if value and len(value) >= 6:
            self._known.add(value)

    def clean(self, text):
        for value in sorted(self._known, key=len, reverse=True):
            text = text.replace(value, REDACTED)
        for pattern, replacement in PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def evidence(self, value, _path='evidence'):
        if isinstance(value, dict):
            out = {}
            for key, item in value.items():
                if FORBIDDEN_KEY.search(str(key)):
                    raise UnsafeEvidence('secret-bearing evidence key %s.%s' % (_path, key))
                out[key] = self.evidence(item, _path + '.' + str(key))
            return out
        if isinstance(value, (list, tuple)):
            return [self.evidence(v, _path) for v in value]
        if isinstance(value, str):
            return self.clean(value)
        return value
