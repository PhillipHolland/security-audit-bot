import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sab

FAKE_KEY = "AKIAFAKEFAKEFAKEFAKE"


class RedactionTests(unittest.TestCase):
    def test_strip_known_patterns_and_supplied_secret(self):
        text = f"token = '{FAKE_KEY}' and ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
        cleaned = sab.strip_secrets(text, extra=[FAKE_KEY])
        self.assertNotIn(FAKE_KEY, cleaned)
        self.assertNotIn("ghp_FAKE", cleaned)
        self.assertIn("[redacted]", cleaned)

    def test_gitleaks_fields_do_not_keep_secret_material(self):
        payload = [
            {
                "RuleID": "generic-api-key",
                "Description": f"leaked {FAKE_KEY}",
                "File": "settings.py",
                "StartLine": 2,
                "Secret": FAKE_KEY,
                "Match": f"api_key='{FAKE_KEY}'",
            }
        ]
        lead = sab.normalize_gitleaks(payload, Path("/repo"))[0]
        encoded = json.dumps(lead)
        self.assertNotIn(FAKE_KEY, encoded)
        for value in lead.values():
            if isinstance(value, str):
                self.assertNotIn(FAKE_KEY, value)

    def test_entropy_detector_ignores_hashes(self):
        self.assertTrue(sab._entropy_token("k8s9QmZ3pL2vN7xR4tY6wA1cE5bH0d"))
        self.assertFalse(sab._entropy_token("a" * 40))
        self.assertFalse(sab._entropy_token("0123456789abcdef" * 4))
        self.assertNotIn("0123456789abcdef" * 4, sab.extract_secrets("commit " + ("0123456789abcdef" * 4)))

    def test_private_key_header_is_a_secret(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----"
        found = sab.extract_secrets(text)
        self.assertTrue(any("PRIVATE KEY" in item for item in found))


if __name__ == "__main__":
    unittest.main()
