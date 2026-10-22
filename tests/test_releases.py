import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sab

GITLEAKS = [
    "gitleaks_8.30.1_checksums.txt",
    "gitleaks_8.30.1_darwin_arm64.tar.gz",
    "gitleaks_8.30.1_darwin_x64.tar.gz",
    "gitleaks_8.30.1_linux_arm64.tar.gz",
    "gitleaks_8.30.1_linux_x64.tar.gz",
]
OSV = [
    "osv-scanner_darwin_amd64",
    "osv-scanner_darwin_arm64",
    "osv-scanner_linux_amd64",
    "osv-scanner_linux_arm64",
    "osv-scanner_SHA256SUMS",
]
TRIVY = [
    "trivy_0.76.1_checksums.txt",
    "trivy_0.76.1_checksums.txt.sigstore.json",
    "trivy_0.76.1_Linux-64bit.tar.gz",
    "trivy_0.76.1_Linux-ARM64.tar.gz",
    "trivy_0.76.1_macOS-ARM64.tar.gz",
    "trivy_0.76.1_macOS-64bit.tar.gz",
]


class ReleaseAssetTests(unittest.TestCase):
    def test_asset_selection(self):
        self.assertEqual(sab.choose_gitleaks_asset(GITLEAKS, "linux", "x64"), "gitleaks_8.30.1_linux_x64.tar.gz")
        self.assertEqual(sab.choose_gitleaks_asset(GITLEAKS, "darwin", "arm64"), "gitleaks_8.30.1_darwin_arm64.tar.gz")
        self.assertEqual(sab.choose_osv_asset(OSV, "linux", "arm64"), "osv-scanner_linux_arm64")
        self.assertEqual(sab.choose_osv_asset(OSV, "darwin", "x64"), "osv-scanner_darwin_amd64")
        self.assertEqual(sab.choose_trivy_asset(TRIVY, "linux", "x64"), "trivy_0.76.1_Linux-64bit.tar.gz")
        self.assertEqual(sab.choose_trivy_asset(TRIVY, "darwin", "arm64"), "trivy_0.76.1_macOS-ARM64.tar.gz")
        self.assertEqual(sab.choose_checksum_asset(GITLEAKS), "gitleaks_8.30.1_checksums.txt")
        self.assertEqual(sab.choose_checksum_asset(OSV), "osv-scanner_SHA256SUMS")
        self.assertEqual(sab.choose_checksum_asset(TRIVY), "trivy_0.76.1_checksums.txt")

    def test_checksum_lookup_and_digest(self):
        text = "\n".join(
            [
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  other.bin",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  gitleaks_8.30.1_linux_x64.tar.gz",
            ]
        )
        self.assertEqual(
            sab.lookup_checksum(text, "gitleaks_8.30.1_linux_x64.tar.gz"),
            "b" * 64,
        )
        self.assertIsNone(sab.lookup_checksum(text, "missing.bin"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blob"
            path.write_bytes(b"abc")
            digest = hashlib.sha256(b"abc").hexdigest()
            self.assertEqual(sab.sha256_file(path), digest)
            self.assertNotEqual(sab.sha256_file(path), "b" * 64)


if __name__ == "__main__":
    unittest.main()
