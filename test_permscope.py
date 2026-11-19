#!/usr/bin/env python3
"""Tests for permscope.py (stdlib unittest)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "permscope.py")
sys.path.insert(0, HERE)
import permscope  # noqa: E402


def run_cli(*argv):
    return subprocess.run([sys.executable, TOOL, *argv],
                          capture_output=True, text=True)


class PermScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        # Restore permissive modes so cleanup cannot fail on odd modes.
        for dirpath, dirnames, filenames in os.walk(self.root):
            os.chmod(dirpath, 0o755)
            for n in filenames:
                try:
                    os.chmod(os.path.join(dirpath, n), 0o644)
                except OSError:
                    pass
        self.tmp.cleanup()

    def make(self, name, mode, content=b"x"):
        path = os.path.join(self.root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(content)
        os.chmod(path, mode)
        return path

    def rules(self, result):
        return {(f["path"], f["rule"]) for f in result["findings"]}

    def test_clean_tree_no_findings(self):
        self.make("ok.txt", 0o644)
        r = permscope.scan([self.root])
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["files_scanned"], 1)

    def test_world_writable_file_high(self):
        p = self.make("loose.txt", 0o666)
        r = permscope.scan([self.root])
        self.assertIn((p, "world-writable-file"), self.rules(r))

    def test_world_writable_dir_nosticky_vs_sticky(self):
        d1 = os.path.join(self.root, "open")
        os.makedirs(d1)
        os.chmod(d1, 0o777)
        d2 = os.path.join(self.root, "sticky")
        os.makedirs(d2)
        os.chmod(d2, 0o1777)
        r = permscope.scan([self.root])
        self.assertIn((d1, "world-writable-dir-nosticky"), self.rules(r))
        self.assertNotIn((d2, "world-writable-dir-nosticky"),
                         self.rules(r))

    def test_setuid_and_setgid(self):
        p = self.make("suid.bin", 0o4755)
        q = self.make("sgid.bin", 0o2755)
        r = permscope.scan([self.root])
        self.assertIn((p, "setuid"), self.rules(r))
        self.assertIn((q, "setgid"), self.rules(r))

    def test_key_material_broad_and_tight(self):
        broad = self.make("id_ed25519", 0o644)
        tight = self.make("server.pem", 0o600)
        r = permscope.scan([self.root])
        self.assertIn((broad, "key-material-broad"), self.rules(r))
        self.assertNotIn((tight, "key-material-broad"), self.rules(r))

    def test_world_readable_sensitive(self):
        p = self.make("app.env", 0o644)
        q = self.make("notes.txt", 0o644)
        r = permscope.scan([self.root])
        self.assertIn((p, "world-readable-sensitive"), self.rules(r))
        self.assertNotIn((q, "world-readable-sensitive"), self.rules(r))

    def test_contents_never_opened(self):
        # A key-named file with undecodable content must scan fine:
        # the tool decides from name + mode only.
        p = self.make("blob.key", 0o600, content=b"\xff\xfe\x00bad")
        r = permscope.scan([self.root])
        self.assertEqual(r["errors"], 0)
        self.assertNotIn((p, "key-material-broad"), self.rules(r))

    def test_symlink_never_followed(self):
        target = self.make("real.txt", 0o666)
        link = os.path.join(self.root, "link.txt")
        os.symlink(target, link)
        r = permscope.scan([self.root])
        self.assertEqual(r["symlinks_skipped"], 1)
        paths = {f["path"] for f in r["findings"]}
        self.assertNotIn(link, paths)
        self.assertIn(target, paths)

    def test_determinism_json(self):
        self.make("a.txt", 0o666)
        self.make("b.pem", 0o640)
        a = run_cli("scan", "--json", self.root)
        b = run_cli("scan", "--json", self.root)
        self.assertEqual(a.stdout, b.stdout)
        json.loads(a.stdout)

    def test_read_only(self):
        self.make("a.txt", 0o666)
        before = sorted(os.listdir(self.root))
        run_cli("scan", self.root)
        self.assertEqual(sorted(os.listdir(self.root)), before)
        self.assertEqual(
            oct(os.stat(os.path.join(self.root, "a.txt")).st_mode & 0o7777),
            "0o666")

    def test_missing_root_exit_2_no_traceback(self):
        r = run_cli("scan", os.path.join(self.root, "nope"))
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("Traceback", r.stderr)

    def test_fail_on_thresholds(self):
        self.make("sgid.bin", 0o2755)  # medium only
        self.assertEqual(run_cli("scan", self.root).returncode, 0)
        self.assertEqual(
            run_cli("scan", "--fail-on", "medium", self.root).returncode, 1)
        self.assertEqual(
            run_cli("scan", "--fail-on", "never", self.root).returncode, 0)
        self.make("loose.txt", 0o666)  # high
        self.assertEqual(run_cli("scan", self.root).returncode, 1)

    def test_min_severity_filters(self):
        self.make("sgid.bin", 0o2755)
        r = run_cli("scan", "--json", "--min-severity", "high", self.root)
        data = json.loads(r.stdout)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["counts"], {"high": 0, "medium": 0, "low": 0})

    def test_summary_line_shape(self):
        self.make("loose.txt", 0o666)
        r = run_cli("scan", self.root)
        self.assertIn("1 findings (1 high, 0 medium, 0 low)", r.stdout)
        self.assertIn("WORLD-WRITABLE-FILE".lower().replace("-", "-"),
                      r.stdout.lower())


if __name__ == "__main__":
    unittest.main()
