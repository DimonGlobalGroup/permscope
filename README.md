# PermScope

A read-only, deterministic file-permission auditor in a single Python
file. PermScope walks one or more directory trees, checks permission
bits against a small set of named rules, and reports exactly what it
found — it never changes anything.

Permission drift is a silent security regression: a copied tree, an
extracted archive, or a restored backup can quietly leave key files
group-readable and shared directories world-writable. PermScope makes
that drift visible, reproducibly, so a human can decide what to fix.

## Why it's different

- **Read-only by construction.** No `--fix`, no chmod, no writes of
  any kind. It reports; you decide.
- **Name-aware, content-blind.** The key-material and sensitive-file
  rules use file *names and modes only*. File contents are never
  opened, so the auditor never becomes a secret-reading risk itself.
- **Symlink-safe.** Symlinks are counted and never followed — no
  loops, no escaping the scanned tree through a link.
- **Deterministic.** Sorted walk and sorted findings; repeated
  `--json` runs are byte-identical, so output diffs cleanly in CI
  and in code review.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| `setuid` | high | Regular file with the setuid bit |
| `setgid` | medium | File or directory with the setgid bit |
| `world-writable-file` | high | Regular file writable by others |
| `world-writable-dir-nosticky` | high | Directory writable by others without the sticky bit |
| `key-material-broad` | high | Key-like name (`*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`, `*.p12`, `*.pfx`) with any group/other permission bit |
| `world-readable-sensitive` | medium | Sensitive-named file (name contains `secret`, `credential`, `password`, or `.env`) readable by others |

One path can produce several findings, one per rule.

## Install

Nothing to install. Python 3.10+ and its standard library only.

```sh
python3 permscope.py --version
```

## Usage

```sh
python3 permscope.py scan DIR [DIR ...] [--json] \
    [--min-severity low|medium|high] \
    [--fail-on low|medium|high|never]
```

`--fail-on` defaults to `high`: the scan exits 1 when any finding is
at or above that severity. `--min-severity` filters what is reported
and counted.

### Example

A tree containing a `0644` key file named `id_ed25519`, a `0644`
`app.env`, and a `0777` directory named `shared`:

```text
$ python3 permscope.py scan /tmp/ps-demo
MEDIUM world-readable-sensitive 0644 /tmp/ps-demo/app.env
HIGH   key-material-broad 0644 /tmp/ps-demo/id_ed25519
HIGH   world-writable-dir-nosticky 0777 /tmp/ps-demo/shared
permscope: 2 dirs scanned, 3 files, 3 findings (2 high, 1 medium, 0 low)
(exit code 1, because a high finding meets the default --fail-on high)
```

## Exit codes

- `0` — scan completed; no finding at or above `--fail-on`
- `1` — at least one finding at or above `--fail-on`
- `2` — usage error or a scan root that is missing / not a directory

## Limitations

- Permission bits only: ACLs, capabilities, and mount options are
  out of scope.
- Name patterns are heuristics — a key file with an unusual name
  will not match `key-material-broad`. Treat a clean scan as "no
  findings under these rules", not as a proof of safety.
- Unreadable directories are counted in `errors` and the scan
  continues past them.

## Tests

```sh
python3 -m unittest -v
```

14 tests covering every rule, the sticky-bit exception, symlink
handling, determinism, read-only behavior, severity filtering, and
exit codes.

## License

MIT — see `LICENSE`. © 2026 Dimon Global Group.
