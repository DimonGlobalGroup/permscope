#!/usr/bin/env python3
"""PermScope — a read-only, deterministic file-permission auditor.

Audits permission bits across one or more directory trees and reports
named findings. It never opens file contents, never follows symlinks,
and never changes anything: it reports, a human decides.
"""
import argparse
import fnmatch
import json
import os
import stat
import sys

VERSION = "1.0.0"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

KEY_PATTERNS = ("*.pem", "*.key", "id_rsa*", "id_ed25519*",
                "id_ecdsa*", "id_dsa*", "*.p12", "*.pfx")
SENSITIVE_MARKERS = ("secret", "credential", "password", ".env")


def findings_for(path, st):
    """Return a list of (rule, severity) for one stat result."""
    mode = st.st_mode
    out = []
    is_dir = stat.S_ISDIR(mode)
    is_file = stat.S_ISREG(mode)
    base = os.path.basename(path).lower()
    if is_file and mode & stat.S_ISUID:
        out.append(("setuid", "high"))
    if (is_file or is_dir) and mode & stat.S_ISGID:
        out.append(("setgid", "medium"))
    if is_file and mode & stat.S_IWOTH:
        out.append(("world-writable-file", "high"))
    if is_dir and (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
        out.append(("world-writable-dir-nosticky", "high"))
    if is_file and any(fnmatch.fnmatchcase(base, p) for p in KEY_PATTERNS):
        if stat.S_IMODE(mode) & 0o077:
            out.append(("key-material-broad", "high"))
    if is_file and any(m in base for m in SENSITIVE_MARKERS):
        if mode & stat.S_IROTH:
            out.append(("world-readable-sensitive", "medium"))
    return out


def scan(roots):
    findings = []
    dirs_scanned = 0
    files_scanned = 0
    symlinks_skipped = 0
    errors = 0
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            # Count and prune symlinked dirs; audit real dirs.
            kept = []
            for name in dirnames:
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    symlinks_skipped += 1
                else:
                    kept.append(name)
            dirnames[:] = kept
            try:
                st = os.lstat(dirpath)
            except OSError:
                errors += 1
                continue
            dirs_scanned += 1
            for rule, sev in findings_for(dirpath, st):
                findings.append({
                    "path": dirpath, "rule": rule, "severity": sev,
                    "mode": format(stat.S_IMODE(st.st_mode), "04o"),
                    "kind": "dir",
                })
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    symlinks_skipped += 1
                    continue
                try:
                    st = os.lstat(full)
                except OSError:
                    errors += 1
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                files_scanned += 1
                for rule, sev in findings_for(full, st):
                    findings.append({
                        "path": full, "rule": rule, "severity": sev,
                        "mode": format(stat.S_IMODE(st.st_mode), "04o"),
                        "kind": "file",
                    })
    findings.sort(key=lambda f: (f["path"], f["rule"]))
    return {
        "dirs_scanned": dirs_scanned,
        "files_scanned": files_scanned,
        "symlinks_skipped": symlinks_skipped,
        "errors": errors,
        "findings": findings,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="permscope",
        description="Read-only, deterministic file-permission auditor.")
    parser.add_argument("--version", action="version",
                        version=f"permscope {VERSION}")
    sub = parser.add_subparsers(dest="command")
    sp = sub.add_parser("scan", help="scan one or more directory trees")
    sp.add_argument("dirs", nargs="+", metavar="DIR")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--min-severity", choices=list(SEVERITY_ORDER),
                    default="low")
    sp.add_argument("--fail-on", choices=list(SEVERITY_ORDER) + ["never"],
                    default="high")
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help(sys.stderr)
        return 2
    for d in args.dirs:
        if not os.path.isdir(d):
            print(f"permscope: not a directory: {d}", file=sys.stderr)
            return 2
    result = scan(args.dirs)
    floor = SEVERITY_ORDER[args.min_severity]
    kept = [f for f in result["findings"]
            if SEVERITY_ORDER[f["severity"]] >= floor]
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in kept:
        counts[f["severity"]] += 1
    if args.json:
        out = dict(result)
        out["findings"] = kept
        out["counts"] = counts
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        for f in kept:
            print(f"{f['severity'].upper():6} {f['rule']} "
                  f"{f['mode']} {f['path']}")
        print(f"permscope: {result['dirs_scanned']} dirs scanned, "
              f"{result['files_scanned']} files, {len(kept)} findings "
              f"({counts['high']} high, {counts['medium']} medium, "
              f"{counts['low']} low)")
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f["severity"]] >= threshold for f in kept):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
