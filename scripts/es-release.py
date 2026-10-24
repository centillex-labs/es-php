#!/usr/bin/env python3
"""Build publishable LTS source tarballs.

Each tarball is::

    php-<release>/            e.g. php-8.1.34-lts1/
      <pristine upstream source, patch series applied, version suffixed>
      LTS-RELEASE.json        machine-readable provenance manifest
      lts-patches/            the exact patches applied, for traceability

plus a ``.sha256`` sidecar.  Outputs are deterministic given
``SOURCE_DATE_EPOCH`` (falls back to the git commit date, then a fixed value).

Usage::

    python3 scripts/es-release.py --list
    python3 scripts/es-release.py 8.1 --out dist
    python3 scripts/es-release.py --all --out dist
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import es_version  # noqa: E402

LOCK_PATH = ROOT / "sources.lock.json"
SCHEMA = "lts-php-release/1"
FALLBACK_EPOCH = 1704067200  # 2024-01-01T00:00:00Z

# Mirrors the configure line in containers/*/Dockerfile.  Recorded in the
# manifest so consumers can reproduce the exact build we test in CI.
CONFIGURE_FLAGS: dict[str, list[str]] = {
    "5.4": ["--disable-all", "--enable-cli", "--enable-fpm", "--enable-session", "--enable-json"],
    "5.5": ["--disable-all", "--enable-cli", "--enable-fpm", "--enable-session", "--enable-json", "--enable-opcache"],
    "5.6": ["--disable-all", "--enable-cli", "--enable-fpm", "--enable-session", "--enable-json", "--enable-opcache"],
    "7.0": ["--disable-all", "--enable-cli", "--enable-fpm", "--enable-session", "--enable-json", "--enable-opcache"],
    "7.1": ["--disable-all", "--enable-cli", "--enable-fpm", "--enable-session", "--enable-json", "--enable-opcache"],
    "7.2": ["--disable-all", "--enable-cli", "--enable-fpm", "--enable-session", "--enable-json", "--enable-opcache"],
    "7.3": ["--disable-all", "--enable-cli", "--enable-fpm", "--enable-session", "--enable-json", "--enable-opcache"],
    "7.4": ["--disable-all", "--enable-cli", "--enable-fpm", "--enable-session", "--enable-json", "--enable-opcache"],
    "8.1": ["--disable-all", "--enable-cli", "--enable-fpm", "--enable-session", "--enable-opcache", "--enable-zend-test"],
}


class ReleaseError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(cmd: list[str], cwd: Path | None = None, stdin=None) -> None:
    proc = subprocess.run(cmd, cwd=cwd, stdin=stdin, capture_output=True)
    if proc.returncode != 0:
        raise ReleaseError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"{proc.stdout.decode('utf-8', 'replace')}\n"
            f"{proc.stderr.decode('utf-8', 'replace')}"
        )


def source_date_epoch() -> int:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        return int(epoch)
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%ct"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if out.returncode == 0 and out.stdout.strip().isdigit():
            return int(out.stdout.strip())
    except OSError:
        pass
    return FALLBACK_EPOCH


def load_lock() -> dict:
    return json.loads(LOCK_PATH.read_text())


def ensure_upstream(entry: dict, cache: Path) -> Path:
    """Return a verified path to the pristine upstream tarball."""
    url = entry["url"]
    want = entry["sha256"]
    dest = cache / url.rsplit("/", 1)[-1]
    if dest.exists() and sha256_file(dest) == want:
        return dest
    cache.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": f"{SCHEMA} (+es-php)"})
    print(f"    downloading {url}", flush=True)
    with urllib.request.urlopen(request, timeout=180) as response, open(part, "wb") as fh:
        shutil.copyfileobj(response, fh)
    got = sha256_file(part)
    if got != want:
        part.unlink(missing_ok=True)
        raise ReleaseError(f"upstream sha256 mismatch for {url}: {got} != {want}")
    part.replace(dest)
    return dest


def apply_series(branch: str, tree: Path) -> list[str]:
    """Apply the branch patch series in order; return the applied paths."""
    patch_root = ROOT / f"php-{branch}-patches"
    series = patch_root / "series"
    if not series.is_file():
        raise ReleaseError(f"missing series file: {series}")
    applied: list[str] = []
    for raw in series.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patch = patch_root / line
        if not patch.is_file():
            raise ReleaseError(f"series references missing patch: {patch}")
        with open(patch, "rb") as fh:
            run(["patch", "--batch", "--fuzz=0", "-p1"], cwd=tree, stdin=fh)
        applied.append(line)
    if not applied:
        raise ReleaseError(f"{series}: no patches applied")
    return applied


def make_tarball(parent: Path, dirname: str, out: Path, epoch: int) -> None:
    """Deterministic tar.gz: sorted entries, zeroed ownership, pinned mtime."""
    env = dict(os.environ, LC_ALL="C")
    tar = subprocess.Popen(
        [
            "tar", "--sort=name", "--owner=0", "--group=0", "--numeric-owner",
            f"--mtime=@{epoch}", "--format=gnu", "-C", str(parent), "-cf", "-", dirname,
        ],
        stdout=subprocess.PIPE,
        env=env,
    )
    assert tar.stdout is not None
    with open(out, "wb") as fh:
        gz = subprocess.Popen(["gzip", "-9n"], stdin=tar.stdout, stdout=fh)
        tar.stdout.close()
        gz.wait()
        tar.wait()
    if tar.returncode != 0 or gz.returncode != 0:
        raise ReleaseError(f"tar/gzip failed building {out}")


def build_branch(branch: str, lock: dict, out: Path, cache: Path,
                 revision: int | None = None) -> dict:
    entry = lock["branches"][branch]
    version = entry["version"]
    rev = revision if revision is not None else int(entry.get("es_revision", 1))
    extra = es_version.extra_version(rev)
    rel = es_version.release(version, rev)

    print(f"[{branch}] release {rel}", flush=True)
    upstream = ensure_upstream(entry, cache)
    if sha256_file(upstream) != entry["sha256"]:
        raise ReleaseError(f"{upstream}: sha256 does not match sources.lock.json")

    epoch = source_date_epoch()
    with tempfile.TemporaryDirectory(prefix=f"lts-{branch}-") as tmp:
        tmpdir = Path(tmp)
        tree = tmpdir / f"php-{rel}"
        tree.mkdir()
        flag = "-xzf" if upstream.name.endswith(".gz") else "-xJf"
        run(["tar", flag, str(upstream), "-C", str(tree), "--strip-components=1"])

        applied = apply_series(branch, tree)
        changes = es_version.inject(tree, extra, version)

        # Ship only the active stack: candidate patches stay out of releases.
        shipped = tree / "lts-patches"
        shipped.mkdir()
        shutil.copy2(ROOT / f"php-{branch}-patches" / "series", shipped / "series")
        for name in applied:
            dest = shipped / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / f"php-{branch}-patches" / name, dest)

        manifest = {
            "schema": SCHEMA,
            "branch": branch,
            "base_version": version,
            "release": rel,
            "es_revision": rev,
            "php_extra_version": extra,
            "php_version_id": entry.get("version_id"),
            "upstream": {"url": entry["url"], "sha256": entry["sha256"]},
            "patches": [
                {
                    "path": name,
                    "sha256": sha256_file(ROOT / f"php-{branch}-patches" / name),
                }
                for name in applied
            ],
            "series_sha256": sha256_file(ROOT / f"php-{branch}-patches" / "series"),
            "version_edits": changes,
            "configure_flags": CONFIGURE_FLAGS[branch],
            "source_date_epoch": epoch,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)),
        }
        (tree / "LTS-RELEASE.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )

        out.mkdir(parents=True, exist_ok=True)
        tarball = out / f"php-{rel}.tar.gz"
        make_tarball(tmpdir, tree.name, tarball, epoch)
        digest = sha256_file(tarball)
        (out / f"{tarball.name}.sha256").write_text(f"{digest}  {tarball.name}\n")

    size = tarball.stat().st_size
    print(f"[{branch}] wrote {tarball.name} ({size} bytes) sha256={digest[:16]}…", flush=True)
    return manifest


def write_sums(out: Path) -> None:
    lines = []
    for tarball in sorted(out.glob("php-*.tar.gz")):
        lines.append(f"{sha256_file(tarball)}  {tarball.name}")
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def main() -> int:
    lock = load_lock()
    branches = list(lock["branches"])
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("branches", nargs="*", choices=branches,
                        help="branches to build (default: all)")
    parser.add_argument("--all", action="store_true", help="build every branch")
    parser.add_argument("--out", type=Path, default=ROOT / "dist",
                        help="output directory (default: dist/)")
    parser.add_argument("--cache", type=Path, default=ROOT / "work" / "cache",
                        help="upstream tarball cache (default: work/cache/)")
    parser.add_argument("--revision", type=int, default=None,
                        help="override the LTS revision for this build")
    parser.add_argument("--list", action="store_true",
                        help="print the version mapping and exit")
    parser.add_argument("--resolve-tag", metavar="TAG",
                        help="print the JSON branch list for a release tag")
    args = parser.parse_args()

    if args.resolve_tag:
        want = args.resolve_tag[1:] if args.resolve_tag.startswith("v") else args.resolve_tag
        matches = [
            b for b in branches
            if es_version.release(
                lock["branches"][b]["version"],
                int(lock["branches"][b].get("es_revision", 1)),
            ) == want
        ]
        if not matches:
            raise SystemExit(
                f"tag {args.resolve_tag!r} does not match any release in "
                f"sources.lock.json; expected one of: "
                + ", ".join(
                    es_version.release(
                        lock["branches"][b]["version"],
                        int(lock["branches"][b].get("es_revision", 1)),
                    )
                    for b in branches
                )
            )
        print(json.dumps(matches))
        return 0

    if args.list:
        for branch in branches:
            entry = lock["branches"][branch]
            rev = int(entry.get("es_revision", 1))
            print(f"{branch:>4}  {entry['version']:>8}  ->  "
                  f"{es_version.release(entry['version'], rev)}")
        return 0

    targets = branches if (args.all or not args.branches) else args.branches
    failures = []
    for branch in targets:
        try:
            build_branch(branch, lock, args.out, args.cache, args.revision)
        except (ReleaseError, es_version.EsVersionError) as exc:
            failures.append(branch)
            print(f"[{branch}] FAILED: {exc}", file=sys.stderr, flush=True)
    if failures:
        print(f"failed branches: {', '.join(failures)}", file=sys.stderr)
        return 1
    write_sums(args.out)
    print(f"wrote {args.out}/SHA256SUMS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
