# Releasing

## Version scheme

```
<upstream-version>-lts<N>          e.g. 8.1.34-lts1
```

- **Base** is the pristine upstream release; it never changes, because every
  branch here is upstream-EOL.
- **`N`** is the LTS revision for that branch, stored as `es_revision` in
  `sources.lock.json`. It is the only way to distinguish two of our releases
  built from the same upstream tarball, so **bump it whenever a branch's patch
  series changes**.
- `PHP_VERSION_ID` stays at the upstream value (`8.1.34` → `80134`).

Resulting artifacts:

```
tarball        php-8.1.34-lts1.tar.gz          (top dir php-8.1.34-lts1/)
checksums      php-8.1.34-lts1.tar.gz.sha256, SHA256SUMS
git tag        v8.1.34-lts1
```

Note there is **no `es-` prefix** on any artifact.

## Cutting a release

1. Land the patch changes on `main` and confirm the mapping:

   ```sh
   python3 scripts/check-consistency.py
   python3 scripts/es-release.py --list
   ```

2. Bump `es_revision` for each affected branch in `sources.lock.json`, and
   refresh any patch SHA-256s that changed.

3. Commit, then tag the branch release and push the tag:

   ```sh
   git tag v8.1.34-lts1
   git push origin v8.1.34-lts1
   ```

4. The `release` workflow resolves the tag against `sources.lock.json`
   (failing loudly if the tag matches no release), builds **only** that
   branch's tarball, compiles and verifies it, and publishes a GitHub Release.

Branches have independent revisions, so a tag covers exactly one branch. To
rebuild everything (e.g. after a tooling change), use the `build-tarballs`
workflow manually.

## What CI guarantees

Per branch, before anything is published:

1. The upstream tarball's SHA-256 matches `sources.lock.json`.
2. The series applies cleanly with `--fuzz=0`.
3. The version suffix is injected into `configure`, `configure.ac` and
   `main/php_version.h`.
4. The tarball is extracted and **compiled from scratch**, then asserts:
   - `PHP_VERSION == <release>`
   - `PHP_EXTRA_VERSION == -lts<N>`
   - `PHP_VERSION_ID == <upstream id>`
   - `session.upload_progress.enabled == 1` (policy regression guard)
5. Every shipped patch in `lts-patches/` matches the hash in the manifest.

Only the active series is shipped: held candidates such as
`CVE-2026-115560` are never copied into a release.

## Reproducing locally

```sh
# Build all tarballs (downloads upstream into work/cache/ on first run)
python3 scripts/es-release.py --all --out dist

# Reuse an existing tarball cache
python3 scripts/es-release.py 8.1 --out dist --cache downloads

# Compile a built tarball and check the version/policy assertions
bash scripts/verify-release-tarball.sh dist/php-8.1.34-lts1.tar.gz
```

Output is deterministic given `SOURCE_DATE_EPOCH` (defaults to the git commit
date), so identical inputs produce identical archives. Note that this makes the
hash depend on the **commit**, not just the sources: commit after building and
the hash changes, so build the tarballs after the final commit and before
tagging.

Build **outside any file-syncing directory** (Dropbox, OneDrive, iCloud Drive).
A sync client unlinks and recreates files as it uploads them, so a burst of new
tarballs and sidecars makes a concurrent reader see spurious `ENOENT` -- we hit
this as `sha256sum: php-5.5.38-lts1.tar.gz.sha256: No such file or directory`
during verification, with a different file failing each run while the sidecars
were all present on disk. Building under `/tmp` avoided it entirely:

```sh
python3 scripts/es-release.py --all --out /tmp/esphp-release
bash scripts/verify-release-tarball.sh /tmp/esphp-release/php-*.tar.gz
```

## Relationship to the Docker test images

`containers/` builds **development/test** images that apply the same patch
series but report the *vanilla* upstream version string. They exist to run the
PHPT suites and the php-lab/php2shell harnesses against the patched source.
The released tarballs are the branded artifacts; the only difference between
the two is the injected version suffix.
