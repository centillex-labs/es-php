#!/usr/bin/env python3
"""Version-suffix logic for LTS PHP releases.

Scheme::

    <upstream-version>-lts<N>        e.g. 8.1.34-lts1

Why the trailing integer: every branch here is upstream-EOL, so the base
version never changes again.  The counter is the only thing that distinguishes
two of our releases built from the same upstream tarball.  Bump
``es_revision`` in ``sources.lock.json`` for a branch whenever that branch's
patch series changes.

``PHP_VERSION_ID`` is deliberately left at the upstream release value so
integer version comparisons behave exactly as on a vanilla build.
"""

from __future__ import annotations

from pathlib import Path

SUFFIX = "-lts"


class EsVersionError(RuntimeError):
    """Raised when a tree does not match a known upstream version layout."""


def extra_version(revision: int) -> str:
    """Return the PHP_EXTRA_VERSION value, e.g. ``-lts1``."""
    if not isinstance(revision, int) or revision < 1:
        raise EsVersionError(f"revision must be a positive int, got {revision!r}")
    return f"{SUFFIX}{revision}"


def release(version: str, revision: int) -> str:
    """Return the full release string, e.g. ``8.1.34-lts1``."""
    return f"{version}{extra_version(revision)}"


def _read(path: Path) -> str:
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def _write(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def _sub_once(text: str, old: str, new: str, where: str) -> str:
    count = text.count(old)
    if count != 1:
        raise EsVersionError(
            f"{where}: expected exactly 1 occurrence of {old!r}, found {count}"
        )
    return text.replace(old, new)


# Upstream has shipped two shapes of the assignment across 5.4 .. 8.1:
#   * PHP_EXTRA_VERSION=""    (5.4 .. 7.3, a literal)
#   * PHP_EXTRA_VERSION=$4    (7.4, 8.1, split out of AC_PACKAGE_VERSION)
_CONFIGURE_PATTERNS = ('PHP_EXTRA_VERSION=""', "PHP_EXTRA_VERSION=$4")
_CONFIGURE_AC_PATTERNS = ("PHP_EXTRA_VERSION=[$]4", 'PHP_EXTRA_VERSION=""')


def inject(tree: Path, extra: str, version: str) -> dict[str, str]:
    """Rewrite a pristine PHP tree so builds report ``<version><extra>``.

    Edits the generated ``configure`` (which is what the release tarball
    actually runs), ``configure.ac`` when present, and ``main/php_version.h``
    (so the version is also correct for anyone grepping without configuring).

    Returns a mapping of file -> the upstream pattern that was replaced.
    """
    changes: dict[str, str] = {}

    configure = tree / "configure"
    text = _read(configure)
    for pattern in _CONFIGURE_PATTERNS:
        if pattern in text:
            text = _sub_once(
                text, pattern, f'PHP_EXTRA_VERSION="{extra}"', "configure"
            )
            changes["configure"] = pattern
            break
    else:
        raise EsVersionError(
            f"{configure}: no known PHP_EXTRA_VERSION assignment found"
        )
    _write(configure, text)

    configure_ac = tree / "configure.ac"
    if configure_ac.exists():
        text = _read(configure_ac)
        for pattern in _CONFIGURE_AC_PATTERNS:
            if pattern in text:
                replacement = (
                    f"PHP_EXTRA_VERSION=[{extra}]"
                    if pattern == "PHP_EXTRA_VERSION=[$]4"
                    else f'PHP_EXTRA_VERSION="{extra}"'
                )
                text = _sub_once(text, pattern, replacement, "configure.ac")
                changes["configure.ac"] = pattern
                break
        else:
            raise EsVersionError(
                f"{configure_ac}: no known PHP_EXTRA_VERSION assignment found"
            )
        _write(configure_ac, text)

    header = tree / "main" / "php_version.h"
    text = _read(header)
    text = _sub_once(
        text,
        '#define PHP_EXTRA_VERSION ""',
        f'#define PHP_EXTRA_VERSION "{extra}"',
        "main/php_version.h",
    )
    text = _sub_once(
        text,
        f'#define PHP_VERSION "{version}"',
        f'#define PHP_VERSION "{version}{extra}"',
        "main/php_version.h",
    )
    if "#define PHP_VERSION_ID " not in text:
        raise EsVersionError(f"{header}: PHP_VERSION_ID define not found")
    _write(header, text)
    changes["main/php_version.h"] = '#define PHP_EXTRA_VERSION ""'

    return changes
