from __future__ import annotations

import argparse
from dataclasses import dataclass
from email.parser import Parser
from email.policy import default
from pathlib import Path, PurePosixPath
import tarfile
from typing import Iterable, Iterator, Sequence
import zipfile

from test_hygiene_rules import is_public_text_path, scan_named_texts


BOUNDARY_MARKERS = (
    "PWA" + "_TMUX",
    "pwa" + "-tmux",
    ".claude-" + "observability-lab",
    "claude-" + "observability-lab",
    "backend." + "observability",
)

MIT_LICENSE_TEXT = """MIT License

Copyright (c) 2026 kohaku4yz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


@dataclass(frozen=True)
class AuditSummary:
    archive: str
    entries: int
    text_entries: int
    fixture_entries: int
    license_state: str


@dataclass(frozen=True)
class LicenseProfile:
    expression: str | None
    files: tuple[str, ...]
    state: str


@dataclass(frozen=True)
class SdistLayout:
    root: PurePosixPath
    metadata_name: str
    relative_names: tuple[str, ...]

    def archive_name(self, relative_name: str) -> str:
        return (self.root / PurePosixPath(relative_name)).as_posix()


@dataclass(frozen=True)
class TarMember:
    name: str
    kind: str
    linkname: str


REQUIRED_SDIST_TESTS = (
    "tests/test_collectors.py",
    "tests/test_dedupe_routing.py",
    "tests/test_fixture_hygiene.py",
    "tests/test_goldens.py",
    "tests/test_hygiene_rules.py",
)

PACKAGE_PREFIXES = (
    "claude_code_data_kit/",
    "src/claude_code_data_kit/",
)

FIXTURE_PREFIXES = tuple(
    f"{prefix}claude_code_data_kit/_fixtures/"
    for prefix in ("", "src/")
)


def _zip_entries(path: Path) -> Iterator[tuple[str, bytes]]:
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if name.endswith("/"):
                continue
            yield name, archive.read(name)


def _tar_kind(member: tarfile.TarInfo) -> str:
    if member.isfile():
        return "file"
    if member.isdir():
        return "directory"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    if member.isfifo():
        return "fifo"
    if member.ischr():
        return "character device"
    if member.isblk():
        return "block device"
    return "special"


def _tar_members(path: Path) -> tuple[TarMember, ...]:
    with tarfile.open(path, "r:gz") as archive:
        return tuple(
            TarMember(member.name, _tar_kind(member), member.linkname)
            for member in archive.getmembers()
        )


def _tar_entries(path: Path) -> Iterator[tuple[str, bytes]]:
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            yield member.name, handle.read()


def _entries(path: Path) -> tuple[tuple[str, bytes], ...]:
    if path.suffix == ".whl":
        return tuple(_zip_entries(path))
    if path.name.endswith(".tar.gz"):
        return tuple(_tar_entries(path))
    raise ValueError(f"unsupported distribution: {path}")


def _text_entries(entries: Iterable[tuple[str, bytes]]) -> tuple[tuple[str, str], ...]:
    decoded: list[tuple[str, str]] = []
    for name, payload in entries:
        if not is_public_text_path(name):
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                continue
        else:
            text = payload.decode("utf-8")
        decoded.append((name, text))
    return tuple(decoded)


def _validate_archive_names(names: Sequence[str], findings: list[str]) -> None:
    normalized: set[str] = set()
    for name in names:
        raw_parts = name.split("/")
        pure = PurePosixPath(name)
        if (
            not name
            or "\\" in name
            or pure.is_absolute()
            or any(part in {"", ".", ".."} for part in raw_parts)
            or pure.as_posix() != name
        ):
            findings.append(f"unsafe or ambiguous archive path: {name!r}")
            continue
        normalized_name = pure.as_posix()
        if normalized_name in normalized:
            findings.append(f"duplicate archive path: {normalized_name}")
        normalized.add(normalized_name)


def _validate_link_target(member: TarMember, findings: list[str]) -> None:
    target = member.linkname
    raw_parts = target.split("/")
    pure = PurePosixPath(target)
    if (
        not target
        or "\\" in target
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
        or pure.as_posix() != target
    ):
        findings.append(
            f"unsafe or ambiguous {member.kind} target for {member.name!r}: "
            f"{target!r}"
        )


def _validate_tar_members(members: Sequence[TarMember], findings: list[str]) -> None:
    for member in members:
        if member.kind in {"file", "directory"}:
            continue
        if member.kind in {"symlink", "hardlink"}:
            _validate_link_target(member, findings)
        findings.append(
            f"unsupported sdist tar member type {member.kind}: {member.name!r}"
        )


def _sdist_layout(names: Sequence[str], findings: list[str]) -> SdistLayout | None:
    primary_metadata = [
        name
        for name in names
        if len(PurePosixPath(name).parts) == 2
        and PurePosixPath(name).name == "PKG-INFO"
    ]
    if len(primary_metadata) != 1:
        pkg_info_paths = [name for name in names if PurePosixPath(name).name == "PKG-INFO"]
        if not primary_metadata and "PKG-INFO" in pkg_info_paths:
            findings.append(
                "sdist PKG-INFO must be located at <canonical-root>/PKG-INFO, "
                "not at archive root"
            )
        elif not primary_metadata and pkg_info_paths:
            findings.append(
                "sdist PKG-INFO must be a direct child of one canonical root; "
                f"found {pkg_info_paths!r}"
            )
        else:
            findings.append(
                "expected exactly one sdist <canonical-root>/PKG-INFO; "
                f"found {len(primary_metadata)}: {primary_metadata!r}"
            )
        return None

    metadata_name = primary_metadata[0]
    root = PurePosixPath(metadata_name).parent
    relative_names: list[str] = []
    outside: list[str] = []
    for name in names:
        pure = PurePosixPath(name)
        try:
            relative = pure.relative_to(root)
        except ValueError:
            outside.append(name)
            continue
        relative_names.append(relative.as_posix())

    if outside:
        findings.append(
            f"sdist entry outside canonical root {root.as_posix()!r}: {outside!r}"
        )

    unexpected_pkg_info = [
        name
        for name in names
        if PurePosixPath(name).name == "PKG-INFO"
        and name != metadata_name
        and not PurePosixPath(name).parent.name.endswith(".egg-info")
    ]
    if unexpected_pkg_info:
        findings.append(f"unexpected sdist PKG-INFO path(s): {unexpected_pkg_info!r}")

    return SdistLayout(root, metadata_name, tuple(relative_names))


def _normalized_license(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"


def _license_profile(
    path: Path,
    entries: tuple[tuple[str, bytes], ...],
    text_entries: tuple[tuple[str, str], ...],
    findings: list[str],
    sdist_layout: SdistLayout | None,
) -> LicenseProfile:
    names = [name for name, _ in entries]
    text_by_name = dict(text_entries)
    if path.suffix == ".whl":
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
    elif sdist_layout is not None:
        metadata_names = [sdist_layout.metadata_name]
    else:
        metadata_names = []
    if len(metadata_names) != 1:
        if path.suffix == ".whl":
            findings.append(
                f"expected exactly one primary metadata file; found {len(metadata_names)}"
            )
        return LicenseProfile(None, (), "invalid")

    metadata_name = metadata_names[0]
    metadata_text = text_by_name.get(metadata_name)
    if metadata_text is None:
        findings.append(f"primary metadata file is not UTF-8 text: {metadata_name}")
        return LicenseProfile(None, (), "invalid")

    metadata = Parser(policy=default).parsestr(metadata_text)
    expressions = tuple(metadata.get_all("License-Expression", []))
    expression = expressions[0].strip() if len(expressions) == 1 else None
    declared_files = tuple(metadata.get_all("License-File", []))
    legacy_licenses = tuple(
        value.strip() for value in metadata.get_all("License", []) if value.strip()
    )
    license_classifiers = tuple(
        value.strip()
        for value in metadata.get_all("Classifier", [])
        if value.strip().startswith("License ::")
    )
    license_entries = [
        name
        for name in names
        if PurePosixPath(name).name.upper().startswith("LICENSE")
    ]
    has_license_signal = bool(
        expressions
        or declared_files
        or legacy_licenses
        or license_classifiers
        or license_entries
    )
    if not has_license_signal:
        return LicenseProfile(None, (), "none")

    if not expressions:
        findings.append("license file present but License-Expression is missing")
    elif len(expressions) != 1:
        findings.append(
            "MIT distribution must declare exactly one License-Expression; "
            f"found {expressions!r}"
        )
    elif expression != "MIT":
        findings.append(f"unsupported License-Expression: {expression}")

    if legacy_licenses:
        findings.append(f"conflicting legacy License metadata present: {legacy_licenses!r}")
    conflicting_classifiers = tuple(
        value
        for value in license_classifiers
        if value != "License :: OSI Approved :: MIT License"
    )
    if conflicting_classifiers:
        findings.append(
            f"conflicting license classifier metadata present: {conflicting_classifiers!r}"
        )

    if not declared_files:
        findings.append("MIT distribution missing License-File declaration")
    elif declared_files != ("LICENSE",):
        findings.append(
            "MIT distribution must declare exactly License-File: LICENSE; "
            f"found {declared_files!r}"
        )

    if path.suffix == ".whl":
        dist_info = PurePosixPath(metadata_name).parent.as_posix()
        expected_name = f"{dist_info}/licenses/LICENSE"
    elif sdist_layout is not None:
        expected_name = sdist_layout.archive_name("LICENSE")
    else:
        expected_name = "<canonical-root>/LICENSE"

    if expected_name not in license_entries:
        findings.append(f"declared license file missing from archive: {expected_name}")
    unexpected = [name for name in license_entries if name != expected_name]
    if unexpected:
        findings.append(f"unexpected or conflicting license file(s): {unexpected!r}")
    if license_entries.count(expected_name) > 1:
        findings.append(f"multiple conflicting copies of license file: {expected_name}")

    if expected_name in license_entries:
        license_text = text_by_name.get(expected_name)
        if license_text is None:
            findings.append(f"license file is not UTF-8 text: {expected_name}")
        else:
            normalized = _normalized_license(license_text)
            if "commons clause" in normalized.lower():
                findings.append("license contains Commons Clause or an extra restriction")
            if normalized != MIT_LICENSE_TEXT:
                findings.append("license text is not the approved canonical MIT License")

    return LicenseProfile(expression, declared_files, "mit")


def audit(path: Path) -> AuditSummary:
    entries = _entries(path)
    file_names = [name for name, _ in entries]
    findings: list[str] = []

    archive_names = file_names
    if path.name.endswith(".tar.gz"):
        tar_members = _tar_members(path)
        archive_names = [member.name for member in tar_members]
        _validate_tar_members(tar_members, findings)

    _validate_archive_names(archive_names, findings)
    text_entries = _text_entries(entries)
    findings.extend(scan_named_texts(text_entries))

    for name, text in text_entries:
        for marker in BOUNDARY_MARKERS:
            if marker in text:
                findings.append(f"{name}: forbidden boundary marker: {marker}")

    sdist_layout = None
    audited_names = archive_names
    if path.name.endswith(".tar.gz"):
        sdist_layout = _sdist_layout(archive_names, findings)
        if sdist_layout is not None:
            audited_names = list(sdist_layout.relative_names)

    if any(name.startswith("backend/") for name in audited_names):
        findings.append("backend package present")
    if any("tmux" in PurePosixPath(name).name.lower() for name in archive_names):
        findings.append("tmux-named module or artifact present")
    if any(
        PurePosixPath(name).suffix.lower() in {".env", ".key", ".pem", ".p12", ".pfx"}
        for name in archive_names
    ):
        findings.append("private credential artifact extension present")

    fixture_entries = sum(
        any(name.startswith(prefix) for prefix in FIXTURE_PREFIXES)
        for name in audited_names
    )
    if fixture_entries < 5:
        findings.append("sanitized package fixture resources missing")

    if path.suffix == ".whl":
        metadata_names = [
            name for name in file_names if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) == 1:
            metadata = dict(text_entries).get(metadata_names[0])
            if metadata is not None and "Requires-Dist:" in metadata:
                findings.append("runtime dependency metadata present")
        if not any(name.endswith(".dist-info/entry_points.txt") for name in file_names):
            findings.append("console entry point metadata missing")
    elif sdist_layout is not None:
        if not any(
            any(name.startswith(prefix) for prefix in PACKAGE_PREFIXES)
            for name in sdist_layout.relative_names
        ):
            findings.append("sdist package content missing from canonical root")
        relative_names = set(sdist_layout.relative_names)
        for required in REQUIRED_SDIST_TESTS:
            if required not in relative_names:
                findings.append(f"sdist missing contract test: {required}")

    profile = _license_profile(path, entries, text_entries, findings, sdist_layout)
    if findings:
        raise AssertionError("\n".join(findings))
    return AuditSummary(
        archive=path.name,
        entries=len(entries),
        text_entries=len(text_entries),
        fixture_entries=fixture_entries,
        license_state=profile.state,
    )


def audit_distributions(paths: Sequence[Path]) -> tuple[AuditSummary, ...]:
    summaries = tuple(audit(path) for path in paths)
    states = {summary.license_state for summary in summaries}
    if len(states) > 1:
        rendered = ", ".join(
            f"{summary.archive}={summary.license_state}" for summary in summaries
        )
        raise AssertionError(f"distribution license state mismatch: {rendered}")
    return summaries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archives", nargs="+")
    args = parser.parse_args(argv)
    summaries = audit_distributions(tuple(Path(item) for item in args.archives))
    for summary in summaries:
        print(
            f"{summary.archive}: OK; entries={summary.entries}; "
            f"text_entries={summary.text_entries}; fixtures={summary.fixture_entries}; "
            f"license={summary.license_state}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
