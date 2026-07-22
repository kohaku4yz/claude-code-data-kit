from __future__ import annotations

import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from distribution_audit import MIT_LICENSE_TEXT, audit, audit_distributions


BASE_METADATA = """Metadata-Version: 2.4
Name: claude-code-data-kit
Version: 0.1.0
Summary: Synthetic distribution audit fixture

Synthetic body.
"""
MIT_METADATA = """Metadata-Version: 2.4
Name: claude-code-data-kit
Version: 0.1.0
Summary: Synthetic distribution audit fixture
License-Expression: MIT
License-File: LICENSE

Synthetic body.
"""
REQUIRED_SDIST_TESTS = (
    "tests/test_collectors.py",
    "tests/test_dedupe_routing.py",
    "tests/test_fixture_hygiene.py",
    "tests/test_goldens.py",
    "tests/test_hygiene_rules.py",
)
SDIST_ROOT = "claude_code_data_kit-0.1.0/"


def _fixture_entries(prefix: str = "") -> dict[str, str]:
    return {
        f"{prefix}claude_code_data_kit/_fixtures/fixture_{index}.json": "{}\n"
        for index in range(5)
    }


def _write_wheel(
    path: Path,
    *,
    metadata: str = BASE_METADATA,
    license_text: str | None = None,
    extra: dict[str, str] | None = None,
) -> None:
    dist_info = "claude_code_data_kit-0.1.0.dist-info"
    entries = _fixture_entries()
    entries[f"{dist_info}/METADATA"] = metadata
    entries[f"{dist_info}/entry_points.txt"] = (
        "[console_scripts]\nclaude-code-data-kit-lab = synthetic:main\n"
    )
    if license_text is not None:
        entries[f"{dist_info}/licenses/LICENSE"] = license_text
    entries.update(extra or {})
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in entries.items():
            archive.writestr(name, text)


def _sdist_entries(
    *,
    root: str = SDIST_ROOT,
    metadata: str = BASE_METADATA,
    license_text: str | None = None,
) -> dict[str, str]:
    entries = _fixture_entries(root)
    entries[f"{root}PKG-INFO"] = metadata
    for required in REQUIRED_SDIST_TESTS:
        entries[f"{root}{required}"] = "# synthetic contract test\n"
    if license_text is not None:
        entries[f"{root}LICENSE"] = license_text
    return entries


def _tar_member(
    name: str,
    member_type: bytes,
    *,
    linkname: str = "",
) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.type = member_type
    member.linkname = linkname
    return member


def _write_tar(
    path: Path,
    entries: dict[str, str],
    *,
    extra_members: tuple[tarfile.TarInfo, ...] = (),
) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, text in entries.items():
            payload = text.encode("utf-8")
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        for member in extra_members:
            archive.addfile(member)


def _write_sdist(
    path: Path,
    *,
    metadata: str = BASE_METADATA,
    license_text: str | None = None,
    extra: dict[str, str] | None = None,
) -> None:
    entries = _sdist_entries(metadata=metadata, license_text=license_text)
    entries.update(extra or {})
    _write_tar(path, entries)


class DistributionLicenseAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_no_license_baseline_archives_pass(self) -> None:
        wheel = self.root / "baseline.whl"
        sdist = self.root / "baseline.tar.gz"
        _write_wheel(wheel)
        _write_sdist(sdist)
        summaries = audit_distributions((wheel, sdist))
        self.assertEqual([item.license_state for item in summaries], ["none", "none"])

    def test_canonical_mit_wheel_passes(self) -> None:
        wheel = self.root / "mit.whl"
        _write_wheel(wheel, metadata=MIT_METADATA, license_text=MIT_LICENSE_TEXT)
        self.assertEqual(audit(wheel).license_state, "mit")

    def test_canonical_single_root_mit_sdist_passes(self) -> None:
        sdist = self.root / "mit.tar.gz"
        _write_sdist(sdist, metadata=MIT_METADATA, license_text=MIT_LICENSE_TEXT)
        self.assertEqual(audit(sdist).license_state, "mit")

    def test_license_from_second_top_level_root_is_rejected(self) -> None:
        sdist = self.root / "wrong-sdist-root.tar.gz"
        entries = _sdist_entries(metadata=MIT_METADATA)
        entries["unrelated-root/LICENSE"] = MIT_LICENSE_TEXT
        _write_tar(sdist, entries)
        with self.assertRaisesRegex(
            AssertionError,
            "outside canonical root.*unrelated-root/LICENSE",
        ):
            audit(sdist)

    def test_root_level_license_cannot_pair_with_project_pkg_info(self) -> None:
        sdist = self.root / "root-license.tar.gz"
        entries = _sdist_entries(metadata=MIT_METADATA)
        entries["LICENSE"] = MIT_LICENSE_TEXT
        _write_tar(sdist, entries)
        with self.assertRaisesRegex(
            AssertionError,
            "outside canonical root.*LICENSE",
        ):
            audit(sdist)

    def test_canonical_license_plus_second_root_license_is_rejected(self) -> None:
        sdist = self.root / "extra-license-root.tar.gz"
        entries = _sdist_entries(metadata=MIT_METADATA, license_text=MIT_LICENSE_TEXT)
        entries["unrelated-root/LICENSE"] = MIT_LICENSE_TEXT
        _write_tar(sdist, entries)
        with self.assertRaisesRegex(
            AssertionError,
            "outside canonical root.*unrelated-root/LICENSE",
        ):
            audit(sdist)

    def test_multiple_primary_pkg_info_roots_are_rejected(self) -> None:
        sdist = self.root / "multiple-pkg-info.tar.gz"
        entries = _sdist_entries(metadata=MIT_METADATA, license_text=MIT_LICENSE_TEXT)
        entries["second-root/PKG-INFO"] = MIT_METADATA
        _write_tar(sdist, entries)
        with self.assertRaisesRegex(
            AssertionError,
            "exactly one sdist <canonical-root>/PKG-INFO",
        ):
            audit(sdist)

    def test_second_distribution_root_content_is_rejected(self) -> None:
        sdist = self.root / "multiple-roots.tar.gz"
        entries = _sdist_entries(metadata=MIT_METADATA, license_text=MIT_LICENSE_TEXT)
        entries["second-root/claude_code_data_kit/_fixtures/fixture_0.json"] = "{}\n"
        _write_tar(sdist, entries)
        with self.assertRaisesRegex(
            AssertionError,
            "outside canonical root.*second-root",
        ):
            audit(sdist)

    def test_pkg_info_at_archive_root_is_rejected(self) -> None:
        sdist = self.root / "root-pkg-info.tar.gz"
        entries = _fixture_entries(SDIST_ROOT)
        entries["PKG-INFO"] = MIT_METADATA
        for required in REQUIRED_SDIST_TESTS:
            entries[f"{SDIST_ROOT}{required}"] = "# synthetic contract test\n"
        entries[f"{SDIST_ROOT}LICENSE"] = MIT_LICENSE_TEXT
        _write_tar(sdist, entries)
        with self.assertRaisesRegex(
            AssertionError,
            "PKG-INFO must be located at <canonical-root>/PKG-INFO",
        ):
            audit(sdist)

    def test_nested_primary_pkg_info_is_rejected(self) -> None:
        sdist = self.root / "nested-pkg-info.tar.gz"
        entries = _fixture_entries(SDIST_ROOT)
        entries[f"{SDIST_ROOT}nested/PKG-INFO"] = MIT_METADATA
        for required in REQUIRED_SDIST_TESTS:
            entries[f"{SDIST_ROOT}{required}"] = "# synthetic contract test\n"
        entries[f"{SDIST_ROOT}LICENSE"] = MIT_LICENSE_TEXT
        _write_tar(sdist, entries)
        with self.assertRaisesRegex(
            AssertionError,
            "PKG-INFO must be a direct child of one canonical root",
        ):
            audit(sdist)

    def test_path_traversal_is_rejected_before_root_checks(self) -> None:
        sdist = self.root / "traversal.tar.gz"
        entries = _sdist_entries(metadata=MIT_METADATA, license_text=MIT_LICENSE_TEXT)
        entries[f"{SDIST_ROOT}../LICENSE.extra"] = MIT_LICENSE_TEXT
        _write_tar(sdist, entries)
        with self.assertRaisesRegex(AssertionError, "unsafe or ambiguous archive path"):
            audit(sdist)

    def test_malformed_sdist_still_fails_when_paired_with_valid_mit_wheel(self) -> None:
        wheel = self.root / "mit.whl"
        sdist = self.root / "wrong-sdist-root.tar.gz"
        _write_wheel(wheel, metadata=MIT_METADATA, license_text=MIT_LICENSE_TEXT)
        entries = _sdist_entries(metadata=MIT_METADATA)
        entries["unrelated-root/LICENSE"] = MIT_LICENSE_TEXT
        _write_tar(sdist, entries)
        with self.assertRaisesRegex(
            AssertionError,
            "outside canonical root.*unrelated-root/LICENSE",
        ):
            audit_distributions((wheel, sdist))

    def test_non_regular_and_sibling_tar_members_are_rejected(self) -> None:
        cases = (
            (
                "sibling-directory",
                _tar_member("second-root", tarfile.DIRTYPE),
                "outside canonical root",
            ),
            (
                "sibling-symlink",
                _tar_member(
                    "second-root/LICENSE",
                    tarfile.SYMTYPE,
                    linkname=f"../{SDIST_ROOT}LICENSE",
                ),
                "tar member type symlink",
            ),
            (
                "escaping-symlink",
                _tar_member(
                    f"{SDIST_ROOT}docs/license-link",
                    tarfile.SYMTYPE,
                    linkname="../../outside/LICENSE",
                ),
                "unsafe or ambiguous symlink target",
            ),
            (
                "hardlink",
                _tar_member(
                    f"{SDIST_ROOT}LICENSE.link",
                    tarfile.LNKTYPE,
                    linkname=f"{SDIST_ROOT}LICENSE",
                ),
                "tar member type hardlink",
            ),
            (
                "hardlink-traversal",
                _tar_member(
                    f"{SDIST_ROOT}LICENSE.link",
                    tarfile.LNKTYPE,
                    linkname="../outside/LICENSE",
                ),
                "unsafe or ambiguous hardlink target",
            ),
            (
                "fifo",
                _tar_member(f"{SDIST_ROOT}named-pipe", tarfile.FIFOTYPE),
                "tar member type fifo",
            ),
        )
        for name, member, finding in cases:
            with self.subTest(name=name):
                sdist = self.root / f"{name}.tar.gz"
                entries = _sdist_entries(
                    metadata=MIT_METADATA,
                    license_text=MIT_LICENSE_TEXT,
                )
                _write_tar(sdist, entries, extra_members=(member,))
                with self.assertRaisesRegex(AssertionError, finding):
                    audit(sdist)

    def test_non_regular_member_sdists_fail_when_paired_with_valid_wheel(self) -> None:
        wheel = self.root / "mit.whl"
        _write_wheel(wheel, metadata=MIT_METADATA, license_text=MIT_LICENSE_TEXT)
        members = (
            _tar_member("second-root", tarfile.DIRTYPE),
            _tar_member(
                "second-root/LICENSE",
                tarfile.SYMTYPE,
                linkname=f"../{SDIST_ROOT}LICENSE",
            ),
            _tar_member(
                f"{SDIST_ROOT}docs/license-link",
                tarfile.SYMTYPE,
                linkname="../../outside/LICENSE",
            ),
            _tar_member(
                f"{SDIST_ROOT}LICENSE.link",
                tarfile.LNKTYPE,
                linkname=f"{SDIST_ROOT}LICENSE",
            ),
            _tar_member(
                f"{SDIST_ROOT}LICENSE.link",
                tarfile.LNKTYPE,
                linkname="../outside/LICENSE",
            ),
            _tar_member(f"{SDIST_ROOT}named-pipe", tarfile.FIFOTYPE),
        )
        for index, member in enumerate(members):
            with self.subTest(index=index):
                sdist = self.root / f"paired-{index}.tar.gz"
                entries = _sdist_entries(
                    metadata=MIT_METADATA,
                    license_text=MIT_LICENSE_TEXT,
                )
                _write_tar(sdist, entries, extra_members=(member,))
                with self.assertRaises(AssertionError):
                    audit_distributions((wheel, sdist))

    def test_normal_sdist_directory_entries_are_accepted(self) -> None:
        sdist = self.root / "directory-entries.tar.gz"
        entries = _sdist_entries(metadata=MIT_METADATA, license_text=MIT_LICENSE_TEXT)
        directories = (
            _tar_member(SDIST_ROOT.rstrip("/"), tarfile.DIRTYPE),
            _tar_member(f"{SDIST_ROOT}src", tarfile.DIRTYPE),
            _tar_member(f"{SDIST_ROOT}src/claude_code_data_kit", tarfile.DIRTYPE),
            _tar_member(f"{SDIST_ROOT}tests", tarfile.DIRTYPE),
        )
        _write_tar(sdist, entries, extra_members=directories)
        self.assertEqual(audit(sdist).license_state, "mit")

    def test_license_file_without_mit_metadata_fails(self) -> None:
        wheel = self.root / "missing-metadata.whl"
        _write_wheel(wheel, license_text=MIT_LICENSE_TEXT)
        with self.assertRaisesRegex(AssertionError, "License-Expression is missing"):
            audit(wheel)

    def test_mit_metadata_without_license_file_fails(self) -> None:
        wheel = self.root / "missing-license.whl"
        _write_wheel(wheel, metadata=MIT_METADATA)
        with self.assertRaisesRegex(AssertionError, "declared license file missing"):
            audit(wheel)

    def test_license_file_declaration_must_target_license(self) -> None:
        wheel = self.root / "bad-path.whl"
        metadata = MIT_METADATA.replace("License-File: LICENSE", "License-File: COPYING")
        _write_wheel(wheel, metadata=metadata, license_text=MIT_LICENSE_TEXT)
        with self.assertRaisesRegex(AssertionError, "exactly License-File: LICENSE"):
            audit(wheel)

    def test_non_mit_expression_fails(self) -> None:
        wheel = self.root / "non-mit.whl"
        metadata = MIT_METADATA.replace("License-Expression: MIT", "License-Expression: Apache-2.0")
        _write_wheel(wheel, metadata=metadata, license_text=MIT_LICENSE_TEXT)
        with self.assertRaisesRegex(AssertionError, "unsupported License-Expression"):
            audit(wheel)

    def test_duplicate_or_legacy_conflicting_metadata_fails(self) -> None:
        duplicate = self.root / "duplicate-expression.whl"
        duplicate_metadata = MIT_METADATA.replace(
            "License-Expression: MIT",
            "License-Expression: MIT\nLicense-Expression: Apache-2.0",
        )
        _write_wheel(
            duplicate,
            metadata=duplicate_metadata,
            license_text=MIT_LICENSE_TEXT,
        )
        with self.assertRaisesRegex(AssertionError, "exactly one License-Expression"):
            audit(duplicate)

        legacy = self.root / "legacy-conflict.whl"
        legacy_metadata = MIT_METADATA.replace(
            "License-Expression: MIT",
            "License-Expression: MIT\nLicense: Proprietary",
        )
        _write_wheel(legacy, metadata=legacy_metadata, license_text=MIT_LICENSE_TEXT)
        with self.assertRaisesRegex(AssertionError, "conflicting legacy License metadata"):
            audit(legacy)

    def test_truncated_or_modified_mit_text_fails(self) -> None:
        sdist = self.root / "truncated.tar.gz"
        _write_sdist(
            sdist,
            metadata=MIT_METADATA,
            license_text=MIT_LICENSE_TEXT.split("THE SOFTWARE", 1)[0],
        )
        with self.assertRaisesRegex(AssertionError, "not the approved canonical MIT License"):
            audit(sdist)

    def test_commons_clause_or_extra_restriction_fails(self) -> None:
        wheel = self.root / "commons-clause.whl"
        _write_wheel(
            wheel,
            metadata=MIT_METADATA,
            license_text=MIT_LICENSE_TEXT + "Commons Clause: commercial use is restricted.\n",
        )
        with self.assertRaisesRegex(AssertionError, "Commons Clause"):
            audit(wheel)

    def test_multiple_conflicting_license_files_fail(self) -> None:
        wheel = self.root / "multiple.whl"
        _write_wheel(
            wheel,
            metadata=MIT_METADATA,
            license_text=MIT_LICENSE_TEXT,
            extra={"LICENSE.extra": MIT_LICENSE_TEXT},
        )
        with self.assertRaisesRegex(AssertionError, "unexpected or conflicting"):
            audit(wheel)

    def test_wheel_and_sdist_license_state_must_match(self) -> None:
        wheel = self.root / "baseline.whl"
        sdist = self.root / "mit.tar.gz"
        _write_wheel(wheel)
        _write_sdist(sdist, metadata=MIT_METADATA, license_text=MIT_LICENSE_TEXT)
        with self.assertRaisesRegex(AssertionError, "distribution license state mismatch"):
            audit_distributions((wheel, sdist))

    def test_existing_privacy_and_boundary_findings_still_fail(self) -> None:
        privacy = self.root / "privacy.whl"
        _write_wheel(
            privacy,
            extra={"claude_code_data_kit/leak.txt": "fictional-" "private-owner\n"},
        )
        with self.assertRaisesRegex(AssertionError, "fictional-public-sentinel"):
            audit(privacy)

        boundary = self.root / "boundary.whl"
        _write_wheel(
            boundary,
            extra={"claude_code_data_kit/boundary.txt": "backend." "observability\n"},
        )
        with self.assertRaisesRegex(AssertionError, "forbidden boundary marker"):
            audit(boundary)


if __name__ == "__main__":
    unittest.main()
