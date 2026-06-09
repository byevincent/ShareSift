"""v0.40 step 1 — default noise-exclusion glob tests."""

from __future__ import annotations

import pytest

from sharesift.share.exclusions import (
    DEFAULT_EXCLUDE_GLOBS,
    filter_paths,
    is_excluded,
)


class TestDefaultExclusions:
    """Verify the default pattern list catches the noise paths that
    actually dominate real shares."""

    @pytest.mark.parametrize(
        "path",
        [
            r"C:\Windows\System32\kernel32.dll",
            r"C:\Windows\System32\foo.exe",
            r"C:\Windows\System32\drivers\disk.sys",
            r"C:\Windows\SysWOW64\user32.dll",
            r"C:\Windows\winsxs\x86_random.manifest",
            r"C:\Windows\Prefetch\NOTEPAD.EXE-abc.pf",
            "/c/Windows/System32/kernel32.dll",  # POSIX-mounted
            r"\\10.0.0.5\C$\Windows\System32\kernel32.dll",  # UNC
        ],
    )
    def test_windows_system_noise_excluded(self, path):
        assert is_excluded(path, DEFAULT_EXCLUDE_GLOBS)

    @pytest.mark.parametrize(
        "path",
        [
            "/srv/code/node_modules/react/index.js",
            "/srv/code/.git/objects/ab/cdef0123",
            "/srv/code/.svn/entries",
            "/srv/proj/__pycache__/module.cpython-311.pyc",
            "/srv/vendor/package/file.go",
            "/srv/build/intermediates/incremental/build.json",
        ],
    )
    def test_dev_tool_dirs_excluded(self, path):
        assert is_excluded(path, DEFAULT_EXCLUDE_GLOBS)

    @pytest.mark.parametrize(
        "path",
        [
            "/share/backup.iso",
            "/share/disk.vmdk",
            "/share/img.vhd",
            "/share/video.mp4",
            "/share/photo.jpg",
            "/share/screenshot.png",
        ],
    )
    def test_media_and_disk_images_excluded(self, path):
        assert is_excluded(path, DEFAULT_EXCLUDE_GLOBS)


class TestNonExcludedPaths:
    """Files that ARE worth scanning — these must NOT be excluded
    by the default list."""

    @pytest.mark.parametrize(
        "path",
        [
            r"C:\Users\alice\.aws\credentials",
            r"C:\Users\alice\.vault-token",
            r"C:\inetpub\wwwroot\web.config",
            r"C:\Windows\Panther\unattend.xml",
            r"\\10.0.0.5\Finance\secrets.cfg",
            "/home/alice/.ssh/id_rsa",
            "/etc/ansible/vault.yml",
            "/srv/data/terraform.tfstate",
            "/srv/data/customer-list.docx",
            "/srv/data/payroll.xlsx",
            "/share/keys/server.ppk",
            "/share/config.cfg",
        ],
    )
    def test_credential_targets_not_excluded(self, path):
        assert not is_excluded(path, DEFAULT_EXCLUDE_GLOBS)


class TestFilterPaths:
    def test_filter_returns_kept_paths_and_count(self):
        paths = [
            r"C:\Windows\System32\kernel32.dll",
            r"C:\inetpub\wwwroot\web.config",
            "/srv/code/node_modules/react/index.js",
            "/home/alice/.ssh/id_rsa",
        ]
        kept, excluded = filter_paths(paths)
        assert excluded == 2
        assert kept == [
            r"C:\inetpub\wwwroot\web.config",
            "/home/alice/.ssh/id_rsa",
        ]

    def test_extra_globs_combine_with_defaults(self):
        paths = [
            "/srv/share/file.txt",
            "/srv/share/secret.scratch",
        ]
        kept, excluded = filter_paths(paths, extra_globs=["*.scratch"])
        assert excluded == 1
        assert kept == ["/srv/share/file.txt"]

    def test_use_defaults_false_disables_default_list(self):
        paths = [r"C:\Windows\System32\kernel32.dll"]
        kept, excluded = filter_paths(paths, use_defaults=False)
        assert excluded == 0
        assert kept == paths

    def test_empty_patterns_returns_input_unchanged(self):
        paths = ["/a", "/b", "/c"]
        kept, excluded = filter_paths(paths, use_defaults=False)
        assert excluded == 0
        assert kept == ["/a", "/b", "/c"]

    def test_filter_preserves_order(self):
        paths = ["/share/" + f for f in
                 ["a.txt", "b.dll", "c.txt", "d.dll", "e.txt"]]
        kept, _ = filter_paths(paths, extra_globs=["*.dll"], use_defaults=False)
        assert kept == ["/share/a.txt", "/share/c.txt", "/share/e.txt"]


class TestPathNormalization:
    """Case-insensitive + slash-normalized matching is essential
    because operators copy paths from both Windows and POSIX
    contexts."""

    def test_uppercase_path_matches_lowercase_pattern(self):
        assert is_excluded(r"C:\WINDOWS\SYSTEM32\KERNEL32.DLL", DEFAULT_EXCLUDE_GLOBS)

    def test_forward_slashes_match_backslash_pattern(self):
        # The default pattern uses */Windows/System32/*.dll
        assert is_excluded("/c/windows/system32/foo.dll", DEFAULT_EXCLUDE_GLOBS)

    def test_unc_path_matches(self):
        assert is_excluded(
            r"\\10.0.0.5\C$\Windows\System32\kernel32.dll",
            DEFAULT_EXCLUDE_GLOBS,
        )
