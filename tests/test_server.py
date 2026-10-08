# Author: Fabian Bitter (fabian@bitter.de)

"""Integration tests against throwaway VeraCrypt containers.

Run with: python -m unittest discover -s tests
Needs the VeraCrypt CLI (and macFUSE on macOS); skipped otherwise.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from veracrypt_mcp import server

PASSWORD = "throwaway-pw-123"


def _veracrypt() -> str | None:
    try:
        return server._find_veracrypt()
    except RuntimeError:
        return None


@unittest.skipIf(_veracrypt() is None, "VeraCrypt CLI not installed")
class MountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="vcmcp-")).resolve()
        cls.keyfile = cls.tmp / "good.key"
        cls.keyfile.write_bytes(os.urandom(64))
        cls.other_keyfile = cls.tmp / "other.key"
        cls.other_keyfile.write_bytes(os.urandom(64))
        cls.key_volume = cls.tmp / "key.vc"
        cls.pw_volume = cls.tmp / "pw.vc"
        cls._create(cls.key_volume, ["-p", "", "-k", str(cls.keyfile)])
        cls._create(cls.pw_volume, ["-p", PASSWORD, "-k", ""])

    @classmethod
    def _create(cls, path: Path, credentials: list[str]) -> None:
        subprocess.run(
            [_veracrypt(), "-t", "--non-interactive", "-c", str(path),
             "--volume-type=normal", "--size=5000000", "--encryption=AES",
             "--hash=SHA-512", "--filesystem=exFAT", "--pim=0",
             "--random-source=/dev/urandom", *credentials],
            check=True, capture_output=True,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.mnt = self.tmp / "mnt"
        self.mnt.mkdir(exist_ok=True)
        clean = {k: v for k, v in os.environ.items() if not k.startswith("VERACRYPT_MCP_")}
        patcher = mock.patch.dict(os.environ, clean, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        for volume in (self.key_volume, self.pw_volume):
            server._run_veracrypt(["--dismount", str(volume)])

    def assertMounted(self, result: str, volume: Path):
        self.assertTrue(result.startswith("Mounted"), result)
        self.assertEqual(server._find_mount_point(str(volume)), str(self.mnt))

    def test_keyfile_with_empty_password(self):
        result = server.mount_container(
            str(self.key_volume), str(self.mnt), keyfiles=[str(self.keyfile)]
        )
        self.assertMounted(result, self.key_volume)

    def test_wrong_keyfile_reports_key_not_released(self):
        result = server.mount_container(
            str(self.key_volume), str(self.mnt), keyfiles=[str(self.other_keyfile)]
        )
        self.assertIn(server.KEY_NOT_RELEASED, result)

    def test_missing_explicit_keyfile_does_not_guess(self):
        with mock.patch.object(server, "_keyring_password") as keyring:
            result = server.mount_container(
                str(self.key_volume), str(self.mnt),
                keyfiles=[str(self.tmp / "absent.key")], keychain_account="data",
            )
        self.assertIn(server.KEY_NOT_RELEASED, result)
        keyring.assert_not_called()

    def test_default_keyfile_from_env(self):
        os.environ[server.ENV_DEFAULT_KEYFILES] = str(self.keyfile)
        result = server.mount_container(str(self.key_volume), str(self.mnt))
        self.assertMounted(result, self.key_volume)

    def test_missing_default_keyfile_falls_back_to_keychain(self):
        os.environ[server.ENV_DEFAULT_KEYFILES] = str(self.tmp / "absent.key")
        os.environ[server.ENV_DEFAULT_KEYCHAIN_ACCOUNT] = "data"
        with mock.patch.object(server, "_keyring_password", return_value=PASSWORD):
            result = server.mount_container(str(self.pw_volume), str(self.mnt))
        self.assertMounted(result, self.pw_volume)

    def test_keychain_rejected_after_switch_reports_key_not_released(self):
        os.environ[server.ENV_DEFAULT_KEYFILES] = str(self.tmp / "absent.key")
        os.environ[server.ENV_DEFAULT_KEYCHAIN_ACCOUNT] = "data"
        with mock.patch.object(server, "_keyring_password", return_value=PASSWORD):
            result = server.mount_container(str(self.key_volume), str(self.mnt))
        self.assertIn(server.KEY_NOT_RELEASED, result)

    def test_missing_default_keyfile_without_password_source(self):
        os.environ[server.ENV_DEFAULT_KEYFILES] = str(self.tmp / "absent.key")
        result = server.mount_container(str(self.key_volume), str(self.mnt))
        self.assertIn(server.KEY_NOT_RELEASED, result)

    def test_old_keychain_path_unchanged(self):
        with mock.patch.object(server, "_keyring_password", return_value=PASSWORD):
            result = server.mount_container(
                str(self.pw_volume), str(self.mnt), keychain_account="data"
            )
        self.assertMounted(result, self.pw_volume)

    def _unlock_script(self, release: bool) -> str:
        script = self.tmp / ("unlock-yes.sh" if release else "unlock-no.sh")
        if release:
            body = (f'printf "\\n" | "{_veracrypt()}" -t --non-interactive --stdin --pim 0 '
                    f'-k "{self.keyfile}" --protect-hidden=no "{self.key_volume}" "{self.mnt}"')
        else:
            body = 'echo "Key nicht freigegeben"; exit 1'
        script.write_text(f'#!/bin/bash\n[ "$1" = "--interaktiv" ] || exit 9\n{body}\n')
        script.chmod(0o700)
        return str(script)

    def test_unlock_command_released(self):
        os.environ[server.ENV_UNLOCK_COMMAND] = self._unlock_script(True)
        os.environ[server.ENV_DEFAULT_KEYCHAIN_ACCOUNT] = "data"
        with mock.patch.object(server, "_keyring_password") as keyring:
            result = server.mount_container(str(self.key_volume), str(self.mnt))
        self.assertMounted(result, self.key_volume)
        keyring.assert_not_called()

    def test_unlock_command_refused(self):
        os.environ[server.ENV_UNLOCK_COMMAND] = self._unlock_script(False)
        result = server.mount_container(str(self.key_volume), str(self.mnt))
        self.assertEqual(result, f"Error: {server.KEY_NOT_RELEASED}")


if __name__ == "__main__":
    unittest.main()
