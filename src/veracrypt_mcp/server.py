# Author: Fabian Bitter (fabian@bitter.de)

"""VeraCrypt MCP server (stdio transport).

Security model:
- The volume password is NEVER passed as a command line argument (it would be
  visible in the process list). It is always piped to VeraCrypt via stdin
  using the official ``--stdin`` option.
- Preferred password source is the OS keyring (macOS Keychain via ``security``,
  Linux via ``secret-tool``). With the keyring, the password never enters the
  LLM context or any conversation log.
- Passwords are never logged and never included in tool results or errors.
"""

import os
import platform
import shlex
import shutil
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

KEYCHAIN_SERVICE = "veracrypt-mcp"
SUBPROCESS_TIMEOUT = 180

mcp = FastMCP("veracrypt")


def _find_veracrypt() -> str:
    """Locate the VeraCrypt binary (env override, PATH, macOS app bundle)."""
    env_path = os.environ.get("VERACRYPT_PATH")
    if env_path and Path(env_path).is_file():
        return env_path
    on_path = shutil.which("veracrypt")
    if on_path:
        return on_path
    macos_bundle = "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"
    if Path(macos_bundle).is_file():
        return macos_bundle
    raise RuntimeError(
        "VeraCrypt binary not found. Install VeraCrypt or set the "
        "VERACRYPT_PATH environment variable."
    )


def _keyring_password(account: str) -> str:
    """Read a password from the OS keyring without ever logging it."""
    system = platform.system()
    if system == "Darwin":
        cmd = [
            "security",
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            account,
            "-w",
        ]
    elif system == "Linux":
        if not shutil.which("secret-tool"):
            raise RuntimeError(
                "secret-tool not found. Install libsecret-tools to use the "
                "keyring password source on Linux."
            )
        cmd = ["secret-tool", "lookup", "service", KEYCHAIN_SERVICE, "account", account]
    else:
        raise RuntimeError(f"Keyring lookup is not supported on {system}.")

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT
    )
    if result.returncode != 0 or not result.stdout:
        raise RuntimeError(
            f"No keyring entry found for service '{KEYCHAIN_SERVICE}' and "
            f"account '{account}'. Store one first (see README)."
        )
    return result.stdout.rstrip("\n")


def _resolve_password(password: str | None, keychain_account: str | None) -> str:
    if keychain_account:
        return _keyring_password(keychain_account)
    if password:
        return password
    raise RuntimeError(
        "No password source given. Provide 'keychain_account' (recommended) "
        "or 'password'."
    )


def _run_veracrypt(
    args: list[str], stdin_data: str | None = None
) -> subprocess.CompletedProcess[str]:
    cmd = [_find_veracrypt(), "--text", "--non-interactive", *args]
    return subprocess.run(
        cmd,
        input=stdin_data,
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )


def _error_text(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stderr.strip() or result.stdout.strip() or "Unknown VeraCrypt error")


@mcp.tool()
def mount_container(
    container_path: str,
    mount_point: str | None = None,
    keychain_account: str | None = None,
    password: str | None = None,
    pim: int | None = None,
    read_only: bool = False,
) -> str:
    """Mount a VeraCrypt container.

    Password sources (exactly one is required):
    - keychain_account (RECOMMENDED): name of an OS keyring entry with service
      'veracrypt-mcp'. The password never enters the conversation.
    - password: the volume password in plain text. It is piped to VeraCrypt
      via stdin (never visible in the process list), but it does pass through
      the LLM context. Prefer keychain_account.

    Args:
        container_path: Absolute path to the VeraCrypt container file.
        mount_point: Optional mount directory. If omitted, VeraCrypt picks one
            automatically (e.g. /Volumes/... on macOS).
        keychain_account: Keyring account name to look up the password.
        password: Plain text password (fallback, see above).
        pim: Optional PIM (Personal Iterations Multiplier) of the volume.
        read_only: Mount the volume read-only.
    """
    container = Path(container_path).expanduser()
    if not container.exists():
        return f"Error: container not found: {container}"

    try:
        volume_password = _resolve_password(password, keychain_account)
    except RuntimeError as exc:
        return f"Error: {exc}"

    args = ["--stdin", "--pim", str(pim if pim is not None else 0)]
    if read_only:
        args += ["--mount-options", "readonly"]
    args.append(str(container))
    if mount_point:
        mount_dir = Path(mount_point).expanduser()
        mount_dir.mkdir(parents=True, exist_ok=True)
        args.append(str(mount_dir))

    try:
        result = _run_veracrypt(args, stdin_data=volume_password + "\n")
    except subprocess.TimeoutExpired:
        return "Error: VeraCrypt timed out while mounting the container."
    finally:
        del volume_password

    if result.returncode != 0:
        return f"Error mounting container: {_error_text(result)}"

    actual_mount = _find_mount_point(str(container))
    location = actual_mount or str(mount_point or "auto-selected by VeraCrypt")
    return f"Mounted {container} at {location}"


@mcp.tool()
def unmount_container(container_or_mount_point: str) -> str:
    """Unmount (dismount) a VeraCrypt container.

    Args:
        container_or_mount_point: Path to the container file OR its current
            mount directory.
    """
    target = str(Path(container_or_mount_point).expanduser())
    try:
        result = _run_veracrypt(["--dismount", target])
    except subprocess.TimeoutExpired:
        return "Error: VeraCrypt timed out while dismounting."

    if result.returncode != 0:
        return f"Error dismounting: {_error_text(result)}"
    return f"Dismounted {target}"


@mcp.tool()
def list_mounted_containers() -> str:
    """List all currently mounted VeraCrypt volumes."""
    try:
        result = _run_veracrypt(["--list"])
    except subprocess.TimeoutExpired:
        return "Error: VeraCrypt timed out while listing volumes."

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "No volumes mounted" in stderr:
            return "No VeraCrypt volumes are currently mounted."
        return f"Error listing volumes: {_error_text(result)}"
    return result.stdout.strip() or "No VeraCrypt volumes are currently mounted."


def _find_mount_point(container_path: str) -> str | None:
    """Parse `veracrypt --list` output to find where a container is mounted."""
    try:
        result = _run_veracrypt(["--list"])
    except subprocess.TimeoutExpired:
        return None
    if result.returncode != 0:
        return None
    # Line format: "1: '/path/to/container' /dev/diskN /mount/point"
    # VeraCrypt quotes paths containing spaces, so parse with shlex.
    for line in result.stdout.splitlines():
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if len(parts) >= 4 and parts[1] == container_path:
            return parts[3]
    return None


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
