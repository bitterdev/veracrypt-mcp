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
- Keyfiles (VeraCrypt ``-k``) are supported for volumes protected by a keyfile
  plus an empty password, e.g. a keyfile that is only briefly decrypted onto a
  RAM disk by a hardware token. A configured keyfile that is missing is
  reported as "Key nicht freigegeben" instead of guessing other credentials.
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

# Optional defaults so a user can say "mount my vault" without arguments.
ENV_DEFAULT_CONTAINER = "VERACRYPT_MCP_CONTAINER"
ENV_DEFAULT_KEYCHAIN_ACCOUNT = "VERACRYPT_MCP_KEYCHAIN_ACCOUNT"
ENV_DEFAULT_MOUNT_POINT = "VERACRYPT_MCP_MOUNT_POINT"
ENV_DEFAULT_KEYFILES = "VERACRYPT_MCP_KEYFILES"
ENV_UNLOCK_COMMAND = "VERACRYPT_MCP_UNLOCK_COMMAND"
UNLOCK_TIMEOUT = 420

KEY_NOT_RELEASED = "Key nicht freigegeben"
WRONG_CREDENTIALS_MARKER = "Incorrect password"

mcp = FastMCP("veracrypt")


def _default_container(container_path: str | None) -> str | None:
    return container_path or os.environ.get(ENV_DEFAULT_CONTAINER)


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


def _has_password_source(password: str | None, keychain_account: str | None) -> bool:
    return bool(password or keychain_account or os.environ.get(ENV_DEFAULT_KEYCHAIN_ACCOUNT))


def _resolve_password(password: str | None, keychain_account: str | None) -> str:
    account = keychain_account or os.environ.get(ENV_DEFAULT_KEYCHAIN_ACCOUNT)
    if account:
        return _keyring_password(account)
    if password:
        return password
    raise RuntimeError(
        "No password source given. Provide 'keychain_account' (recommended), "
        "'password', or set the VERACRYPT_MCP_KEYCHAIN_ACCOUNT environment "
        "variable."
    )


class KeyNotReleasedError(RuntimeError):
    """A keyfile was requested but is not present (token not unlocked)."""


def _split_keyfiles(raw: str) -> list[str]:
    # os.pathsep (":") cannot separate paths that may contain colons on macOS
    # volume names, so a newline or comma separated list is used instead.
    parts = raw.replace(",", "\n").splitlines()
    return [p.strip() for p in parts if p.strip()]


def _resolve_keyfiles(keyfiles: list[str] | None) -> tuple[list[str], bool]:
    """Return (keyfile paths, explicitly requested by the caller)."""
    if keyfiles:
        return [str(Path(k).expanduser()) for k in keyfiles], True
    raw = os.environ.get(ENV_DEFAULT_KEYFILES, "")
    return [str(Path(k).expanduser()) for k in _split_keyfiles(raw)], False


def _missing_keyfiles(paths: list[str]) -> list[str]:
    return [p for p in paths if not Path(p).is_file()]


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
    container_path: str | None = None,
    mount_point: str | None = None,
    keychain_account: str | None = None,
    password: str | None = None,
    keyfiles: list[str] | None = None,
    pim: int | None = None,
    read_only: bool = False,
) -> str:
    """Mount a VeraCrypt container.

    Credential sources:
    - keyfiles: paths of keyfiles (VeraCrypt -k). Used together with an empty
      password unless a password source is given as well. If a keyfile does
      not exist (e.g. the hardware token has not released it yet), the tool
      answers "Key nicht freigegeben" and does not try anything else.
    - keychain_account (RECOMMENDED for password volumes): name of an OS
      keyring entry with service 'veracrypt-mcp'. The password never enters
      the conversation.
    - password: the volume password in plain text. It is piped to VeraCrypt
      via stdin (never visible in the process list), but it does pass through
      the LLM context. Prefer keychain_account.

    If VERACRYPT_MCP_UNLOCK_COMMAND is set and no credential is passed, the
    mount is handed to that command (called with --interaktiv), which asks
    the user for the hardware token and PIN. Nothing is cached: every mount
    through this tool needs the user's input.

    Defaults from the environment: VERACRYPT_MCP_CONTAINER,
    VERACRYPT_MCP_KEYCHAIN_ACCOUNT, VERACRYPT_MCP_MOUNT_POINT and
    VERACRYPT_MCP_KEYFILES (comma or newline separated). With default
    keyfiles configured, a present keyfile is used; a missing one falls back
    to the keychain password (transition period while a volume still has its
    old password), and if that is rejected the answer is
    "Key nicht freigegeben".

    Args:
        container_path: Absolute path to the VeraCrypt container file.
            Defaults to VERACRYPT_MCP_CONTAINER.
        mount_point: Optional mount directory. If omitted, falls back to
            VERACRYPT_MCP_MOUNT_POINT, otherwise VeraCrypt picks one
            automatically (e.g. /Volumes/... on macOS).
        keychain_account: Keyring account name to look up the password.
            Defaults to VERACRYPT_MCP_KEYCHAIN_ACCOUNT.
        password: Plain text password (fallback, see above).
        keyfiles: Keyfile paths. Defaults to VERACRYPT_MCP_KEYFILES.
        pim: Optional PIM (Personal Iterations Multiplier) of the volume.
        read_only: Mount the volume read-only.
    """
    resolved_container = _default_container(container_path)
    if not resolved_container:
        return (
            "Error: no container given. Provide 'container_path' or set the "
            f"{ENV_DEFAULT_CONTAINER} environment variable."
        )
    container = Path(resolved_container).expanduser()
    if not container.exists():
        return f"Error: container not found: {container}"

    resolved_mount_point = mount_point or os.environ.get(ENV_DEFAULT_MOUNT_POINT)
    unlock_command = os.environ.get(ENV_UNLOCK_COMMAND)
    if unlock_command and not keyfiles and not password and not keychain_account:
        return _mount_via_unlock_command(unlock_command, container, resolved_mount_point)

    keyfile_paths, explicit_keyfiles = _resolve_keyfiles(keyfiles)
    missing = _missing_keyfiles(keyfile_paths)
    use_keyfiles = bool(keyfile_paths) and not missing
    fell_back = False

    if missing and (explicit_keyfiles or not _has_password_source(password, keychain_account)):
        return f"Error: {KEY_NOT_RELEASED} (keyfile not present: {', '.join(missing)})"

    try:
        if use_keyfiles and not password and not keychain_account:
            volume_password = ""
        else:
            volume_password = _resolve_password(password, keychain_account)
            fell_back = bool(missing)
    except RuntimeError as exc:
        return f"Error: {exc}"

    args = ["--stdin", "--pim", str(pim if pim is not None else 0)]
    if use_keyfiles:
        args += ["--keyfiles", ",".join(keyfile_paths), "--protect-hidden=no"]
    if read_only:
        args += ["--mount-options", "readonly"]
    args.append(str(container))
    if resolved_mount_point:
        mount_dir = Path(resolved_mount_point).expanduser()
        mount_dir.mkdir(parents=True, exist_ok=True)
        args.append(str(mount_dir))

    try:
        result = _run_veracrypt(args, stdin_data=volume_password + "\n")
    except subprocess.TimeoutExpired:
        return "Error: VeraCrypt timed out while mounting the container."
    finally:
        del volume_password

    if result.returncode != 0:
        error = _error_text(result)
        if (use_keyfiles or fell_back) and WRONG_CREDENTIALS_MARKER in error:
            return f"Error: {KEY_NOT_RELEASED} (VeraCrypt rejected the credentials)"
        return f"Error mounting container: {error}"

    actual_mount = _find_mount_point(str(container))
    location = actual_mount or str(resolved_mount_point or "auto-selected by VeraCrypt")
    return f"Mounted {container} at {location}"


def _mount_via_unlock_command(
    command: str, container: Path, mount_point: str | None
) -> str:
    """Delegate mounting to an interactive unlock command (e.g. hardware token + PIN).

    The command receives --interaktiv and is expected to ask the user, mount the
    volume and exit non-zero if the user did not release the key.
    """
    cmd = [*shlex.split(command), "--interaktiv"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=UNLOCK_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return f"Error: {KEY_NOT_RELEASED} (no answer within {UNLOCK_TIMEOUT} s)"
    except OSError as exc:
        return f"Error: unlock command failed to start: {exc}"
    actual_mount = _find_mount_point(str(container))
    if result.returncode != 0 or not actual_mount:
        return f"Error: {KEY_NOT_RELEASED}"
    return f"Mounted {container} at {actual_mount}"


@mcp.tool()
def unmount_container(container_or_mount_point: str | None = None) -> str:
    """Unmount (dismount) a VeraCrypt container.

    Args:
        container_or_mount_point: Path to the container file OR its current
            mount directory. Defaults to VERACRYPT_MCP_CONTAINER.
    """
    resolved = _default_container(container_or_mount_point)
    if not resolved:
        return (
            "Error: no target given. Provide 'container_or_mount_point' or "
            f"set the {ENV_DEFAULT_CONTAINER} environment variable."
        )
    target = str(Path(resolved).expanduser())
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
