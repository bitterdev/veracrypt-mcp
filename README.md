# veracrypt-mcp

MCP (Model Context Protocol) server for mounting and unmounting [VeraCrypt](https://veracrypt.io) containers, with a security-first approach to password handling.

Once a container is mounted, your MCP client (e.g. Claude Code) can read and edit the files inside it with its normal file tools. Say "mount my vault", work on the files, then "unmount my vault".

## Features

- **mount_container**: mount a VeraCrypt container (optional mount point, PIM, read-only)
- **unmount_container**: dismount by container path or mount point
- **list_mounted_containers**: show all mounted VeraCrypt volumes
- **Default vault**: configure your container once via environment variables; "mount my vault" then works without any arguments

## Security model

The volume password is **never passed as a command line argument**. Command line arguments are visible to every process on the machine (`ps aux`), so this server always pipes the password to VeraCrypt via stdin using VeraCrypt's official `--stdin` option.

There are two password sources:

### 1. OS keyring (recommended)

Store the password once in the OS keyring. The MCP tool then only receives a keyring *account name*, so the password never enters the LLM context, chat logs, or transcripts.

macOS (Keychain):

```bash
security add-generic-password -s veracrypt-mcp -a my-container -w
# you will be prompted for the password interactively
```

Linux (libsecret / GNOME Keyring, requires `libsecret-tools`):

```bash
secret-tool store --label="veracrypt-mcp my-container" service veracrypt-mcp account my-container
```

Then mount with `keychain_account: "my-container"`.

### 2. Direct password (fallback)

You can pass `password` directly to the tool. It is still piped via stdin to VeraCrypt (never visible in the process list), **but it passes through the LLM conversation** and may be stored in chat logs. Use the keyring source whenever possible.

Additional notes:

- Passwords are never logged and never included in tool results or error messages.
- Python cannot securely wipe strings from memory; for maximum security, use the keyring source and a dedicated container password.

## Requirements

- Python >= 3.10
- VeraCrypt with the command line binary available (`veracrypt` on PATH, the macOS app bundle, or set `VERACRYPT_PATH`)
- macOS: [macFUSE](https://macfuse.github.io/) (required by VeraCrypt for mounting)
- Linux keyring source: `libsecret-tools` (`secret-tool`)

## Installation

```bash
pip install git+https://github.com/bitterdev/veracrypt-mcp.git
```

Or from a local clone:

```bash
git clone https://github.com/bitterdev/veracrypt-mcp.git
cd veracrypt-mcp
pip install .
```

## Configuration

### Claude Code

```bash
claude mcp add veracrypt -- veracrypt-mcp
```

With a default vault (recommended):

```bash
claude mcp add veracrypt \
  -e VERACRYPT_MCP_CONTAINER="/path/to/vault.hc" \
  -e VERACRYPT_MCP_KEYCHAIN_ACCOUNT="my-vault" \
  -- veracrypt-mcp
```

### Claude Desktop / generic MCP client

```json
{
  "mcpServers": {
    "veracrypt": {
      "command": "veracrypt-mcp",
      "env": {
        "VERACRYPT_MCP_CONTAINER": "/path/to/vault.hc",
        "VERACRYPT_MCP_KEYCHAIN_ACCOUNT": "my-vault"
      }
    }
  }
}
```

The server runs over stdio.

## Usage examples

With a configured default vault:

> Mount my vault

> Unmount my vault

Explicit, without defaults:

> Mount the container /Users/me/secret.hc using the keychain account "my-container"

Mount read-only at a specific mount point:

> Mount /Users/me/secret.hc read-only at ~/mnt/secret, keychain account "my-container"

## Environment variables

| Variable | Description |
| --- | --- |
| `VERACRYPT_MCP_CONTAINER` | Default container path used when no `container_path` is given |
| `VERACRYPT_MCP_KEYCHAIN_ACCOUNT` | Default keyring account used when no password source is given |
| `VERACRYPT_MCP_MOUNT_POINT` | Default mount directory (otherwise VeraCrypt auto-selects) |
| `VERACRYPT_PATH` | Absolute path to the VeraCrypt binary if it is not on PATH |

## License

MIT, see [LICENSE](LICENSE).

## Author

Fabian Bitter (fabian@bitter.de)
