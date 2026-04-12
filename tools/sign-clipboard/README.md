# sign-clipboard

A small Go CLI that signs the current clipboard contents with your Ed25519 key and puts the 128-hex signature back on the clipboard. Use it with the Continuum node app so you don’t have to copy or paste the private key.

## Flow

1. In the app (Multi-Sign page), copy the **message to sign** (the JSON string shown in the message field).
2. Run `sign-clipboard` (or the built binary).
3. The tool reads the message from the clipboard, signs it with your Ed25519 management key, and writes the **128-hex signature** to the clipboard. By default it uses `~/.ssh/mpc_auth_ed25519` if that file exists, otherwise `~/.ssh/mpc_auth_bootstrap_ed25519`. If you have multiple added keys, use `--key-file <path>` to specify which key file to use.
4. Paste into the signature field in the app and submit.

## Build

```bash
cd tools/sign-clipboard
go build -o sign-clipboard .
```

Or with `GOWORK=off` if you're in a Go workspace that excludes this module:

```bash
GOWORK=off go build -o sign-clipboard .
```

## Flags

- **`--bootstrap`** — Use only the bootstrap key (`~/.ssh/mpc_auth_bootstrap_ed25519`). If that file does not exist, the tool exits with a clear error. Use this when you selected **Bootstrap (config)** in the app’s “Which key are you using?” step.
- **`--primary`** — Use only the primary key (`~/.ssh/mpc_auth_ed25519`). Fails if that file does not exist.
- **`--key-file <path>`** — Use this key file (e.g. `~/.ssh/mpc_auth_2_ed25519`). Use when you have multiple added keys and need to sign with the key you selected in the app. Fails if the file does not exist.
- **`--stdin`** — Read the message from standard input and write the 128-hex signature to **standard output** (status lines go to stderr). Does not use the clipboard. Use on **SSH or headless** hosts where `DISPLAY` / `WAYLAND_DISPLAY` are unset and `xclip` cannot run.
- **`--inline '<string>'`** — Sign this **exact** UTF-8 string (e.g. the canonical JSON body for a management **`POST`**). Writes the 128-hex signature to **stdout**; no clipboard. **Do not** use together with **`--stdin`** or **`--inline-file`**. Prefer this for agents and scripts so the message matches the real request body without copy/paste.
- **`--inline-file <path>`** — Read the message to sign from this file (**exact** bytes; `~` expanded). Writes the 128-hex signature to **stdout**. Use for **large** JSON bodies where shell-quoting **`--inline`** is impractical. **Do not** combine with **`--stdin`** or **`--inline`**.
- With no flags, the tool uses the first of (primary, bootstrap) that exists.

## Requirements

- **Key file:** By default the tool looks for a key in this order: `~/.ssh/mpc_auth_ed25519`, then `~/.ssh/mpc_auth_bootstrap_ed25519` (uses the first that exists). Use `--bootstrap` or `--primary` to force one of those. Use `--key-file ~/.ssh/mpc_auth_2_ed25519` (or similar) when you have multiple added keys. Supports:
  - PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) from the app’s “Create new key pair” flow.
  - OpenSSH format (`-----BEGIN OPENSSH PRIVATE KEY-----`).
- **Clipboard:** On Linux, `xclip` or `xsel` must be installed for clipboard access (not needed if you use `--stdin`).
- **Headless / SSH:** If `echo $DISPLAY` is empty, the clipboard path will not work. Put the exact message in a file and run:
  `sign-clipboard --bootstrap --stdin < message.txt`
  then copy the first line of output (the hex signature) into the app.

## Usage

```bash
./sign-clipboard                              # use first of primary / bootstrap that exists
./sign-clipboard --bootstrap                  # use only bootstrap key (fail if missing)
./sign-clipboard --primary                    # use only primary key (fail if missing)
./sign-clipboard --key-file ~/.ssh/mpc_auth_2_ed25519   # use specific key file (multiple added keys)
./sign-clipboard --bootstrap --stdin < message.txt   # headless: message from file, signature on stdout
./sign-clipboard --inline '{"foo":1}'                 # sign literal body; signature on stdout (POST / automation)
./sign-clipboard --inline-file ./body.json            # sign file contents; signature on stdout (large POST bodies)
```

- If the clipboard is empty or invalid, the tool exits with an error.
- If you selected **Bootstrap (config)** in the app, run `./sign-clipboard --bootstrap` so the correct key file is used; if the bootstrap file does not exist, you get a clear error instead of it silently using the primary key.
- On success it prints a short confirmation and the first 32 characters of the signature; the full 128-hex signature is on the clipboard for pasting into the app.

## Shipping a binary

Build for your target OS/arch, for example:

```bash
GOOS=linux GOARCH=amd64 go build -o sign-clipboard-linux-amd64 .
GOOS=darwin GOARCH=arm64 go build -o sign-clipboard-darwin-arm64 .
GOOS=windows GOARCH=amd64 go build -o sign-clipboard-windows-amd64.exe .
```

Put the binary on the user’s PATH or document where to download it so they can run it after copying the message from the app.
