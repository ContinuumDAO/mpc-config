# sign-clipboard

A small Go CLI that signs the current clipboard contents with your Ed25519 key and puts the 128-hex signature back on the clipboard. Use it with the Continuum node app so you don't have to copy or paste the private key.

## Flow

1. In the app (Multi-Sign page), copy the **message to sign** (the JSON string shown in the message field).
2. Run `sign-clipboard` (or the built binary).
3. The tool reads the message from the clipboard, signs it with `~/.ssh/mpc_auth_ed25519`, and writes the **128-hex signature** to the clipboard.
4. Paste into the signature field in the app and submit.

## Build

From this repository root (mpc-config):

```bash
cd tools/sign-clipboard
go build -o sign-clipboard .
```

Or with `GOWORK=off` if you're in a Go workspace that excludes this module:

```bash
cd tools/sign-clipboard
GOWORK=off go build -o sign-clipboard .
```

**Requirements to build:** Go 1.21 or later. Fetch dependencies with `go mod tidy` (run automatically on first build).

## Requirements to run

- **Key file:** `~/.ssh/mpc_auth_ed25519` (same path as used by the app and docs). Supports:
  - PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) from the app's "Create new key pair" flow.
  - OpenSSH format (`-----BEGIN OPENSSH PRIVATE KEY-----`).
- **Clipboard:** On Linux, `xclip` or `xsel` must be installed for clipboard access.

## Usage

```bash
./sign-clipboard
```

- If the clipboard is empty or invalid, the tool exits with an error.
- On success it prints a short confirmation and the first 32 characters of the signature; the full 128-hex signature is on the clipboard for pasting into the app.

## Shipping a binary

Build for your target OS/arch, for example:

```bash
cd tools/sign-clipboard
GOOS=linux GOARCH=amd64 go build -o sign-clipboard-linux-amd64 .
GOOS=darwin GOARCH=arm64 go build -o sign-clipboard-darwin-arm64 .
GOOS=windows GOARCH=amd64 go build -o sign-clipboard-windows-amd64.exe .
```

Put the binary on the user's PATH or document where to download it so they can run it after copying the message from the app.
