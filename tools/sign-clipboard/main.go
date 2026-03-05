// sign-clipboard reads the message to sign from the clipboard, signs it with
// ~/.ssh/mpc_auth_ed25519, and writes the 128-hex signature back to the clipboard.
// Usage: copy the message in the app, run this binary, then paste the signature into the app.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/atotto/clipboard"
	"golang.org/x/crypto/ssh"
)

const keyPath = "~/.ssh/mpc_auth_ed25519"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run() error {
	// Read message from clipboard
	msg, err := clipboard.ReadAll()
	if err != nil {
		return fmt.Errorf("reading clipboard: %w", err)
	}
	msg = trimBOM(msg)
	if strings.TrimSpace(msg) == "" {
		return fmt.Errorf("clipboard is empty; copy the message to sign from the app first")
	}

	// Resolve key path
	keyFile := keyPath
	if keyFile == "~/.ssh/mpc_auth_ed25519" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("home dir: %w", err)
		}
		keyFile = filepath.Join(home, ".ssh", "mpc_auth_ed25519")
	}

	keyPem, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("reading key file %s: %w", keyFile, err)
	}

	priv, err := parseEd25519PrivateKey(keyPem)
	if err != nil {
		return fmt.Errorf("parsing key: %w", err)
	}

	// Sign the exact message bytes (as shown in the app)
	sig := ed25519.Sign(priv, []byte(msg))
	sigHex := hex.EncodeToString(sig)
	if len(sigHex) != 128 {
		return fmt.Errorf("unexpected signature length: %d hex chars", len(sigHex))
	}

	// Write signature to clipboard
	if err := clipboard.WriteAll(sigHex); err != nil {
		return fmt.Errorf("writing to clipboard: %w", err)
	}

	fmt.Println("Signature (128 hex) copied to clipboard. Paste it into the app.")
	fmt.Println("First 32 chars:", sigHex[:32]+"...")
	return nil
}

// parseEd25519PrivateKey supports PKCS#8 PEM (from the app) and OpenSSH format.
func parseEd25519PrivateKey(keyPem []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 from the app's key generation
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#8: %w", err)
		}
		p, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not Ed25519")
		}
		return p, nil
	case "OPENSSH PRIVATE KEY":
		// OpenSSH format (e.g. from ssh-keygen)
		key, err := ssh.ParseRawPrivateKey(keyPem)
		if err != nil {
			return nil, fmt.Errorf("OpenSSH: %w", err)
		}
		switch k := key.(type) {
		case *ed25519.PrivateKey:
			return *k, nil
		case ed25519.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("OpenSSH key is not Ed25519")
		}
	default:
		return nil, fmt.Errorf("unsupported key type %q; use PRIVATE KEY (PKCS#8) or OPENSSH PRIVATE KEY", block.Type)
	}
}

func trimBOM(s string) string {
	if len(s) >= 3 && s[0] == '\xef' && s[1] == '\xbb' && s[2] == '\xbf' {
		return s[3:]
	}
	return s
}
