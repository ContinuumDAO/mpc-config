// sign-clipboard reads the message to sign from the clipboard, signs it with
// the Ed25519 management key from ~/.ssh/mpc_auth_ed25519 (or, if that does
// not exist, ~/.ssh/mpc_auth_bootstrap_ed25519), and writes the 128-hex
// signature back to the clipboard.
// Usage: copy the message in the app, run this binary, then paste the signature into the app.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/atotto/clipboard"
	"golang.org/x/crypto/ssh"
)

// Key file names under ~/.ssh (prefer primary, fallback to bootstrap).
const (
	keyFilePrimary   = "mpc_auth_ed25519"
	keyFileBootstrap = "mpc_auth_bootstrap_ed25519"
)

func main() {
	flagBootstrap := flag.Bool("bootstrap", false, "use only the bootstrap key (~/.ssh/mpc_auth_bootstrap_ed25519); fail if that file does not exist (use when you selected 'Bootstrap (config)' in the app)")
	flagPrimary := flag.Bool("primary", false, "use only the primary key (~/.ssh/mpc_auth_ed25519); fail if that file does not exist")
	flagKeyFile := flag.String("key-file", "", "use this key file path (e.g. ~/.ssh/mpc_auth_2_ed25519); use when you have multiple added keys and need to sign with a specific one")
	flag.Parse()
	if err := run(*flagBootstrap, *flagPrimary, *flagKeyFile); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// expandTilde expands a leading ~ to the user's home directory.
func expandTilde(path string) (string, error) {
	if path == "" || path[0] != '~' {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	if len(path) == 1 {
		return home, nil
	}
	if path[1] == '/' || path[1] == '\\' {
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

// resolveEd25519KeyPath returns the path to the private key to use. When keyFileOverride
// is non-empty, it is used (after expanding ~). Otherwise when forceBootstrap is true,
// only the bootstrap file is used; when forcePrimary is true, only the primary file;
// else prefer primary, then bootstrap (first that exists).
func resolveEd25519KeyPath(forceBootstrap, forcePrimary bool, keyFileOverride string) (string, error) {
	keyFileOverride = strings.TrimSpace(keyFileOverride)
	if keyFileOverride != "" {
		path, err := expandTilde(keyFileOverride)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("key file does not exist:\n  %s\nUse the path where you saved this key (e.g. ~/.ssh/mpc_auth_2_ed25519).", path)
		}
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	sshDir := filepath.Join(home, ".ssh")
	primary := filepath.Join(sshDir, keyFilePrimary)
	bootstrap := filepath.Join(sshDir, keyFileBootstrap)

	if forceBootstrap {
		if _, err := os.Stat(bootstrap); err != nil {
			return "", fmt.Errorf(
				"bootstrap key file does not exist:\n  %s\nYou selected 'Bootstrap (config)' in the app. Create this file or choose an added key in the app and run sign-clipboard without --bootstrap.",
				bootstrap,
			)
		}
		return bootstrap, nil
	}
	if forcePrimary {
		if _, err := os.Stat(primary); err != nil {
			return "", fmt.Errorf(
				"primary key file does not exist:\n  %s\nCreate this file (e.g. add a key in the app and save the private key here) or run without --primary to use bootstrap if present.",
				primary,
			)
		}
		return primary, nil
	}

	if _, err := os.Stat(primary); err == nil {
		return primary, nil
	}
	if _, err := os.Stat(bootstrap); err == nil {
		return bootstrap, nil
	}
	return "", fmt.Errorf(
		"Ed25519 management key file not found. Neither of these files exists:\n  - %s\n  - %s\nCreate one of them (e.g. add a key in the app and save the private key to %s).",
		primary, bootstrap, primary,
	)
}

func run(forceBootstrap, forcePrimary bool, keyFileOverride string) error {
	// Read message from clipboard
	msg, err := clipboard.ReadAll()
	if err != nil {
		return fmt.Errorf("reading clipboard: %w", err)
	}
	msg = trimBOM(msg)
	if strings.TrimSpace(msg) == "" {
		return fmt.Errorf("clipboard is empty; copy the message to sign from the app first")
	}

	keyFile, err := resolveEd25519KeyPath(forceBootstrap, forcePrimary, keyFileOverride)
	if err != nil {
		return err
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
	fmt.Println("Key used:", keyFile)
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
