package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type WgConfig struct {
	PrivateKey string
	Address    netip.Addr
	DNS        netip.Addr
	PublicKey  string
	Endpoint   string
	AllowedIPs string
	Keepalive  int
}

func parseConfig(path string) (*WgConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &WgConfig{Keepalive: 25}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "PrivateKey":
			cfg.PrivateKey = val
		case "Address":
			// strip CIDR if present
			addr := strings.Split(val, "/")[0]
			a, err := netip.ParseAddr(addr)
			if err != nil {
				return nil, fmt.Errorf("bad address %q: %w", val, err)
			}
			cfg.Address = a
		case "DNS":
			a, err := netip.ParseAddr(val)
			if err != nil {
				return nil, fmt.Errorf("bad dns %q: %w", val, err)
			}
			cfg.DNS = a
		case "PublicKey":
			cfg.PublicKey = val
		case "Endpoint":
			cfg.Endpoint = val
		case "AllowedIPs":
			cfg.AllowedIPs = val
		}
	}
	return cfg, scanner.Err()
}

func keyToHex(b64Key string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <path-to-wg-conf>\n", os.Args[0])
		os.Exit(1)
	}

	cfg, err := parseConfig(os.Args[1])
	if err != nil {
		log.Fatalf("parse config: %v", err)
	}

	fmt.Printf("Config loaded:\n")
	fmt.Printf("  Address:  %s\n", cfg.Address)
	fmt.Printf("  Endpoint: %s\n", cfg.Endpoint)
	fmt.Printf("  DNS:      %s\n", cfg.DNS)

	// Create userspace tun device backed by netstack (gVisor)
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{cfg.Address},
		[]netip.Addr{cfg.DNS},
		1420,
	)
	if err != nil {
		log.Fatalf("create netstack tun: %v", err)
	}

	// Create WireGuard device
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, "(wg) "))

	privHex, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		log.Fatalf("decode private key: %v", err)
	}
	pubHex, err := keyToHex(cfg.PublicKey)
	if err != nil {
		log.Fatalf("decode public key: %v", err)
	}

	// Build UAPI config
	uapi := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
allowed_ip=0.0.0.0/0
persistent_keepalive_interval=%d
`, privHex, pubHex, cfg.Endpoint, cfg.Keepalive)

	if err := dev.IpcSet(uapi); err != nil {
		log.Fatalf("ipc set: %v", err)
	}

	if err := dev.Up(); err != nil {
		log.Fatalf("device up: %v", err)
	}
	defer dev.Close()

	fmt.Println("\nWireGuard tunnel is up (userspace). Testing connectivity...")

	// Create an HTTP client that dials through the WireGuard tunnel
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
	}

	// Test: fetch our public IP through the tunnel
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		// Try plain HTTP as fallback
		fmt.Printf("HTTPS failed (%v), trying HTTP...\n", err)
		resp, err = client.Get("http://api.ipify.org")
		if err != nil {
			log.Fatalf("connectivity test failed: %v", err)
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("\nPublic IP through tunnel: %s\n", string(body))

	// Also show our real IP for comparison
	realIP := getRealIP()
	fmt.Printf("Real IP (no tunnel):     %s\n", realIP)
}

func getRealIP() string {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "(unknown)"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// Ensure net is used (for DNS resolution in the resolver)
var _ = net.Dial
