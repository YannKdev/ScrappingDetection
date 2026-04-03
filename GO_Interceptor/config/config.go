package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"time"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	ListenAddr     string // LISTEN_ADDR, default ":8443"
	UpstreamURL    string // UPSTREAM_URL, required
	TLSCert        string // TLS_CERT path to PEM cert file
	TLSKey         string // TLS_KEY path to PEM key file
	RedisURL       string // REDIS_URL, optional (sessions disabled if empty)
	SessionSecret  string // SESSION_SECRET for HMAC cookie signing (auto-generated if empty)
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:    getEnv("LISTEN_ADDR", ":8443"),
		UpstreamURL:   os.Getenv("UPSTREAM_URL"),
		TLSCert:       os.Getenv("TLS_CERT"),
		TLSKey:        os.Getenv("TLS_KEY"),
		RedisURL:      os.Getenv("REDIS_URL"),
		SessionSecret: os.Getenv("SESSION_SECRET"),
	}

	if cfg.UpstreamURL == "" {
		return nil, errors.New("UPSTREAM_URL environment variable is required")
	}

	return cfg, nil
}

// LoadTLSCertificate loads a TLS certificate from files or generates a self-signed one.
func LoadTLSCertificate(cfg *Config) (tls.Certificate, error) {
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		return tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	}
	return GenerateSelfSignedCert()
}

// GenerateSelfSignedCert generates a self-signed ECDSA P-256 certificate valid for 1 year.
// The certificate covers localhost and 127.0.0.1 as SANs.
func GenerateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"ScrappingDetection Dev"},
		},
		DNSNames:  []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
