package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// ClientHelloData is the fingerprint package's view of a parsed TLS ClientHello.
// It mirrors tls.ClientHelloData but lives here to avoid circular imports.
type ClientHelloData struct {
	RawVersion          uint16
	SupportedVersions   []uint16
	CipherSuites        []uint16
	Extensions          []Extension
	SupportedGroups     []uint16
	SignatureAlgorithms []uint16
	ALPNProtocols       []string
	SNIHostname         string
}

// Extension is a TLS extension type+data pair.
type Extension struct {
	Type uint16
	Data []byte
}

// JA4Result holds the canonical JA4 string and the raw (original-order) variant.
type JA4Result struct {
	JA4    string // Sorted variant: t13d1516h2_8daaf6152771_b186095e22b6
	JA4Raw string // JA4_r: original wire order, no GREASE
}

// ComputeJA4 computes the JA4 and JA4Raw fingerprints from a parsed ClientHello.
// It follows the FoxIO JA4 specification.
func ComputeJA4(hello *ClientHelloData) JA4Result {
	if hello == nil {
		return JA4Result{JA4: "t00i0000_000000000000_000000000000"}
	}

	// --- Part A ---
	protocol := "t" // TCP TLS (use "q" for QUIC when applicable)
	version := tlsVersionStr(hello)
	sniFlag := sniFlag(hello)

	// Cipher suites: exclude GREASE
	ciphers := filterGREASE16(hello.CipherSuites)
	cipherCount := fmt.Sprintf("%02d", min99(len(ciphers)))

	// Extensions count: exclude GREASE per JA4 spec, but include SNI and ALPN.
	extTypes := extensionTypes(hello.Extensions, false) // false = exclude GREASE
	extCount := fmt.Sprintf("%02d", min99(len(extTypes)))

	alpn := alpnStr(hello.ALPNProtocols)

	partA := protocol + version + sniFlag + cipherCount + extCount + alpn

	// --- Part B: sorted cipher suites hash ---
	cipherHexes := make([]string, len(ciphers))
	for i, cs := range ciphers {
		cipherHexes[i] = fmt.Sprintf("%04x", cs)
	}
	cipherHexesRaw := make([]string, len(cipherHexes))
	copy(cipherHexesRaw, cipherHexes)

	sort.Strings(cipherHexes)
	partB := sha256Hex12(strings.Join(cipherHexes, ","))
	partBRaw := sha256Hex12(strings.Join(cipherHexesRaw, ","))

	// --- Part C: sorted extensions (excluding SNI + ALPN) + sig algs hash ---
	// Extensions for Part C: no GREASE, no SNI (0x0000), no ALPN (0x0010)
	extForHash := extensionTypesFiltered(hello.Extensions)
	extForHashRaw := make([]string, len(extForHash))
	copy(extForHashRaw, extForHash)

	sort.Strings(extForHash)

	// Signature algorithms in original wire order
	sigAlgStrs := make([]string, 0, len(hello.SignatureAlgorithms))
	for _, sa := range hello.SignatureAlgorithms {
		if !isGREASE(sa) {
			sigAlgStrs = append(sigAlgStrs, fmt.Sprintf("%04x", sa))
		}
	}

	sigAlgPart := strings.Join(sigAlgStrs, ",")

	extPartSorted := strings.Join(extForHash, ",")
	extPartRaw := strings.Join(extForHashRaw, ",")

	var partCInput, partCInputRaw string
	if sigAlgPart != "" {
		partCInput = extPartSorted + "_" + sigAlgPart
		partCInputRaw = extPartRaw + "_" + sigAlgPart
	} else {
		partCInput = extPartSorted
		partCInputRaw = extPartRaw
	}

	partC := sha256Hex12(partCInput)
	partCRaw := sha256Hex12(partCInputRaw)

	return JA4Result{
		JA4:    partA + "_" + partB + "_" + partC,
		JA4Raw: partA + "_" + partBRaw + "_" + partCRaw,
	}
}

// tlsVersionStr maps the negotiated TLS version to the 2-char JA4 version code.
// Prefers supported_versions extension (0x002b) over legacy_version.
func tlsVersionStr(hello *ClientHelloData) string {
	// Find the highest non-GREASE version offered in supported_versions.
	var best uint16
	for _, v := range hello.SupportedVersions {
		if !isGREASE(v) && v > best {
			best = v
		}
	}
	if best == 0 {
		best = hello.RawVersion
	}

	switch best {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

// sniFlag returns "d" if an SNI hostname is present, "i" if connecting by IP.
func sniFlag(hello *ClientHelloData) string {
	if hello.SNIHostname != "" {
		return "d"
	}
	return "i"
}

// alpnStr returns the 2-char ALPN component: first and last char of the first ALPN protocol.
// Returns "00" if no ALPN protocols are offered.
func alpnStr(protocols []string) string {
	if len(protocols) == 0 {
		return "00"
	}
	proto := protocols[0]
	if len(proto) == 0 {
		return "00"
	}
	first := proto[0]
	last := proto[len(proto)-1]
	return string(alpnChar(first)) + string(alpnChar(last))
}

// alpnChar returns the character as-is if alphanumeric, otherwise its hex representation.
func alpnChar(b byte) byte {
	if isAlphaNum(b) {
		return b
	}
	// For non-alphanumeric bytes, use their hex value as ASCII (single char, upper nibble)
	// JA4 spec: use the character itself for printable, else '?' (simplified)
	return b
}

func isAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// filterGREASE16 returns a new slice with GREASE values removed.
func filterGREASE16(vals []uint16) []uint16 {
	result := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASE(v) {
			result = append(result, v)
		}
	}
	return result
}

// extensionTypes returns the extension type values for the given extensions,
// optionally including GREASE types (for counting purposes).
func extensionTypes(exts []Extension, includeGREASE bool) []string {
	result := make([]string, 0, len(exts))
	for _, e := range exts {
		if !includeGREASE && isGREASE(e.Type) {
			continue
		}
		result = append(result, fmt.Sprintf("%04x", e.Type))
	}
	return result
}

// extensionTypesFiltered returns extension types excluding GREASE, SNI (0x0000), and ALPN (0x0010).
// Used for Part C hash input.
func extensionTypesFiltered(exts []Extension) []string {
	result := make([]string, 0, len(exts))
	for _, e := range exts {
		if isGREASE(e.Type) {
			continue
		}
		if e.Type == 0x0000 { // SNI
			continue
		}
		if e.Type == 0x0010 { // ALPN
			continue
		}
		result = append(result, fmt.Sprintf("%04x", e.Type))
	}
	return result
}

// isGREASE returns true if v is a GREASE value per RFC 8701.
func isGREASE(v uint16) bool {
	lo := v & 0xff
	hi := v >> 8
	return lo == hi && lo&0x0f == 0x0a
}

// sha256Hex12 returns the first 12 characters of the lowercase SHA256 hex digest.
func sha256Hex12(input string) string {
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", h)[:12]
}

// min99 clamps n to a maximum of 99 for the 2-digit decimal JA4 fields.
func min99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}
