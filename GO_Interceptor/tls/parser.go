package tlsinterceptor

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// ParseClientHello parses a raw TLS record containing a ClientHello handshake message.
// The input must be the complete TLS record: 5-byte header + handshake payload.
func ParseClientHello(record []byte) (*ClientHelloData, error) {
	if len(record) < 5 {
		return nil, errors.New("record too short")
	}

	// Validate TLS Handshake record type (0x16).
	if record[0] != 0x16 {
		return nil, errors.New("not a TLS handshake record")
	}

	// The payload starts after the 5-byte record header.
	payload := record[5:]
	if len(payload) < 4 {
		return nil, errors.New("handshake payload too short")
	}

	// Validate ClientHello handshake type (0x01).
	if payload[0] != 0x01 {
		return nil, errors.New("not a ClientHello handshake message")
	}

	// Skip the 3-byte handshake message length (bytes 1-3 of payload).
	// The ClientHello body starts at offset 4.
	s := cryptobyte.String(payload[4:])

	hello := &ClientHelloData{}

	// legacy_version (2 bytes).
	if !s.ReadUint16(&hello.RawVersion) {
		return nil, errors.New("failed to read legacy_version")
	}

	// random (32 bytes) — discard.
	var random []byte
	if !s.ReadBytes(&random, 32) {
		return nil, errors.New("failed to read random")
	}

	// session_id (1-byte length prefix + data) — discard.
	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return nil, errors.New("failed to read session_id")
	}

	// cipher_suites (2-byte length prefix + list of uint16).
	var cipherSuitesRaw cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuitesRaw) {
		return nil, errors.New("failed to read cipher_suites")
	}
	for !cipherSuitesRaw.Empty() {
		var cs uint16
		if !cipherSuitesRaw.ReadUint16(&cs) {
			break
		}
		hello.CipherSuites = append(hello.CipherSuites, cs)
	}

	// compression_methods (1-byte length prefix + list of uint8) — store but rarely used.
	var compressionRaw cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compressionRaw) {
		return nil, errors.New("failed to read compression_methods")
	}
	for !compressionRaw.Empty() {
		var cm uint8
		if !compressionRaw.ReadUint8(&cm) {
			break
		}
		hello.CompressionMethods = append(hello.CompressionMethods, cm)
	}

	// Extensions block (2-byte length prefix) — optional in TLS 1.2, required in TLS 1.3.
	if s.Empty() {
		return hello, nil
	}

	var extensionsRaw cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensionsRaw) {
		return nil, errors.New("failed to read extensions")
	}

	for !extensionsRaw.Empty() {
		var extType uint16
		var extData cryptobyte.String

		if !extensionsRaw.ReadUint16(&extType) {
			break
		}
		if !extensionsRaw.ReadUint16LengthPrefixed(&extData) {
			break
		}

		extBytes := []byte(extData)
		hello.Extensions = append(hello.Extensions, Extension{Type: extType, Data: extBytes})

		// Dispatch to specific extension parsers.
		switch extType {
		case 0x0000: // server_name
			hello.SNIHostname = parseSNI(extBytes)
		case 0x000a: // supported_groups (elliptic curves)
			hello.SupportedGroups = parseUint16List(extBytes)
		case 0x000d: // signature_algorithms
			hello.SignatureAlgorithms = parseUint16List(extBytes)
		case 0x0010: // application_layer_protocol_negotiation
			hello.ALPNProtocols = parseALPN(extBytes)
		case 0x002b: // supported_versions
			hello.SupportedVersions = parseSupportedVersions(extBytes)
		}
	}

	return hello, nil
}

// parseSNI extracts the server name from the SNI extension data.
// Extension 0x0000 structure: uint16 list_length, then entries of (uint8 nameType, uint16LengthPrefixed name).
func parseSNI(data []byte) string {
	s := cryptobyte.String(data)
	var serverNameList cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&serverNameList) {
		return ""
	}
	for !serverNameList.Empty() {
		var nameType uint8
		if !serverNameList.ReadUint8(&nameType) {
			break
		}
		var name cryptobyte.String
		if !serverNameList.ReadUint16LengthPrefixed(&name) {
			break
		}
		if nameType == 0x00 { // host_name
			return string(name)
		}
	}
	return ""
}

// parseUint16List parses an extension whose payload is: uint16 list_length, then uint16 values.
// Used for supported_groups and signature_algorithms.
func parseUint16List(data []byte) []uint16 {
	s := cryptobyte.String(data)
	var listRaw cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&listRaw) {
		return nil
	}
	var result []uint16
	for !listRaw.Empty() {
		var v uint16
		if !listRaw.ReadUint16(&v) {
			break
		}
		result = append(result, v)
	}
	return result
}

// parseALPN extracts protocol names from the ALPN extension data.
// Structure: uint16 protocol_name_list_length, then uint8LengthPrefixed protocol_names.
func parseALPN(data []byte) []string {
	s := cryptobyte.String(data)
	var protocolList cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&protocolList) {
		return nil
	}
	var result []string
	for !protocolList.Empty() {
		var proto cryptobyte.String
		if !protocolList.ReadUint8LengthPrefixed(&proto) {
			break
		}
		result = append(result, string(proto))
	}
	return result
}

// parseSupportedVersions extracts TLS versions from extension 0x002b.
// In a ClientHello, the structure is: uint8 list_length, then uint16 versions.
func parseSupportedVersions(data []byte) []uint16 {
	s := cryptobyte.String(data)
	var listRaw cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&listRaw) {
		return nil
	}
	var result []uint16
	for !listRaw.Empty() {
		var v uint16
		if !listRaw.ReadUint16(&v) {
			break
		}
		result = append(result, v)
	}
	return result
}
