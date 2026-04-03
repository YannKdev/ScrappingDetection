package fingerprint

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/http2/hpack"
)

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" // 24 bytes

// HTTP2Fingerprint holds parsed HTTP/2 connection parameters.
type HTTP2Fingerprint struct {
	Settings     map[uint16]uint32 // setting identifier → value
	SettingsStr  string            // wire-order pairs: "1:65536;3:1000;4:6291456"
	WindowUpdate uint32            // initial WINDOW_UPDATE increment (0 if absent)
	Raw          string            // SettingsStr + "|" + WindowUpdate

	// HeaderOrder contains header names (lowercase) in the wire order of the first
	// HEADERS frame, including pseudo-headers (:method, :path, :scheme, :authority).
	HeaderOrder []string
}

// Known HTTP/2 SETTINGS identifiers (RFC 7540 Section 6.5.2).
const (
	h2SettingsHeaderTableSize      uint16 = 0x0001
	h2SettingsEnablePush           uint16 = 0x0002
	h2SettingsMaxConcurrentStreams uint16 = 0x0003
	h2SettingsInitialWindowSize    uint16 = 0x0004
	h2SettingsMaxFrameSize         uint16 = 0x0005
	h2SettingsMaxHeaderListSize    uint16 = 0x0006
)

// HTTP/2 frame types.
const (
	h2FrameHeaders      byte = 0x01
	h2FrameSettings     byte = 0x04
	h2FrameWindowUpdate byte = 0x08
)

// HTTP/2 HEADERS frame flags.
const (
	h2FlagEndHeaders byte = 0x04
	h2FlagPadded     byte = 0x08
	h2FlagPriority   byte = 0x20
)

// ParseHTTP2Settings parses an HTTP/2 connection preface and SETTINGS frame
// from the provided byte slice. The input is typically the first ~512 bytes of
// application data on an HTTP/2 connection.
func ParseHTTP2Settings(buf []byte) (*HTTP2Fingerprint, error) {
	if len(buf) < len(h2Preface) {
		return nil, errors.New("buffer too short for H2 preface")
	}

	// Verify the HTTP/2 connection preface.
	if string(buf[:len(h2Preface)]) != h2Preface {
		return nil, errors.New("H2 preface not found")
	}

	fp := &HTTP2Fingerprint{
		Settings: make(map[uint16]uint32),
	}

	var settingsWireOrder []string
	offset := len(h2Preface)

	// Parse frames until we run out of data.
	for offset+9 <= len(buf) {
		// Frame header: 3 bytes length + 1 byte type + 1 byte flags + 4 bytes stream ID.
		payloadLen := int(buf[offset])<<16 | int(buf[offset+1])<<8 | int(buf[offset+2])
		frameType := buf[offset+3]
		frameFlags := buf[offset+4]
		// streamID := binary.BigEndian.Uint32(buf[offset+5:offset+9]) & 0x7fffffff

		offset += 9

		if offset+payloadLen > len(buf) {
			// Frame payload extends beyond our buffer — stop parsing.
			break
		}

		payload := buf[offset : offset+payloadLen]
		offset += payloadLen

		switch frameType {
		case h2FrameHeaders:
			// Only parse the first HEADERS frame (the initial request).
			if len(fp.HeaderOrder) > 0 {
				break
			}
			hpackBlock := payload

			// Strip padding if PADDED flag is set.
			if frameFlags&h2FlagPadded != 0 {
				if len(hpackBlock) < 1 {
					break
				}
				padLen := int(hpackBlock[0])
				hpackBlock = hpackBlock[1:]
				if len(hpackBlock) < padLen {
					break
				}
				hpackBlock = hpackBlock[:len(hpackBlock)-padLen]
			}

			// Strip priority fields if PRIORITY flag is set (5 bytes).
			if frameFlags&h2FlagPriority != 0 {
				if len(hpackBlock) < 5 {
					break
				}
				hpackBlock = hpackBlock[5:]
			}

			// Decode HPACK block and collect header names in order.
			var order []string
			dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
				order = append(order, f.Name)
			})
			dec.SetMaxDynamicTableSize(4096)
			if _, err := dec.Write(hpackBlock); err == nil {
				fp.HeaderOrder = order
			}

		case h2FrameSettings:
			// Ignore ACK SETTINGS frames (flags & 0x01).
			if frameFlags&0x01 != 0 {
				continue
			}
			// SETTINGS payload: each setting is 6 bytes (uint16 ID + uint32 value).
			if payloadLen%6 != 0 {
				continue
			}
			for i := 0; i+6 <= payloadLen; i += 6 {
				id := binary.BigEndian.Uint16(payload[i : i+2])
				val := binary.BigEndian.Uint32(payload[i+2 : i+6])
				fp.Settings[id] = val
				settingsWireOrder = append(settingsWireOrder, fmt.Sprintf("%d:%d", id, val))
			}

		case h2FrameWindowUpdate:
			// WINDOW_UPDATE payload: 4 bytes, MSB is reserved.
			if len(payload) == 4 {
				fp.WindowUpdate = binary.BigEndian.Uint32(payload) & 0x7fffffff
			}
		}
	}

	fp.SettingsStr = strings.Join(settingsWireOrder, ";")
	fp.Raw = fmt.Sprintf("%s|%d", fp.SettingsStr, fp.WindowUpdate)

	return fp, nil
}

// FormatHTTP2Fingerprint returns the canonical string representation of an HTTP2Fingerprint.
func FormatHTTP2Fingerprint(fp *HTTP2Fingerprint) string {
	if fp == nil {
		return ""
	}
	return fp.Raw
}

// settingName returns a human-readable name for known SETTINGS identifiers.
func settingName(id uint16) string {
	switch id {
	case h2SettingsHeaderTableSize:
		return "HEADER_TABLE_SIZE"
	case h2SettingsEnablePush:
		return "ENABLE_PUSH"
	case h2SettingsMaxConcurrentStreams:
		return "MAX_CONCURRENT_STREAMS"
	case h2SettingsInitialWindowSize:
		return "INITIAL_WINDOW_SIZE"
	case h2SettingsMaxFrameSize:
		return "MAX_FRAME_SIZE"
	case h2SettingsMaxHeaderListSize:
		return "MAX_HEADER_LIST_SIZE"
	default:
		return fmt.Sprintf("UNKNOWN_%04x", id)
	}
}

// DetailedString returns a verbose multi-line representation for debugging.
func (fp *HTTP2Fingerprint) DetailedString() string {
	if fp == nil {
		return "<nil>"
	}
	var sb strings.Builder
	sb.WriteString("HTTP/2 Fingerprint:\n")
	for id, val := range fp.Settings {
		sb.WriteString(fmt.Sprintf("  %s (%d): %d\n", settingName(id), id, val))
	}
	sb.WriteString(fmt.Sprintf("  WINDOW_UPDATE: %d\n", fp.WindowUpdate))
	return sb.String()
}
