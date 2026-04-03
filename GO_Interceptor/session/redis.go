package session

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	tlsi "scrappingdetection/go-interceptor/tls"
)

const (
	sessionTTL = 30 * time.Minute // matches cookie TTL
	ja4TTL     = 1 * time.Hour    // JA4 index lives longer than individual sessions
	keyPrefix  = "session:"
	ja4Prefix  = "ja4:"
)

// Store wraps a Redis client with session-oriented operations.
type Store struct {
	rdb *redis.Client
}

// NewStore connects to Redis and returns a Store.
// url format: "redis://:password@host:port/db" or "redis://host:port"
func NewStore(url string) (*Store, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("invalid REDIS_URL: %w", err)
	}

	rdb := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	return &Store{rdb: rdb}, nil
}

// Close closes the underlying Redis connection.
func (s *Store) Close() error {
	return s.rdb.Close()
}

// SessionData is the full session record stored in Redis.
type SessionData struct {
	// Network fingerprints (set on first request)
	JA4          string `json:"ja4"`
	JA4Raw       string `json:"ja4_raw"`
	HTTP2        string `json:"http2"`
	TLSJson      string `json:"tls_json"`
	ClientIP     string `json:"client_ip"`

	// Lifecycle
	FirstSeen    int64  `json:"first_seen"`    // unix timestamp
	LastSeen     int64  `json:"last_seen"`
	RequestCount int64  `json:"request_count"`

	// Anomaly signals (incremented by detection layers)
	Score        int64  `json:"score"`           // 0 = clean, higher = more suspicious
	TLSChanged   bool   `json:"tls_changed"`     // JA4 mismatch detected on subsequent request
}

// StoreFingerprint creates a new session record from a connection fingerprint.
// Should be called on first request (no existing valid cookie).
func (s *Store) StoreFingerprint(ctx context.Context, uuid string, fp *tlsi.ConnectionFingerprint) error {
	now := time.Now().Unix()

	data := map[string]interface{}{
		"ja4":           fp.JA4,
		"ja4_raw":       fp.JA4Raw,
		"http2":         fp.HTTP2FingerprintStr(),
		"tls_json":      fp.TLSFingerprintJSON(),
		"client_ip":     fp.ClientIP,
		"first_seen":    now,
		"last_seen":     now,
		"request_count": 1,
		"score":         0,
		"tls_changed":   false,
	}

	key := keyPrefix + uuid
	pipe := s.rdb.Pipeline()
	pipe.HSet(ctx, key, data)
	pipe.Expire(ctx, key, sessionTTL)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("StoreFingerprint: %w", err)
	}

	// Secondary index: JA4 → set of session UUIDs (for mass detection).
	if fp.JA4 != "" {
		s.addJA4Index(ctx, fp.JA4, uuid)
	}

	return nil
}

// GetSession retrieves the session data for the given UUID.
// Returns nil, nil if the key does not exist.
func (s *Store) GetSession(ctx context.Context, uuid string) (*SessionData, error) {
	key := keyPrefix + uuid
	vals, err := s.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("GetSession: %w", err)
	}
	if len(vals) == 0 {
		return nil, nil // session not found / expired
	}

	sd := &SessionData{
		JA4:      vals["ja4"],
		JA4Raw:   vals["ja4_raw"],
		HTTP2:    vals["http2"],
		TLSJson:  vals["tls_json"],
		ClientIP: vals["client_ip"],
	}
	sd.FirstSeen, _ = strconv.ParseInt(vals["first_seen"], 10, 64)
	sd.LastSeen, _ = strconv.ParseInt(vals["last_seen"], 10, 64)
	sd.RequestCount, _ = strconv.ParseInt(vals["request_count"], 10, 64)
	sd.Score, _ = strconv.ParseInt(vals["score"], 10, 64)
	sd.TLSChanged, _ = strconv.ParseBool(vals["tls_changed"])

	return sd, nil
}

// Touch updates last_seen, increments request_count, and refreshes TTL.
// Returns the new request count.
func (s *Store) Touch(ctx context.Context, uuid string) (int64, error) {
	key := keyPrefix + uuid
	pipe := s.rdb.Pipeline()
	incrCmd := pipe.HIncrBy(ctx, key, "request_count", 1)
	pipe.HSet(ctx, key, "last_seen", time.Now().Unix())
	pipe.Expire(ctx, key, sessionTTL)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("Touch: %w", err)
	}
	return incrCmd.Val(), nil
}

// FlagTLSChange marks the session as having a TLS fingerprint mismatch
// and increments the suspicion score.
func (s *Store) FlagTLSChange(ctx context.Context, uuid string, newJA4 string) error {
	key := keyPrefix + uuid
	pipe := s.rdb.Pipeline()
	pipe.HSet(ctx, key, "tls_changed", true)
	pipe.HSet(ctx, key, "ja4_seen_new", newJA4)
	pipe.HIncrBy(ctx, key, "score", 10) // TLS mismatch is a strong signal
	_, err := pipe.Exec(ctx)
	return err
}

// IncrScore adds delta to the session suspicion score.
func (s *Store) IncrScore(ctx context.Context, uuid string, delta int64) (int64, error) {
	return s.rdb.HIncrBy(ctx, keyPrefix+uuid, "score", delta).Result()
}

// JA4SessionCount returns how many distinct sessions share the given JA4 fingerprint.
// A high count indicates a bot farm using the same TLS stack.
func (s *Store) JA4SessionCount(ctx context.Context, ja4 string) (int64, error) {
	return s.rdb.SCard(ctx, ja4Prefix+ja4).Result()
}

// addJA4Index adds uuid to the JA4 reverse-lookup set.
func (s *Store) addJA4Index(ctx context.Context, ja4, uuid string) {
	key := ja4Prefix + ja4
	pipe := s.rdb.Pipeline()
	pipe.SAdd(ctx, key, uuid)
	pipe.Expire(ctx, key, ja4TTL)
	pipe.Exec(ctx) // best-effort, ignore error
}

// ToJSON serialises SessionData to a compact JSON string (for logging / headers).
func (sd *SessionData) ToJSON() string {
	b, _ := json.Marshal(sd)
	return string(b)
}