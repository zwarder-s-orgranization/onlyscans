// Package lease signs the short-lived task tokens carried by NodeTask.
package lease

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type payload struct {
	RunID     string `json:"runId"`
	NodeRunID string `json:"nodeRunId"`
	NodeID    string `json:"nodeId"`
	PluginID  string `json:"pluginId"`
	Exp       int64  `json:"exp"`
}

// Sign binds a lease to one node attempt. Analyzers must not receive this token.
func Sign(key []byte, runID, nodeRunID, nodeID, pluginID string, ttl time.Duration) (string, error) {
	raw, err := json.Marshal(payload{RunID: runID, NodeRunID: nodeRunID, NodeID: nodeID, PluginID: pluginID, Exp: time.Now().Add(ttl).Unix()})
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Verify checks the signature, expiry, and the bound identifiers.
func Verify(key []byte, token, runID, nodeRunID, nodeID, pluginID string) error {
	body, sig, ok := strings.Cut(token, ".")
	if !ok || token == "" {
		return errors.New("malformed lease")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(body))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return errors.New("bad lease signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return err
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	if p.Exp < time.Now().Unix() {
		return errors.New("lease expired")
	}
	if p.RunID != runID || p.NodeRunID != nodeRunID || p.NodeID != nodeID || p.PluginID != pluginID {
		return errors.New("lease subject mismatch")
	}
	return nil
}
