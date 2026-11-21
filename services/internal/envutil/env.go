// Package envutil provides environment variable helpers shared across SecFlow services.
package envutil

import "os"

// Get returns the value of key from the environment, or fallback when unset or empty.
func Get(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
