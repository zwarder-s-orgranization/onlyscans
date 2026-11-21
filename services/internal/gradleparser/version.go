package gradleparser

import (
	"strconv"
	"strings"
)

// Compare returns -1, 0, or 1 for numeric-dot-separated versions,
// including calendar versions such as 20230227.
func Compare(a, b string) int {
	ap := splitVersion(a)
	bp := splitVersion(b)
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	v = strings.TrimSpace(v)
	if v == "" {
		return []int{0}
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}

// InRange reports whether version falls inside a catalog range.
// A nil lower bound means negative infinity.
func InRange(version string, lower *string, lowerInclusive bool, upper string, upperInclusive bool) bool {
	if lower != nil {
		cmp := Compare(version, *lower)
		if lowerInclusive {
			if cmp < 0 {
				return false
			}
		} else if cmp <= 0 {
			return false
		}
	}
	cmp := Compare(version, upper)
	if upperInclusive {
		return cmp <= 0
	}
	return cmp < 0
}
