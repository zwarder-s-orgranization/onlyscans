package gradleparser

import (
	"strconv"
	"strings"
)

type versionToken struct {
	isNum bool
	num   int
	str   string
}

// Compare compares two Maven/Gradle version strings using Maven ComparableVersion
// semantics: numeric dot/dash/underscore segments, calendar versions (e.g. 20230227),
// and standard qualifiers (alpha < beta < milestone < rc < snapshot < release/final/ga/jre < sp).
// Returns -1 if a < b, 0 if a == b, or 1 if a > b.
func Compare(a, b string) int {
	ta := tokenizeVersion(a)
	tb := tokenizeVersion(b)

	n := len(ta)
	if len(tb) > n {
		n = len(tb)
	}
	for i := 0; i < n; i++ {
		if i >= len(ta) {
			if cmp := -compareTailToRelease(tb[i]); cmp != 0 {
				return cmp
			}
			continue
		}
		if i >= len(tb) {
			if cmp := compareTailToRelease(ta[i]); cmp != 0 {
				return cmp
			}
			continue
		}
		if cmp := compareToken(ta[i], tb[i]); cmp != 0 {
			return cmp
		}
	}
	return 0
}

func tokenizeVersion(v string) []versionToken {
	v = strings.TrimSpace(v)
	if v == "" {
		return []versionToken{{isNum: true, num: 0}}
	}
	var out []versionToken
	var cur strings.Builder
	curKind := 0 // 0=none, 1=digit, 2=letter

	flush := func() {
		if cur.Len() == 0 {
			return
		}
		raw := cur.String()
		cur.Reset()
		if curKind == 1 {
			n, err := strconv.Atoi(raw)
			if err != nil {
				out = append(out, versionToken{isNum: false, str: strings.ToLower(raw)})
			} else {
				out = append(out, versionToken{isNum: true, num: n})
			}
		} else {
			low := strings.ToLower(raw)
			// Neutral release/platform qualifiers (final, ga, release, jre, android) don't lower rank.
			if isNeutralQualifier(low) {
				return
			}
			out = append(out, versionToken{isNum: false, str: canonicalQualifier(low)})
		}
		curKind = 0
	}

	for i := 0; i < len(v); i++ {
		ch := v[i]
		switch {
		case ch == '.' || ch == '-' || ch == '_' || ch == '+':
			flush()
		case ch >= '0' && ch <= '9':
			if curKind == 2 {
				flush()
			}
			curKind = 1
			cur.WriteByte(ch)
		default:
			if curKind == 1 {
				flush()
			}
			curKind = 2
			cur.WriteByte(ch)
		}
	}
	flush()

	// Trim trailing numeric zeros so 1.10 == 1.10.0
	for len(out) > 1 && out[len(out)-1].isNum && out[len(out)-1].num == 0 {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return []versionToken{{isNum: true, num: 0}}
	}
	return out
}

func isNeutralQualifier(q string) bool {
	switch q {
	case "final", "ga", "release", "jre", "android", "java":
		return true
	default:
		return false
	}
}

func canonicalQualifier(q string) string {
	switch q {
	case "a", "alpha":
		return "alpha"
	case "b", "beta":
		return "beta"
	case "m", "milestone":
		return "milestone"
	case "rc", "cr":
		return "rc"
	case "snapshot":
		return "snapshot"
	case "sp":
		return "sp"
	default:
		return q
	}
}

func qualifierRank(q string) (int, bool) {
	switch q {
	case "alpha":
		return -5, true
	case "beta":
		return -4, true
	case "milestone":
		return -3, true
	case "rc":
		return -2, true
	case "snapshot":
		return -1, true
	case "sp":
		return 1, true
	default:
		return 0, false
	}
}

func compareTailToRelease(tok versionToken) int {
	if tok.isNum {
		if tok.num == 0 {
			return 0
		}
		return 1
	}
	if rank, known := qualifierRank(tok.str); known {
		if rank < 0 {
			return -1
		}
		if rank > 0 {
			return 1
		}
		return 0
	}
	// Unknown non-empty qualifier after release (e.g. -redhat-1, -sec01) sorts after base release.
	return 1
}

func compareToken(a, b versionToken) int {
	if a.isNum && b.isNum {
		if a.num < b.num {
			return -1
		}
		if a.num > b.num {
			return 1
		}
		return 0
	}
	if a.isNum && !b.isNum {
		if rank, known := qualifierRank(b.str); known && rank < 0 {
			return 1
		}
		return 1
	}
	if !a.isNum && b.isNum {
		if rank, known := qualifierRank(a.str); known && rank < 0 {
			return -1
		}
		return -1
	}
	ra, oka := qualifierRank(a.str)
	rb, okb := qualifierRank(b.str)
	if oka && okb {
		if ra < rb {
			return -1
		}
		if ra > rb {
			return 1
		}
		return 0
	}
	if oka && ra < 0 {
		return -1
	}
	if okb && rb < 0 {
		return 1
	}
	return strings.Compare(a.str, b.str)
}

// InRange reports whether version falls inside a catalog range.
// A nil or empty lower bound means negative infinity; an empty upper bound means positive infinity.
func InRange(version string, lower *string, lowerInclusive bool, upper string, upperInclusive bool) bool {
	if lower != nil && strings.TrimSpace(*lower) != "" {
		cmp := Compare(version, *lower)
		if lowerInclusive {
			if cmp < 0 {
				return false
			}
		} else if cmp <= 0 {
			return false
		}
	}
	if strings.TrimSpace(upper) == "" {
		return true
	}
	cmp := Compare(version, upper)
	if upperInclusive {
		return cmp <= 0
	}
	return cmp < 0
}
