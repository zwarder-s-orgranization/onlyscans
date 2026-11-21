package protoconv

import (
	"testing"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
)

func TestSeverityProtoAndRank(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want secflowv1.Severity
		rank int
	}{
		{name: "critical", in: "critical", want: secflowv1.Severity_SEVERITY_CRITICAL, rank: 5},
		{name: "high", in: "HIGH", want: secflowv1.Severity_SEVERITY_HIGH, rank: 4},
		{name: "medium", in: "Medium", want: secflowv1.Severity_SEVERITY_MEDIUM, rank: 3},
		{name: "low", in: "low", want: secflowv1.Severity_SEVERITY_LOW, rank: 2},
		{name: "unknown", in: "bogus", want: secflowv1.Severity_SEVERITY_UNSPECIFIED, rank: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := SeverityProto(tc.in); got != tc.want {
				t.Fatalf("SeverityProto(%q) = %v, want %v", tc.in, got, tc.want)
			}
			if got := SeverityRank(tc.in); got != tc.rank {
				t.Fatalf("SeverityRank(%q) = %d, want %d", tc.in, got, tc.rank)
			}
		})
	}
}

func TestCategoryProto(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want secflowv1.FindingCategory
	}{
		{name: "secret", in: "secret", want: secflowv1.FindingCategory_FINDING_CATEGORY_SECRET},
		{name: "sca", in: "SCA", want: secflowv1.FindingCategory_FINDING_CATEGORY_SCA},
		{name: "sast", in: "sast", want: secflowv1.FindingCategory_FINDING_CATEGORY_SAST},
		{name: "other", in: "", want: secflowv1.FindingCategory_FINDING_CATEGORY_UNSPECIFIED},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := CategoryProto(tc.in); got != tc.want {
				t.Fatalf("CategoryProto(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
