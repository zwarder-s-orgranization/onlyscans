package gradleparser

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultOSVMavenZipURL is the official public OSV Maven ecosystem vulnerability dump (CC BY 4.0).
	DefaultOSVMavenZipURL = "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip"
	// DefaultOSVAPIBaseURL is the official public OSV.dev REST API base URL.
	DefaultOSVAPIBaseURL = "https://api.osv.dev"

	maxOSVFeedBytes   = 64 << 20 // 64 MiB
	maxOSVEntryBytes  = 4 << 20  // 4 MiB per advisory JSON inside ZIP
	osvBatchChunkSize = 500
	osvDetailWorkers  = 8
)

var osvHTTPClient = &http.Client{Timeout: 90 * time.Second}

type osvRecord struct {
	ID               string            `json:"id"`
	Withdrawn        string            `json:"withdrawn"`
	Aliases          []string          `json:"aliases"`
	Severity         []osvSeverityItem `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []osvAffected `json:"affected"`
}

type osvSeverityItem struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

type exportedCatalog struct {
	FormatVersion   int              `json:"formatVersion"`
	Ecosystem       string           `json:"ecosystem"`
	VersionFormat   string           `json:"versionFormat"`
	Snapshot        exportedSnapshot `json:"snapshot"`
	Vulnerabilities []exportedVuln   `json:"vulnerabilities"`
}

type exportedSnapshot struct {
	Date       string `json:"date"`
	URL        string `json:"url"`
	SHA256     string `json:"sha256"`
	Advisories string `json:"advisories"`
}

type exportedVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Group    string   `json:"group"`
	Artifact string   `json:"artifact"`
	Severity string   `json:"severity"`
	Ranges   []Range  `json:"ranges"`
}

// FetchOSVMavenCatalog downloads the live Maven vulnerability database from feedURL
// (defaulting to DefaultOSVMavenZipURL when empty) and converts it into a SecFlow
// vulnerability catalog JSON payload ready for Garage storage and gradleparser.LoadCatalogBytes.
func FetchOSVMavenCatalog(ctx context.Context, feedURL string) ([]byte, int, error) {
	return fetchOSVMavenCatalogWithClient(ctx, osvHTTPClient, feedURL)
}

func fetchOSVMavenCatalogWithClient(ctx context.Context, client *http.Client, feedURL string) ([]byte, int, error) {
	target := strings.TrimSpace(feedURL)
	if target == "" {
		target = DefaultOSVMavenZipURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build OSV catalog request: %w", err)
	}
	req.Header.Set("User-Agent", "SecFlow-SCA/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("download OSV catalog %s: %w", target, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, 0, fmt.Errorf("download OSV catalog %s: HTTP %d: %s", target, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOSVFeedBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read OSV catalog %s: %w", target, err)
	}
	if len(raw) > maxOSVFeedBytes {
		return nil, 0, fmt.Errorf("OSV catalog %s exceeds %d byte limit", target, maxOSVFeedBytes)
	}
	if len(raw) == 0 {
		return nil, 0, fmt.Errorf("OSV catalog %s returned empty body", target)
	}

	// Direct JSON catalog feed (SecFlow format)
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		advs, perr := LoadCatalogBytes(raw)
		if perr != nil {
			return nil, 0, fmt.Errorf("parse JSON catalog feed %s: %w", target, perr)
		}
		return raw, len(advs), nil
	}

	// OSV Maven ZIP dump (e.g. https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip)
	return parseOSVZipCatalog(raw, target)
}

func parseOSVZipCatalog(zipBytes []byte, sourceURL string) ([]byte, int, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, 0, fmt.Errorf("open OSV zip archive: %w", err)
	}

	var vulns []exportedVuln
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			continue
		}
		entryBytes, rerr := io.ReadAll(io.LimitReader(rc, maxOSVEntryBytes))
		_ = rc.Close()
		if rerr != nil || len(entryBytes) == 0 {
			continue
		}
		var rec osvRecord
		if jerr := json.Unmarshal(entryBytes, &rec); jerr != nil {
			continue
		}
		vulns = append(vulns, convertOSVRecord(rec)...)
	}
	if len(vulns) == 0 {
		return nil, 0, fmt.Errorf("OSV zip archive %s contained no Maven advisories", sourceURL)
	}

	sort.Slice(vulns, func(i, j int) bool {
		if vulns[i].Group != vulns[j].Group {
			return vulns[i].Group < vulns[j].Group
		}
		if vulns[i].Artifact != vulns[j].Artifact {
			return vulns[i].Artifact < vulns[j].Artifact
		}
		return vulns[i].ID < vulns[j].ID
	})

	sum := sha256.Sum256(zipBytes)
	doc := exportedCatalog{
		FormatVersion: 1,
		Ecosystem:     "Maven",
		VersionFormat: "maven-comparable",
		Snapshot: exportedSnapshot{
			Date:       time.Now().UTC().Format("2006-01-02"),
			URL:        sourceURL,
			SHA256:     hex.EncodeToString(sum[:]),
			Advisories: "OSV / GitHub Advisory Database (CC BY 4.0)",
		},
		Vulnerabilities: vulns,
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal converted OSV catalog: %w", err)
	}
	return out, len(vulns), nil
}

func convertOSVRecord(rec osvRecord) []exportedVuln {
	if strings.TrimSpace(rec.ID) == "" || strings.TrimSpace(rec.Withdrawn) != "" {
		return nil
	}
	sev := normalizeOSVSeverity(rec)
	type pkgKey struct{ group, artifact string }
	rangesByPkg := make(map[pkgKey][]Range)

	for _, aff := range rec.Affected {
		if !strings.EqualFold(strings.TrimSpace(aff.Package.Ecosystem), "Maven") {
			continue
		}
		group, artifact, ok := strings.Cut(strings.TrimSpace(aff.Package.Name), ":")
		if !ok || group == "" || artifact == "" {
			continue
		}
		pk := pkgKey{group: group, artifact: artifact}
		ranges := convertOSVRanges(aff.Ranges, aff.Versions)
		if len(ranges) == 0 {
			continue
		}
		rangesByPkg[pk] = append(rangesByPkg[pk], ranges...)
	}

	if len(rangesByPkg) == 0 {
		return nil
	}
	out := make([]exportedVuln, 0, len(rangesByPkg))
	for pk, ranges := range rangesByPkg {
		out = append(out, exportedVuln{
			ID:       strings.TrimSpace(rec.ID),
			Aliases:  rec.Aliases,
			Group:    pk.group,
			Artifact: pk.artifact,
			Severity: sev,
			Ranges:   ranges,
		})
	}
	return out
}

func convertOSVRanges(osvRanges []osvRange, explicitVersions []string) []Range {
	var out []Range
	for _, r := range osvRanges {
		if r.Type != "" && !strings.EqualFold(r.Type, "ECOSYSTEM") && !strings.EqualFold(r.Type, "SEMVER") {
			continue
		}
		var curLower *string
		hasOpen := false
		for _, ev := range r.Events {
			if ev.Introduced != "" {
				// If a previous range was left open, close it as unbounded.
				if hasOpen {
					out = append(out, Range{Lower: curLower, LowerInclusive: true, Upper: "", UpperInclusive: false})
				}
				intro := strings.TrimSpace(ev.Introduced)
				if intro == "0" {
					curLower = nil
				} else {
					v := intro
					curLower = &v
				}
				hasOpen = true
			}
			if ev.Fixed != "" && hasOpen {
				out = append(out, Range{
					Lower:          curLower,
					LowerInclusive: true,
					Upper:          strings.TrimSpace(ev.Fixed),
					UpperInclusive: false,
				})
				hasOpen = false
				curLower = nil
			} else if ev.LastAffected != "" && hasOpen {
				out = append(out, Range{
					Lower:          curLower,
					LowerInclusive: true,
					Upper:          strings.TrimSpace(ev.LastAffected),
					UpperInclusive: true,
				})
				hasOpen = false
				curLower = nil
			} else if ev.Limit != "" && hasOpen {
				out = append(out, Range{
					Lower:          curLower,
					LowerInclusive: true,
					Upper:          strings.TrimSpace(ev.Limit),
					UpperInclusive: false,
				})
				hasOpen = false
				curLower = nil
			}
		}
		if hasOpen {
			out = append(out, Range{Lower: curLower, LowerInclusive: true, Upper: "", UpperInclusive: false})
		}
	}
	if len(out) == 0 && len(explicitVersions) > 0 {
		for _, v := range explicitVersions {
			ver := strings.TrimSpace(v)
			if ver == "" {
				continue
			}
			low := ver
			out = append(out, Range{Lower: &low, LowerInclusive: true, Upper: ver, UpperInclusive: true})
		}
	}
	return out
}

func normalizeOSVSeverity(rec osvRecord) string {
	switch strings.ToUpper(strings.TrimSpace(rec.DatabaseSpecific.Severity)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MODERATE", "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	}
	for _, s := range rec.Severity {
		score := strings.ToUpper(strings.TrimSpace(s.Score))
		if strings.HasPrefix(score, "CVSS:3.") || strings.HasPrefix(score, "CVSS:4.") {
			// Without a full CVSS calculator, default to HIGH for network/no-priv vectors, MEDIUM otherwise.
			if strings.Contains(score, "AV:N") && strings.Contains(score, "C:H") && strings.Contains(score, "I:H") && strings.Contains(score, "A:H") {
				return "CRITICAL"
			}
			if strings.Contains(score, "AV:N") && (strings.Contains(score, "C:H") || strings.Contains(score, "I:H") || strings.Contains(score, "A:H")) {
				return "HIGH"
			}
			return "MEDIUM"
		}
	}
	return "MEDIUM"
}

// QueryOSVLive queries the live OSV.dev API (/v1/querybatch + /v1/vulns/{id})
// directly for the given resolved Maven/Gradle dependencies.
func QueryOSVLive(ctx context.Context, deps []Dependency, apiBaseURL string) ([]Finding, error) {
	return queryOSVLiveWithClient(ctx, osvHTTPClient, deps, apiBaseURL)
}

func queryOSVLiveWithClient(ctx context.Context, client *http.Client, deps []Dependency, apiBaseURL string) ([]Finding, error) {
	if len(deps) == 0 {
		return nil, nil
	}
	base := strings.TrimRight(strings.TrimSpace(apiBaseURL), "/")
	if base == "" {
		base = DefaultOSVAPIBaseURL
	}

	type osvQueryPkg struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	}
	type osvQuery struct {
		Version string      `json:"version"`
		Package osvQueryPkg `json:"package"`
	}
	type osvBatchReq struct {
		Queries []osvQuery `json:"queries"`
	}
	type osvBatchResp struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}

	// Map dep index -> matched raw OSV IDs
	matchedIDsByDep := make([][]string, len(deps))
	uniqueVulnIDs := map[string]struct{}{}

	for start := 0; start < len(deps); start += osvBatchChunkSize {
		end := min(start+osvBatchChunkSize, len(deps))
		queries := make([]osvQuery, 0, end-start)
		for _, d := range deps[start:end] {
			queries = append(queries, osvQuery{
				Version: d.Version,
				Package: osvQueryPkg{
					Name:      d.Group + ":" + d.Artifact,
					Ecosystem: "Maven",
				},
			})
		}
		payload, err := json.Marshal(osvBatchReq{Queries: queries})
		if err != nil {
			return nil, fmt.Errorf("marshal OSV batch request: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/querybatch", bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("build OSV querybatch request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SecFlow-SCA/1.0")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("call OSV querybatch: %w", err)
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		_ = resp.Body.Close()
		if rerr != nil {
			return nil, fmt.Errorf("read OSV querybatch response: %w", rerr)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OSV querybatch HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		var batchResp osvBatchResp
		if err := json.Unmarshal(raw, &batchResp); err != nil {
			return nil, fmt.Errorf("decode OSV querybatch response: %w", err)
		}
		for i, res := range batchResp.Results {
			if start+i >= len(deps) {
				break
			}
			for _, v := range res.Vulns {
				id := strings.TrimSpace(v.ID)
				if id == "" {
					continue
				}
				matchedIDsByDep[start+i] = append(matchedIDsByDep[start+i], id)
				uniqueVulnIDs[id] = struct{}{}
			}
		}
	}

	if len(uniqueVulnIDs) == 0 {
		return nil, nil
	}

	// Fetch details (CVE aliases + severity) for unique matched IDs with bounded concurrency.
	type vulnMeta struct {
		advisoryID string
		severity   string
		withdrawn  bool
	}
	metaByID := make(map[string]vulnMeta, len(uniqueVulnIDs))
	var mu sync.Mutex

	ids := make([]string, 0, len(uniqueVulnIDs))
	for id := range uniqueVulnIDs {
		ids = append(ids, id)
	}
	jobs := make(chan string, len(ids))
	for _, id := range ids {
		jobs <- id
	}
	close(jobs)

	workers := min(osvDetailWorkers, len(ids))
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for id := range jobs {
				if ctx.Err() != nil {
					return
				}
				meta := vulnMeta{advisoryID: id, severity: "MEDIUM"}
				u := base + "/v1/vulns/" + url.PathEscape(id)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				if err == nil {
					req.Header.Set("User-Agent", "SecFlow-SCA/1.0")
					if resp, doErr := client.Do(req); doErr == nil {
						body, _ := io.ReadAll(io.LimitReader(resp.Body, maxOSVEntryBytes))
						_ = resp.Body.Close()
						if resp.StatusCode == http.StatusOK {
							var rec osvRecord
							if json.Unmarshal(body, &rec) == nil {
								meta.withdrawn = strings.TrimSpace(rec.Withdrawn) != ""
								meta.advisoryID = preferCVE(Advisory{ID: rec.ID, Aliases: rec.Aliases})
								meta.severity = normalizeOSVSeverity(rec)
							}
						}
					}
				}
				mu.Lock()
				metaByID[id] = meta
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	seen := make(map[string]struct{})
	var out []Finding
	for idx, dep := range deps {
		for _, rawID := range matchedIDsByDep[idx] {
			meta := metaByID[rawID]
			if meta.withdrawn {
				continue
			}
			advID := meta.advisoryID
			if advID == "" {
				advID = rawID
			}
			key := dep.Path + "|" + dep.Group + ":" + dep.Artifact + ":" + dep.Version + "|" + advID
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Finding{
				Group:      dep.Group,
				Artifact:   dep.Artifact,
				Version:    dep.Version,
				Path:       dep.Path,
				Line:       dep.Line,
				AdvisoryID: advID,
				Severity:   meta.severity,
			})
		}
	}
	return out, nil
}
