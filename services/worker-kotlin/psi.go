package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/secflow/secflow/services/internal/kotlinscan"
)

func parseFilterParams(raw []byte) kotlinscan.FilterOptions {
	if len(raw) == 0 {
		return kotlinscan.FilterOptions{}
	}
	var opts kotlinscan.FilterOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		return kotlinscan.FilterOptions{}
	}
	return opts
}

func scanTree(ctx context.Context, plugin, root string, paramsRaw []byte) ([]kotlinscan.Finding, error) {
	if root == "" {
		return nil, fmt.Errorf("source root is empty")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mode, category := pluginModeAndCategory(plugin)
	opts := parseFilterParams(paramsRaw)

	psi, used, err := psiScan(ctx, mode, root)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		slog.Warn("kotlin psi scan failed, falling back to kotlinscan", "plugin", plugin, "mode", mode, "err", err)
	} else if used {
		return kotlinscan.FilterFindings(filterCategory(psi, category), opts), nil
	}

	scanned, err := kotlinscan.Scan(root)
	if err != nil {
		return nil, fmt.Errorf("kotlinscan %s: %w", root, err)
	}
	return kotlinscan.FilterFindings(filterCategory(scanned, category), opts), nil
}

func pluginModeAndCategory(plugin string) (mode, category string) {
	if plugin == "scan.sast.kotlin" {
		return "sast", "SAST"
	}
	return "secrets", "SECRET"
}

func filterCategory(in []kotlinscan.Finding, category string) []kotlinscan.Finding {
	out := make([]kotlinscan.Finding, 0, len(in))
	for _, f := range in {
		if f.Category == category {
			out = append(out, f)
		}
	}
	return out
}

func psiScan(ctx context.Context, mode, root string) ([]kotlinscan.Finding, bool, error) {
	jar := os.Getenv("KOTLIN_PSI_JAR")
	if jar == "" {
		jar = "/opt/secflow-psi.jar"
	}
	if _, err := os.Stat(jar); err != nil {
		return nil, false, nil
	}
	if _, err := exec.LookPath("java"); err != nil {
		return nil, false, nil
	}
	runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(runCtx, "java", "-Dfile.encoding=UTF-8", "-jar", jar, "--mode", mode, root).Output()
	if err != nil {
		return nil, true, fmt.Errorf("exec kotlin psi jar (--mode %s): %w", mode, err)
	}
	var rows []kotlinscan.Finding
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, true, fmt.Errorf("parse kotlin psi output: %w", err)
	}
	return rows, true, nil
}
