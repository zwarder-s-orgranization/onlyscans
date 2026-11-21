package main

import (
	"strconv"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/manifest"
)

type builtinTemplate struct {
	slug, name, description, problem string
	graph                            *secflowv1.WorkflowGraph
}

type tplBuilder struct {
	nodes []*secflowv1.WorkflowNode
	edges []*secflowv1.WorkflowEdge
}

func (b *tplBuilder) node(id, plugin, label, paramsJSON string, col, row int) string {
	if label == "" {
		if spec, ok := manifest.LookupBuiltin(plugin); ok && spec.DisplayName != "" {
			label = spec.DisplayName
		} else {
			label = plugin
		}
	}
	if paramsJSON == "" {
		paramsJSON = defaultParams(plugin)
	}
	b.nodes = append(b.nodes, &secflowv1.WorkflowNode{
		Id:             id,
		PluginId:       plugin,
		Label:          label,
		Position:       &secflowv1.Position{X: float64(col * 240), Y: float64(40 + row*140)},
		ParamsJson:     []byte(paramsJSON),
		SecretBindings: nil, // Unbound secret slots are advertised via PluginManifest.RequiredSecretKeys, never SecretRef: "".
	})
	return id
}

func (b *tplBuilder) edge(src, handle, dst string) {
	if handle == "" {
		handle = "default"
	}
	b.edges = append(b.edges, &secflowv1.WorkflowEdge{
		Id:           "e" + strconv.Itoa(len(b.edges)+1),
		SourceNodeId: src,
		SourceHandle: handle,
		TargetNodeId: dst,
		TargetHandle: "default",
	})
}

func (b *tplBuilder) build() *secflowv1.WorkflowGraph {
	return &secflowv1.WorkflowGraph{
		SchemaVersion: 1,
		Nodes:         b.nodes,
		Edges:         b.edges,
	}
}

func builtinTemplateGraphs() []builtinTemplate {
	return []builtinTemplate{
		{
			slug:        "full-pre-release-appsec-gate",
			name:        "Full Pre-Release AppSec Gate",
			description: "Полный предрелизный Workflow: параллельные SECRET/SCA/SAST/SBOM, Policy Gate, AI Explain, экспорт отчёта и уведомления.",
			problem:     "Полный предрелизный контроль безопасности с Policy Gate и AI-объяснением",
			graph:       tplFullPreReleaseAppSecGate(),
		},
		{
			slug:        "nightly-secret-watch",
			name:        "Nightly Scheduled Secret Watch",
			description: "Ночной Workflow по расписанию: клонирование Git, поиск секретов, проверка условия и AI-сводка в Telegram.",
			problem:     "Регулярный ночной мониторинг утечек секретов в репозитории",
			graph:       tplNightlySecretWatch(),
		},
		{
			slug:        "severity-escalation-router",
			name:        "Severity Escalation Router",
			description: "Маршрутизация находок через logic.switch (maxSeverity) по 4 веткам: CRITICAL, HIGH, MEDIUM_LOW и CLEAN.",
			problem:     "Эскалация инцидентов по максимальной критичности находок",
			graph:       tplSeverityEscalationRouter(),
		},
		{
			slug:        "fast-pr-ci-gate",
			name:        "Fast PR / Commit CI Gate",
			description: "Быстрый CI/PR Workflow от trigger.webhook с динамическими {{ $trigger.repoUrl }} / {{ $trigger.commitSha }}, Policy Gate и AI Explain.",
			problem:     "Быстрый автоматический гейт на push и pull request",
			graph:       tplFastPRCIGate(),
		},
		{
			slug:        "weekly-sbom-audit",
			name:        "Weekly Supply-Chain & SBOM Audit",
			description: "Еженедельный аудит цепочки поставок: SCA + CycloneDX 1.6 SBOM, AI Explain, экспорт отчёта и отправка на почту.",
			problem:     "Еженедельный аудит зависимостей и генерация CycloneDX SBOM",
			graph:       tplWeeklySBOMAudit(),
		},
		{
			slug:        "regression-new-findings",
			name:        "Regression / New-Findings-Only Watch",
			description: "Контроль регрессий по Baseline Diff: фильтрация только новых находок, AI Explain и доставка через webhook.",
			problem:     "Уведомления только о новых находках относительно прошлого успешного Run",
			graph:       tplRegressionNewFindings(),
		},
		{
			slug:        "mentor-benchmark-export",
			name:        "Mentor Benchmark / Compliance Export",
			description: "Эталонный Workflow для проверки бенчмарка: SECRET + SCA + SAST, merge, AI Explain и экспорт отчётов.",
			problem:     "Полный прогон анализаторов и выгрузка submission.json + Markdown/HTML отчёта",
			graph:       tplMentorBenchmarkExport(),
		},
	}
}

func tplFullPreReleaseAppSecGate() *secflowv1.WorkflowGraph {
	var b tplBuilder
	t := b.node("n_trigger", "trigger.manual", "Manual Trigger", `{"description":"Pre-release AppSec gate"}`, 0, 1)
	s := b.node("n_source", "source.upload", "Upload Source Archive", `{"sourceId":"pending-upload"}`, 1, 1)
	sec := b.node("n_secrets", "scan.secrets", "Secret Scanner (PSI)", `{}`, 2, 0)
	sca := b.node("n_sca", "scan.sca", "Gradle SCA Scanner", `{"catalogId":"default"}`, 2, 1)
	sast := b.node("n_sast", "scan.sast.kotlin", "Kotlin/Spring SAST (PSI)", `{}`, 2, 2)
	sbom := b.node("n_sbom", "sbom.generate", "CycloneDX 1.6 SBOM", `{"includeDevDependencies":false}`, 2, 3)
	m := b.node("n_merge", "logic.merge", "Merge Findings", `{"deduplicateByFingerprint":true}`, 3, 1)
	g := b.node("n_gate", "gate.policy", "Release Policy Gate", `{"failOnSeverity":"HIGH","warnOnSeverity":"MEDIUM","failOnAnySecret":true}`, 4, 1)
	ai := b.node("n_ai", "ai.explain", "AI Explain (Grounded)", `{"privacyMode":"REDACTED_SNIPPET","locale":"ru","maxFindings":50}`, 5, 0)
	rep := b.node("n_report", "report.export", "Report Export", `{"title":"Full Pre-Release AppSec Report","formats":["MARKDOWN","HTML"]}`, 6, 0)
	tg := b.node("n_telegram", "notify.telegram", "Telegram Alert", `{"chatId":"0","messageTemplate":"SecFlow Pre-Release Gate: {{ $envelope.gate.status }} ({{ $envelope.stats.total }} findings)"}`, 6, 1)
	wh := b.node("n_webhook_pass", "notify.webhook", "Passed Webhook", `{"url":"https://hooks.example.com/secflow/passed","bodyTemplate":"{\"status\":\"PASS\",\"runId\":\"{{ $run.id }}\"}"}`, 5, 2)

	b.edge(t, "default", s)
	b.edge(s, "default", sec)
	b.edge(s, "default", sca)
	b.edge(s, "default", sast)
	b.edge(s, "default", sbom)
	b.edge(sec, "default", m)
	b.edge(sca, "default", m)
	b.edge(sast, "default", m)
	b.edge(sbom, "default", m)
	b.edge(m, "default", g)
	b.edge(g, "FAIL", ai)
	b.edge(g, "WARN", ai)
	b.edge(g, "PASS", wh)
	b.edge(ai, "default", rep)
	b.edge(ai, "default", tg)
	return b.build()
}

func tplNightlySecretWatch() *secflowv1.WorkflowGraph {
	var b tplBuilder
	t := b.node("n_trigger", "trigger.schedule", "Nightly Schedule", `{"cron":"0 14 * * *","timezone":"UTC","enabled":true}`, 0, 0)
	s := b.node("n_source", "source.git", "Git Repository", `{"repoUrl":"https://github.com/TBagirov/training","gitRef":"main"}`, 1, 0)
	sec := b.node("n_secrets", "scan.secrets", "Secret Scanner (PSI)", `{}`, 2, 0)
	cond := b.node("n_if", "logic.if", "Any Secret Found?", `{"combinator":"AND","conditions":[{"field":"stats.total","operator":"gt","value":0}]}`, 3, 0)
	ai := b.node("n_ai", "ai.explain", "AI Explain (Grounded)", `{"privacyMode":"REDACTED_SNIPPET","locale":"ru","maxFindings":50}`, 4, 0)
	tg := b.node("n_telegram", "notify.telegram", "Telegram Alert", `{"chatId":"0","messageTemplate":"Nightly Secret Watch: {{ $envelope.stats.secretCount }} secrets detected"}`, 5, 0)

	b.edge(t, "default", s)
	b.edge(s, "default", sec)
	b.edge(sec, "default", cond)
	b.edge(cond, "true", ai)
	b.edge(ai, "default", tg)
	return b.build()
}

func tplSeverityEscalationRouter() *secflowv1.WorkflowGraph {
	var b tplBuilder
	t := b.node("n_trigger", "trigger.manual", "Manual Trigger", `{"description":"Severity escalation routing"}`, 0, 1)
	s := b.node("n_source", "source.upload", "Upload Source Archive", `{"sourceId":"pending-upload"}`, 1, 1)
	sec := b.node("n_secrets", "scan.secrets", "Secret Scanner (PSI)", `{}`, 2, 0)
	sast := b.node("n_sast", "scan.sast.kotlin", "Kotlin/Spring SAST (PSI)", `{}`, 2, 2)
	m := b.node("n_merge", "logic.merge", "Merge Findings", `{"deduplicateByFingerprint":true}`, 3, 1)
	sw := b.node("n_switch", "logic.switch", "Severity Router", `{"mode":"maxSeverity"}`, 4, 1)
	aiCrit := b.node("n_ai_critical", "ai.explain", "AI Explain (Critical)", `{"privacyMode":"REDACTED_SNIPPET","locale":"ru","maxFindings":50}`, 5, 0)
	tgCrit := b.node("n_telegram_critical", "notify.telegram", "Critical Telegram Escalation", `{"chatId":"0","messageTemplate":"CRITICAL findings detected in {{ $run.id }}"}`, 6, 0)
	smtpHigh := b.node("n_smtp_high", "notify.smtp", "High Severity Email", `{"to":["appsec@example.com"],"subject":"SecFlow HIGH Severity Findings"}`, 5, 1)
	repMed := b.node("n_report_medium_low", "report.export", "Report Export (Medium/Low)", `{"title":"SecFlow Medium/Low Report","formats":["MARKDOWN","HTML"]}`, 5, 2)
	repClean := b.node("n_report_clean", "report.export", "Report Export (Clean)", `{"title":"SecFlow Clean Verification Report","formats":["MARKDOWN"]}`, 5, 3)

	b.edge(t, "default", s)
	b.edge(s, "default", sec)
	b.edge(s, "default", sast)
	b.edge(sec, "default", m)
	b.edge(sast, "default", m)
	b.edge(m, "default", sw)
	b.edge(sw, "CRITICAL", aiCrit)
	b.edge(aiCrit, "default", tgCrit)
	b.edge(sw, "HIGH", smtpHigh)
	b.edge(sw, "MEDIUM_LOW", repMed)
	b.edge(sw, "CLEAN", repClean)
	return b.build()
}

func tplFastPRCIGate() *secflowv1.WorkflowGraph {
	var b tplBuilder
	t := b.node("n_trigger", "trigger.webhook", "Git PR / Push Webhook", `{"gitProvider":"GITHUB","events":["push","pull_request"],"reportCommitStatus":true,"commitStatusContext":"secflow/security-gate"}`, 0, 1)
	s := b.node("n_source", "source.git", "PR Commit Checkout", `{"repoUrl":"{{ $trigger.repoUrl }}","gitRef":"{{ $trigger.commitSha }}"}`, 1, 1)
	sec := b.node("n_secrets", "scan.secrets", "Secret Scanner (PSI)", `{}`, 2, 0)
	sast := b.node("n_sast", "scan.sast.kotlin", "Kotlin/Spring SAST (PSI)", `{}`, 2, 2)
	m := b.node("n_merge", "logic.merge", "Merge Findings", `{"deduplicateByFingerprint":true}`, 3, 1)
	g := b.node("n_gate", "gate.policy", "PR Policy Gate", `{"failOnSeverity":"HIGH","warnOnSeverity":"MEDIUM","failOnAnySecret":true}`, 4, 1)
	ai := b.node("n_ai", "ai.explain", "AI Explain (Grounded)", `{"privacyMode":"REDACTED_SNIPPET","locale":"ru","maxFindings":50}`, 5, 1)

	b.edge(t, "default", s)
	b.edge(s, "default", sec)
	b.edge(s, "default", sast)
	b.edge(sec, "default", m)
	b.edge(sast, "default", m)
	b.edge(m, "default", g)
	b.edge(g, "FAIL", ai)
	b.edge(g, "WARN", ai)
	return b.build()
}

func tplWeeklySBOMAudit() *secflowv1.WorkflowGraph {
	var b tplBuilder
	t := b.node("n_trigger", "trigger.schedule", "Weekly Schedule (Mon)", `{"cron":"0 14 * * 1","timezone":"UTC","enabled":true}`, 0, 1)
	s := b.node("n_source", "source.git", "Git Repository", `{"repoUrl":"https://github.com/TBagirov/training","gitRef":"main"}`, 1, 1)
	sca := b.node("n_sca", "scan.sca", "Gradle SCA Scanner", `{"catalogId":"default"}`, 2, 0)
	sbom := b.node("n_sbom", "sbom.generate", "CycloneDX 1.6 SBOM", `{"includeDevDependencies":false}`, 2, 2)
	m := b.node("n_merge", "logic.merge", "Merge Supply-Chain Results", `{"deduplicateByFingerprint":true}`, 3, 1)
	ai := b.node("n_ai", "ai.explain", "AI Explain (Grounded)", `{"privacyMode":"METADATA_ONLY","locale":"ru","maxFindings":50}`, 4, 1)
	rep := b.node("n_report", "report.export", "SBOM & SCA Report", `{"title":"Weekly Supply-Chain & SBOM Audit","formats":["MARKDOWN","HTML"]}`, 5, 1)
	smtp := b.node("n_smtp", "notify.smtp", "Email Audit Summary", `{"to":["appsec@example.com"],"subject":"Weekly SecFlow Supply-Chain & SBOM Audit"}`, 6, 1)

	b.edge(t, "default", s)
	b.edge(s, "default", sca)
	b.edge(s, "default", sbom)
	b.edge(sca, "default", m)
	b.edge(sbom, "default", m)
	b.edge(m, "default", ai)
	b.edge(ai, "default", rep)
	b.edge(rep, "default", smtp)
	return b.build()
}

func tplRegressionNewFindings() *secflowv1.WorkflowGraph {
	var b tplBuilder
	t := b.node("n_trigger", "trigger.schedule", "Daily Regression Schedule", `{"cron":"0 14 * * *","timezone":"UTC","enabled":true}`, 0, 1)
	s := b.node("n_source", "source.git", "Git Repository", `{"repoUrl":"https://github.com/TBagirov/training","gitRef":"main"}`, 1, 1)
	sec := b.node("n_secrets", "scan.secrets", "Secret Scanner (PSI)", `{}`, 2, 0)
	sast := b.node("n_sast", "scan.sast.kotlin", "Kotlin/Spring SAST (PSI)", `{}`, 2, 2)
	m := b.node("n_merge", "logic.merge", "Merge Findings", `{"deduplicateByFingerprint":true}`, 3, 1)
	cmp := b.node("n_compare", "logic.compare", "Baseline Diff", `{"mode":"baselineDiff","baselineScope":"previous_succeeded_run","minNewFindingsForTrue":1}`, 4, 1)
	flt := b.node("n_filter", "logic.filter", "Only New Findings", `{"onlyNewVsBaseline":true}`, 5, 1)
	ai := b.node("n_ai", "ai.explain", "AI Explain (New Only)", `{"privacyMode":"REDACTED_SNIPPET","locale":"ru","maxFindings":50}`, 6, 1)
	wh := b.node("n_webhook", "notify.webhook", "Regression Webhook", `{"url":"https://hooks.example.com/secflow/regression","bodyTemplate":"{\"newFindings\":{{ $envelope.stats.newCount }},\"runId\":\"{{ $run.id }}\"}"}`, 7, 1)

	b.edge(t, "default", s)
	b.edge(s, "default", sec)
	b.edge(s, "default", sast)
	b.edge(sec, "default", m)
	b.edge(sast, "default", m)
	b.edge(m, "default", cmp)
	b.edge(cmp, "true", flt)
	b.edge(flt, "default", ai)
	b.edge(ai, "default", wh)
	return b.build()
}

func tplMentorBenchmarkExport() *secflowv1.WorkflowGraph {
	var b tplBuilder
	t := b.node("n_trigger", "trigger.manual", "Manual Trigger", `{"description":"Mentor benchmark verification"}`, 0, 1)
	s := b.node("n_source", "source.upload", "Upload Benchmark Archive", `{"sourceId":"pending-upload"}`, 1, 1)
	sec := b.node("n_secrets", "scan.secrets", "Secret Scanner (PSI)", `{}`, 2, 0)
	sca := b.node("n_sca", "scan.sca", "Gradle SCA Scanner", `{"catalogId":"default"}`, 2, 1)
	sast := b.node("n_sast", "scan.sast.kotlin", "Kotlin/Spring SAST (PSI)", `{}`, 2, 2)
	m := b.node("n_merge", "logic.merge", "Merge All Analyzers", `{"deduplicateByFingerprint":true}`, 3, 1)
	ai := b.node("n_ai", "ai.explain", "AI Explain (Grounded)", `{"privacyMode":"REDACTED_SNIPPET","locale":"ru","maxFindings":50}`, 4, 1)
	rep := b.node("n_report", "report.export", "Compliance & Submission Export", `{"title":"Mentor Benchmark Compliance Report","formats":["MARKDOWN","HTML"]}`, 5, 1)

	b.edge(t, "default", s)
	b.edge(s, "default", sec)
	b.edge(s, "default", sca)
	b.edge(s, "default", sast)
	b.edge(sec, "default", m)
	b.edge(sca, "default", m)
	b.edge(sast, "default", m)
	b.edge(m, "default", ai)
	b.edge(ai, "default", rep)
	return b.build()
}

func defaultParams(plugin string) string {
	switch plugin {
	case "trigger.schedule":
		return `{"cron":"0 14 * * *","timezone":"UTC","enabled":true}`
	case "trigger.webhook":
		return `{"gitProvider":"GITHUB","events":["push","pull_request"]}`
	case "source.upload":
		return `{"sourceId":"pending-upload"}`
	case "source.git":
		return `{"repoUrl":"https://github.com/TBagirov/training","gitRef":"main"}`
	case "logic.switch":
		return `{"mode":"maxSeverity"}`
	case "logic.compare":
		return `{"mode":"baselineDiff"}`
	case "gate.policy":
		return `{"failOnSeverity":"HIGH"}`
	case "notify.telegram":
		return `{"chatId":"0"}`
	case "notify.smtp":
		return `{"to":["appsec@example.com"],"subject":"SecFlow"}`
	default:
		return `{}`
	}
}
