{{/*
Helper templates for the OnlyScans Helm chart.
*/}}
{{- define "secflow.image" -}}
{{- $reg := trimSuffix "/" .root.Values.global.imageRegistry -}}
{{- if $reg -}}
{{ printf "%s/%s:%s" $reg .repo .root.Values.global.imageTag }}
{{- else -}}
{{ printf "%s:%s" .repo .root.Values.global.imageTag }}
{{- end -}}
{{- end -}}

{{- define "secflow.databaseUrl" -}}
{{- printf "postgres://%s:%s@postgres.%s.svc.cluster.local:5432/%s?sslmode=disable" .Values.postgres.user .Values.postgres.password .Values.namespaces.system .Values.postgres.database -}}
{{- end -}}

{{- define "secflow.orchestratorAddr" -}}
{{- printf "orchestrator.%s.svc.cluster.local:50051" .Values.namespaces.app -}}
{{- end -}}

{{- define "secflow.ingesterAddr" -}}
{{- printf "source-ingester.%s.svc.cluster.local:50052" .Values.namespaces.app -}}
{{- end -}}

{{- define "secflow.aiAddr" -}}
{{- printf "ai-service.%s.svc.cluster.local:50053" .Values.namespaces.workers -}}
{{- end -}}

{{- define "secflow.notifyAddr" -}}
{{- printf "notify-service.%s.svc.cluster.local:50054" .Values.namespaces.workers -}}
{{- end -}}

{{- define "secflow.garageEndpoint" -}}
{{- printf "http://garage.%s.svc.cluster.local:3900" .Values.namespaces.system -}}
{{- end -}}

{{- define "secflow.garageAdminUrl" -}}
{{- printf "http://garage.%s.svc.cluster.local:3903" .Values.namespaces.system -}}
{{- end -}}

{{- define "secflow.redisAddr" -}}
{{- printf "redis.%s.svc.cluster.local:6379" .Values.namespaces.system -}}
{{- end -}}

{{- define "secflow.otelEndpoint" -}}
{{- if .Values.observability.enabled -}}
{{- printf "http://otel-collector.%s.svc.cluster.local:4318" .Values.namespaces.observability -}}
{{- else -}}
""
{{- end -}}
{{- end -}}

{{- define "secflow.commonLabels" -}}
app.kubernetes.io/part-of: onlyscans
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "secflow.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "secflow.containerSecurityContext" -}}
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities:
  drop: ["ALL"]
{{- end -}}
