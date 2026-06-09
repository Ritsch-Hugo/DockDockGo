{{/*
Expand the name of the chart.
*/}}
{{- define "docdockgo.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "docdockgo.labels" -}}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/*
PostgreSQL DSN (cluster-internal)
*/}}
{{- define "docdockgo.databaseUrl" -}}
postgres://{{ .Values.postgres.credentials.user }}:{{ .Values.postgres.credentials.password }}@postgres:5432/{{ .Values.postgres.credentials.db }}
{{- end }}
