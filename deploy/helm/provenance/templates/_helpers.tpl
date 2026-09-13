{{/*
Expand the name of the chart.
*/}}
{{- define "provenance.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name.
*/}}
{{- define "provenance.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label value.
*/}}
{{- define "provenance.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "provenance.labels" -}}
helm.sh/chart: {{ include "provenance.chart" . }}
app.kubernetes.io/name: {{ include "provenance.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: provenance
{{- end -}}

{{/*
Selector labels for a given component (pass via "context" + "component").
*/}}
{{- define "provenance.selectorLabels" -}}
app.kubernetes.io/name: {{ include "provenance.name" .context }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Resource name helpers per component.
*/}}
{{- define "provenance.backend.fullname" -}}
{{- printf "%s-backend" (include "provenance.fullname" .) -}}
{{- end -}}

{{- define "provenance.frontend.fullname" -}}
{{- printf "%s-frontend" (include "provenance.fullname" .) -}}
{{- end -}}

{{- define "provenance.postgres.fullname" -}}
{{- printf "%s-postgres" (include "provenance.fullname" .) -}}
{{- end -}}

{{- define "provenance.redis.fullname" -}}
{{- printf "%s-redis" (include "provenance.fullname" .) -}}
{{- end -}}

{{- define "provenance.ansibleRunner.fullname" -}}
{{- printf "%s-ansible-runner" (include "provenance.fullname" .) -}}
{{- end -}}

{{- define "provenance.grypeScanner.fullname" -}}
{{- printf "%s-grype-scanner" (include "provenance.fullname" .) -}}
{{- end -}}

{{/*
Name of the Secret holding sensitive config.
*/}}
{{- define "provenance.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "provenance.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Backend image reference (tag falls back to chart appVersion).
*/}}
{{- define "provenance.backend.image" -}}
{{- printf "%s:%s" .Values.backend.image.repository (default .Chart.AppVersion .Values.backend.image.tag) -}}
{{- end -}}

{{/*
Frontend image reference.
*/}}
{{- define "provenance.frontend.image" -}}
{{- printf "%s:%s" .Values.frontend.image.repository (default .Chart.AppVersion .Values.frontend.image.tag) -}}
{{- end -}}

{{/*
Database URL the backend connects to (in-chart Postgres or external).
*/}}
{{- define "provenance.databaseUrl" -}}
{{- if .Values.postgres.enabled -}}
{{- printf "postgres://%s:%s@%s:5432/%s?sslmode=disable" .Values.postgres.auth.username .Values.postgres.auth.password (include "provenance.postgres.fullname" .) .Values.postgres.auth.database -}}
{{- else -}}
{{- required "postgres.externalDatabaseUrl is required when postgres.enabled=false" .Values.postgres.externalDatabaseUrl -}}
{{- end -}}
{{- end -}}

{{/*
Redis URL (templated against the release).
*/}}
{{- define "provenance.redisUrl" -}}
{{- tpl .Values.redis.url . -}}
{{- end -}}
