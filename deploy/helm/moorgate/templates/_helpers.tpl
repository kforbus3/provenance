{{/*
Expand the name of the chart.
*/}}
{{- define "moorgate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name.
*/}}
{{- define "moorgate.fullname" -}}
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
{{- define "moorgate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "moorgate.labels" -}}
helm.sh/chart: {{ include "moorgate.chart" . }}
app.kubernetes.io/name: {{ include "moorgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: fleet-terminal
{{- end -}}

{{/*
Selector labels for a given component (pass via "context" + "component").
*/}}
{{- define "moorgate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "moorgate.name" .context }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Resource name helpers per component.
*/}}
{{- define "moorgate.backend.fullname" -}}
{{- printf "%s-backend" (include "moorgate.fullname" .) -}}
{{- end -}}

{{- define "moorgate.frontend.fullname" -}}
{{- printf "%s-frontend" (include "moorgate.fullname" .) -}}
{{- end -}}

{{- define "moorgate.postgres.fullname" -}}
{{- printf "%s-postgres" (include "moorgate.fullname" .) -}}
{{- end -}}

{{- define "moorgate.redis.fullname" -}}
{{- printf "%s-redis" (include "moorgate.fullname" .) -}}
{{- end -}}

{{- define "moorgate.ansibleRunner.fullname" -}}
{{- printf "%s-ansible-runner" (include "moorgate.fullname" .) -}}
{{- end -}}

{{- define "moorgate.grypeScanner.fullname" -}}
{{- printf "%s-grype-scanner" (include "moorgate.fullname" .) -}}
{{- end -}}

{{/*
Name of the Secret holding sensitive config.
*/}}
{{- define "moorgate.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "moorgate.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Backend image reference (tag falls back to chart appVersion).
*/}}
{{- define "moorgate.backend.image" -}}
{{- printf "%s:%s" .Values.backend.image.repository (default .Chart.AppVersion .Values.backend.image.tag) -}}
{{- end -}}

{{/*
Frontend image reference.
*/}}
{{- define "moorgate.frontend.image" -}}
{{- printf "%s:%s" .Values.frontend.image.repository (default .Chart.AppVersion .Values.frontend.image.tag) -}}
{{- end -}}

{{/*
Database URL the backend connects to (in-chart Postgres or external).
*/}}
{{- define "moorgate.databaseUrl" -}}
{{- if .Values.postgres.enabled -}}
{{- printf "postgres://%s:%s@%s:5432/%s?sslmode=disable" .Values.postgres.auth.username .Values.postgres.auth.password (include "moorgate.postgres.fullname" .) .Values.postgres.auth.database -}}
{{- else -}}
{{- required "postgres.externalDatabaseUrl is required when postgres.enabled=false" .Values.postgres.externalDatabaseUrl -}}
{{- end -}}
{{- end -}}

{{/*
Redis URL (templated against the release).
*/}}
{{- define "moorgate.redisUrl" -}}
{{- tpl .Values.redis.url . -}}
{{- end -}}
