{{/*
Expand the name of the chart.
*/}}
{{- define "blablador-token-generator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "blablador-token-generator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "blablador-token-generator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "blablador-token-generator.labels" -}}
helm.sh/chart: {{ include "blablador-token-generator.chart" . }}
{{ include "blablador-token-generator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "blablador-token-generator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "blablador-token-generator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "blablador-token-generator.image" -}}
{{- if .digest -}}
{{- printf "%s@%s" .repository .digest -}}
{{- else -}}
{{- $tag := required "Set an immutable release image.tag or image.digest" .tag -}}
{{- if eq $tag "latest" -}}{{- fail "The latest image tag is forbidden; provide a release tag or digest" -}}{{- end -}}
{{- printf "%s:%s" .repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "blablador-token-generator.configSecret" -}}
{{- default (printf "%s-config" (include "blablador-token-generator.fullname" .)) .Values.configExistingSecret -}}
{{- end -}}

{{- define "blablador-token-generator.postgresSecret" -}}
{{- default (printf "%s-postgresql" (include "blablador-token-generator.fullname" .)) .Values.postgresql.existingSecret -}}
{{- end -}}

{{- define "blablador-token-generator.redisSecret" -}}
{{- default (printf "%s-redis" (include "blablador-token-generator.fullname" .)) .Values.redis.existingSecret -}}
{{- end -}}

{{- define "blablador-token-generator.postgresUrl" -}}
{{- $pg := .Values.postgresql -}}
{{- printf "postgresql+asyncpg://%s:%s@%s-postgresql:5432/%s" ($pg.username | urlquery | replace "+" "%20") ($pg.password | urlquery | replace "+" "%20") (include "blablador-token-generator.fullname" .) ($pg.database | urlquery | replace "+" "%20") -}}
{{- end -}}

{{- define "blablador-token-generator.redisUrl" -}}
{{- $name := printf "%s-redis" (include "blablador-token-generator.fullname" .) -}}
{{- $password := .Values.redis.password | urlquery | replace "+" "%20" -}}
{{- if .Values.redis.tls.enabled -}}
{{- printf "rediss://:%s@%s:6379/0?ssl_ca_certs=/app/tls/redis/ca.crt&ssl_cert_reqs=required&ssl_check_hostname=true" $password $name -}}
{{- else -}}
{{- printf "redis://:%s@%s:6379/0" $password $name -}}
{{- end -}}
{{- end -}}

{{/*
Backup CronJob, volume and pod label. CronJob names may have at most 52
characters (Job names get a suffix).
*/}}
{{- define "blablador-token-generator.backupName" -}}
{{- printf "%s-postgresql-backup" (include "blablador-token-generator.fullname" . | trunc 34 | trimSuffix "-") -}}
{{- end -}}
