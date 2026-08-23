{{/*
Names. Standard chart boilerplate: a release-prefixed name, truncated to the 63
characters a label value allows.
*/}}
{{- define "sightingdb.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sightingdb.fullname" -}}
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

{{- define "sightingdb.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sightingdb.labels" -}}
helm.sh/chart: {{ include "sightingdb.chart" . }}
{{ include "sightingdb.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "sightingdb.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sightingdb.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "sightingdb.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sightingdb.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "sightingdb.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Paths. In one place because several templates and an init container have to
agree on them, and because the daemon rewrites two of these files itself —
which is why they live on the data volume and not in a mounted ConfigMap.
*/}}
{{- define "sightingdb.dataDir" -}}/var/lib/sightingdb{{- end }}
{{- define "sightingdb.configDir" -}}/etc/sightingdb{{- end }}
{{- define "sightingdb.configFile" -}}{{ include "sightingdb.configDir" . }}/sightingdb.toml{{- end }}
{{- define "sightingdb.logConfigFile" -}}{{ include "sightingdb.configDir" . }}/log4rs.yml{{- end }}
{{- define "sightingdb.aclSeedFile" -}}{{ include "sightingdb.configDir" . }}/acl-seed/acl.toml{{- end }}
{{- define "sightingdb.aclFile" -}}{{ include "sightingdb.dataDir" . }}/acl.toml{{- end }}
{{- define "sightingdb.tiersFile" -}}{{ include "sightingdb.dataDir" . }}/tiers.toml{{- end }}
{{- define "sightingdb.tlsDir" -}}{{ include "sightingdb.configDir" . }}/tls{{- end }}

{{/*
Where the certificate and key are, per TLS mode. `secret` mounts what you
already have; `selfsigned` has the binary write a pair onto the data volume,
since the rest of the filesystem is read-only.
*/}}
{{- define "sightingdb.tlsCert" -}}
{{- if eq .Values.tls.mode "secret" }}{{ include "sightingdb.tlsDir" . }}/tls.crt{{ else }}{{ include "sightingdb.dataDir" . }}/ssl/cert.pem{{ end }}
{{- end }}
{{- define "sightingdb.tlsKey" -}}
{{- if eq .Values.tls.mode "secret" }}{{ include "sightingdb.tlsDir" . }}/tls.key{{ else }}{{ include "sightingdb.dataDir" . }}/ssl/key.pem{{ end }}
{{- end }}

{{- define "sightingdb.tlsEnabled" -}}
{{- if ne .Values.tls.mode "disabled" }}true{{ else }}false{{ end }}
{{- end }}

{{/*
The scheme probes and the bootstrap job speak. HTTPS when the pod terminates
TLS itself, plain HTTP when something in front of it does.
*/}}
{{- define "sightingdb.scheme" -}}
{{- if eq (include "sightingdb.tlsEnabled" .) "true" }}HTTPS{{ else }}HTTP{{ end }}
{{- end }}

{{- define "sightingdb.url" -}}
{{- $scheme := ternary "https" "http" (eq (include "sightingdb.tlsEnabled" .) "true") -}}
{{- printf "%s://%s:%v" $scheme (include "sightingdb.fullname" .) .Values.service.port }}
{{- end }}

{{/*
The name of the Secret holding acl.toml, and of the ConfigMap holding
sightingdb.toml — either the chart's own or one you brought.
*/}}
{{- define "sightingdb.aclSecretName" -}}
{{- default (printf "%s-acl" (include "sightingdb.fullname" .)) .Values.acl.existingSecret }}
{{- end }}

{{- define "sightingdb.configMapName" -}}
{{- default (include "sightingdb.fullname" .) .Values.existingConfigMap }}
{{- end }}
