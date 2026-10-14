{{- define "attestra.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "attestra.fullname" -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "attestra.labels" -}}
app.kubernetes.io/name: {{ include "attestra.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "attestra.selector" -}}
app.kubernetes.io/name: {{ include "attestra.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "attestra.secretName" -}}{{ default (printf "%s-secrets" (include "attestra.fullname" .)) .Values.existingSecret }}{{- end -}}
{{- define "attestra.image" -}}{{ .Values.image.repository }}:{{ .Values.image.tag }}{{- end -}}
{{- define "attestra.env" -}}
- name: ATTESTRA_DATA_DIR
  value: /data
- name: ATTESTRA_API_KEY_PEPPER
  valueFrom: { secretKeyRef: { name: {{ include "attestra.secretName" . }}, key: ATTESTRA_API_KEY_PEPPER } }
- name: ATTESTRA_SESSION_SECRET
  valueFrom: { secretKeyRef: { name: {{ include "attestra.secretName" . }}, key: ATTESTRA_SESSION_SECRET } }
{{- if .Values.databaseUrl }}
- name: ATTESTRA_DATABASE_URL
  valueFrom: { secretKeyRef: { name: {{ include "attestra.secretName" . }}, key: ATTESTRA_DATABASE_URL } }
{{- end }}
{{- if .Values.oidc.enabled }}
- { name: ATTESTRA_OIDC_ENABLED, value: "true" }
- { name: ATTESTRA_OIDC_ISSUER, value: {{ required "oidc.issuer is required" .Values.oidc.issuer | quote }} }
- { name: ATTESTRA_OIDC_CLIENT_ID, value: {{ .Values.oidc.clientId | quote }} }
- { name: ATTESTRA_OIDC_AUDIENCE, value: {{ .Values.oidc.audience | quote }} }
- { name: ATTESTRA_OIDC_JWKS_URL, value: {{ .Values.oidc.jwksUrl | quote }} }
- { name: ATTESTRA_OIDC_TENANT_CLAIM, value: {{ .Values.oidc.tenantClaim | quote }} }
- { name: ATTESTRA_OIDC_AUTO_PROVISION, value: {{ .Values.oidc.autoProvision | toString | quote }} }
{{- end }}
{{- if eq .Values.secretsStore.backend "vault" }}
- { name: ATTESTRA_SECRETS_BACKEND, value: "vault" }
- { name: ATTESTRA_VAULT_ADDR, value: {{ required "secretsStore.vault.addr is required" .Values.secretsStore.vault.addr | quote }} }
- { name: ATTESTRA_VAULT_KV_MOUNT, value: {{ .Values.secretsStore.vault.kvMount | quote }} }
- { name: ATTESTRA_VAULT_KV_PATH, value: {{ .Values.secretsStore.vault.kvPath | quote }} }
- { name: ATTESTRA_VAULT_NAMESPACE, value: {{ .Values.secretsStore.vault.namespace | quote }} }
- name: ATTESTRA_VAULT_TOKEN
  valueFrom: { secretKeyRef: { name: {{ required "secretsStore.vault.tokenSecret is required" .Values.secretsStore.vault.tokenSecret }}, key: {{ .Values.secretsStore.vault.tokenSecretKey }} } }
{{- end }}
{{- range $k, $v := .Values.env }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
{{- end -}}
{{- define "attestra.volumes" -}}
- name: data
{{- if .Values.persistence.enabled }}
  persistentVolumeClaim: { claimName: {{ include "attestra.fullname" . }}-data }
{{- else }}
  emptyDir: {}
{{- end }}
- name: tmp
  emptyDir: {}
{{- end -}}
