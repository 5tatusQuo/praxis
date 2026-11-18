{{- define "praxis.labels" -}}
app.kubernetes.io/name: praxis
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "praxis.image" -}}
{{ .root.Values.image.registry }}/praxis-{{ .name }}:{{ .root.Values.image.tag | default .root.Chart.AppVersion }}
{{- end }}

{{- define "praxis.databaseUrl" -}}
{{- if .Values.secrets.databaseUrl -}}
{{ .Values.secrets.databaseUrl }}
{{- else -}}
postgresql://praxis:{{ required "postgres.password is required" .Values.postgres.password }}@{{ .Release.Name }}-postgres:5432/praxis
{{- end -}}
{{- end }}
