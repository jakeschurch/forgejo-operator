{{- define "forgejo-operator.name" -}}forgejo-operator{{- end }}
{{- define "forgejo-operator.labels" -}}
app.kubernetes.io/name: {{ include "forgejo-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
