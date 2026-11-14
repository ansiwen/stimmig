{{- define "stimmig.labels" -}}
app.kubernetes.io/name: stimmig
app.kubernetes.io/instance: {{ .release }}
app.kubernetes.io/component: {{ .role }}
{{- end }}
