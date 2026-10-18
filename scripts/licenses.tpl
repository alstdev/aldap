# Third-party licenses

ALDAP is licensed under MIT. The following dependencies are distributed with their own licenses.

| Module | License | Source |
|---|---|---|
{{ range . }}{{ if ne .Name "github.com/alstdev/aldap" }}| {{ .Name }} | {{ .LicenseName }} | {{ .LicenseURL }} |
{{ end }}{{ end }}
