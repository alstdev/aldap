package config

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/alstdev/aldap/internal/secret"
)

// Headers holds extra HTTP request headers of a webhook. Values may carry
// credentials (Authorization, Cookie, API keys), so every value renders
// "***" like an inline secret: in GET /v1/config, logs and events. The
// recommended place for credentials is headers_file.
type Headers map[string]secret.Inline

// CredentialHeaders lists the header names (case-insensitive) that carry
// credentials; inline values of these are warned by the validator.
var CredentialHeaders = []string{"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key"}

// ErrHeaderDuplicate is returned when headers and headers_file name the
// same header.
var ErrHeaderDuplicate = errors.New("header is set both inline and in headers_file")

// IsCredentialHeader reports whether name is one of CredentialHeaders.
func IsCredentialHeader(name string) bool {
	for _, h := range CredentialHeaders {
		if strings.EqualFold(h, name) {
			return true
		}
	}
	return false
}

// LoadHeaders merges the inline headers with the TOML table of file (when
// set), read through r: a file more permissive than secret.MaxFileMode is
// a warning. A header named in both places (case-insensitive) is an error.
// The result holds raw values; callers must not log it.
func LoadHeaders(r secret.Resolver, inline Headers, file string) (map[string]string, []secret.Warning, error) {
	out := make(map[string]string, len(inline))
	for k, v := range inline {
		out[k] = v.Reveal()
	}
	if file == "" {
		return out, nil, nil
	}
	v, warns, err := r.Resolve(secret.Source{File: file})
	if err != nil {
		return nil, warns, fmt.Errorf("headers_file: %w", err)
	}
	defer v.Wipe()
	var fromFile map[string]string
	if _, err := toml.Decode(v.Reveal(), &fromFile); err != nil {
		// The decoder error may quote a value: report the position only.
		var perr toml.ParseError
		if errors.As(err, &perr) {
			return nil, warns, fmt.Errorf("headers_file %s: line %d: not a TOML table of strings", file, perr.Position.Line)
		}
		return nil, warns, fmt.Errorf("headers_file %s: not a TOML table of strings", file)
	}
	names := make([]string, 0, len(fromFile))
	for k := range fromFile {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		for have := range out {
			if strings.EqualFold(have, k) {
				return nil, warns, fmt.Errorf("headers_file %s: %q: %w", file, k, ErrHeaderDuplicate)
			}
		}
		out[k] = fromFile[k]
	}
	return out, warns, nil
}

// checkHeaderSyntax returns a reason when name is not an RFC 9110 token or
// value holds a control character (CR/LF would split the request).
func checkHeaderSyntax(name, value string) string {
	if name == "" {
		return "empty header name"
	}
	for _, c := range name {
		if c > 0x7e || c <= ' ' || strings.ContainsRune("\"(),/:;<=>?@[\\]{}", c) {
			return fmt.Sprintf("header name %q is not a token", name)
		}
	}
	for _, c := range value {
		if (c < ' ' && c != '\t') || c == 0x7f {
			return fmt.Sprintf("header %q: value holds a control character", name)
		}
	}
	return ""
}

// checkHeaders validates headers and headers_file of one webhook: syntax,
// the masked placeholder, credentials given inline (warning) and, with
// StrictFiles, that the file loads.
func (v Validator) checkHeaders(rep *Report, path string, h Headers, file string) {
	for _, k := range sortedKeys(h) {
		val := h[k].Reveal()
		if why := checkHeaderSyntax(k, val); why != "" {
			rep.errorf(path+".headers", "%s", why)
			continue
		}
		if val == secret.Redacted {
			rep.errorf(path+".headers."+k, "is the masked placeholder %q of a rendered configuration: give the value or move it to %s.headers_file", secret.Redacted, path)
			continue
		}
		if IsCredentialHeader(k) {
			rep.warnf(path+".headers."+k, "credential given inline; move it to %s.headers_file", path)
		}
	}
	if file == "" {
		return
	}
	all, warns, err := LoadHeaders(v.Secrets, h, file)
	for _, w := range warns {
		rep.warnf(path+".headers_file", "%s", w.Msg)
	}
	if err != nil {
		if v.StrictFiles || errors.Is(err, ErrHeaderDuplicate) {
			rep.errorf(path+".headers_file", "%v", err)
		} else {
			rep.warnf(path+".headers_file", "%v (verified again at start)", err)
		}
		return
	}
	for _, k := range sortedKeys(all) {
		if _, inline := h[k]; inline {
			continue
		}
		if why := checkHeaderSyntax(k, all[k]); why != "" {
			rep.errorf(path+".headers_file", "%s", why)
		}
	}
}
