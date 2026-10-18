package testdir

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jimlambrt/gldap"

	"github.com/alstdev/aldap/internal/ldapfilter"
)

// AD diagnostic data codes for failed simple binds.
const (
	ADDataNoSuchUser     = "525"
	ADDataBadPassword    = "52e"
	ADDataDisabled       = "533"
	ADDataAccountExpired = "701"
	ADDataMustChange     = "773"
	ADDataLocked         = "775"

	uacAccountDisable = 2
	neverExpires      = "9223372036854775807"
	// windowsEpochDiff is the number of 100ns intervals between 1601-01-01 and 1970-01-01.
	windowsEpochDiff = 116444736000000000
)

// withDiag sets the diagnostic message on a response (gldap ignores the
// WithDiagnosticMessage option in its constructors).
func withDiag[R interface{ SetDiagnosticMessage(string) }](r R, msg string) R {
	if msg != "" {
		r.SetDiagnosticMessage(msg)
	}
	return r
}

// adBindDiag formats an AcceptSecurityContext diagnostic like AD does.
func adBindDiag(data string) string {
	return fmt.Sprintf("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data %s, v4563", data)
}

const unboundDiag = "000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563"

// resolveBindName finds the entry for a bind name: DN, UPN, DOMAIN\sAMAccountName
// or bare sAMAccountName.
func (s *Server) resolveBindName(name string) *Entry {
	if e := s.Dir.Lookup(name); e != nil {
		return e
	}
	if strings.Contains(name, "@") {
		if es := s.Dir.FindByAttr("userPrincipalName", name); len(es) == 1 {
			return es[0]
		}
		return nil
	}
	if i := strings.IndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	if es := s.Dir.FindByAttr("sAMAccountName", name); len(es) == 1 {
		return es[0]
	}
	return nil
}

// checkBind returns the result code and AD data for a password check.
func (s *Server) checkBind(e *Entry, password string) (code int, data string) {
	if e == nil {
		return gldap.ResultInvalidCredentials, ADDataNoSuchUser
	}
	ok := false
	for _, p := range e.Get("userPassword") {
		if p == password {
			ok = true
			break
		}
	}
	if !ok {
		return gldap.ResultInvalidCredentials, ADDataBadPassword
	}
	if uac, err := strconv.ParseInt(e.First("userAccountControl"), 10, 64); err == nil && uac&uacAccountDisable != 0 {
		return gldap.ResultInvalidCredentials, ADDataDisabled
	}
	if lt, err := strconv.ParseInt(e.First("lockoutTime"), 10, 64); err == nil && lt > 0 {
		return gldap.ResultInvalidCredentials, ADDataLocked
	}
	if exp := e.First("accountExpires"); exp != "" && exp != "0" && exp != neverExpires {
		if n, err := strconv.ParseInt(exp, 10, 64); err == nil && n > 0 && (n-windowsEpochDiff)/10000000 < time.Now().Unix() {
			return gldap.ResultInvalidCredentials, ADDataAccountExpired
		}
	}
	if e.First("pwdLastSet") == "0" {
		return gldap.ResultInvalidCredentials, ADDataMustChange
	}
	return gldap.ResultSuccess, ""
}

func (s *Server) handleBind(w *gldap.ResponseWriter, r *gldap.Request) {
	s.binds.Add(1)
	s.sleep()
	m, err := r.GetSimpleBindMessage()
	if err != nil {
		_ = w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultProtocolError)))
		return
	}
	pw := string(m.Password)
	if m.UserName == "" && pw == "" {
		s.setBound(r.ConnectionID(), "")
		_ = w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
		return
	}
	if pw == "" {
		// Unauthenticated bind (RFC 4513 §5.1.2): AD treats it as anonymous.
		s.setBound(r.ConnectionID(), "")
		_ = w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
		return
	}
	e := s.resolveBindName(m.UserName)
	code, data := s.checkBind(e, pw)
	resp := r.NewBindResponse(gldap.WithResponseCode(code))
	if code != gldap.ResultSuccess && s.opts.adBindCodes {
		resp.SetDiagnosticMessage(adBindDiag(data))
	}
	if code == gldap.ResultSuccess {
		s.setBound(r.ConnectionID(), e.DN)
	}
	_ = w.Write(resp)
}

func (s *Server) rootDSEEntry() *Entry {
	e := &Entry{DN: ""}
	base := s.Dir.BaseDN()
	e.Set("namingContexts", base)
	e.Set("defaultNamingContext", base)
	e.Set("rootDomainNamingContext", base)
	e.Set("supportedLDAPVersion", "3")
	e.Set("supportedControl", gldap.ControlTypePaging)
	e.Set("supportedCapabilities", "1.2.840.113556.1.4.800")
	if !s.opts.noStartTLS {
		e.Set("supportedExtension", string(gldap.ExtendedOperationStartTLS))
	}
	e.Set("vendorName", "aldap testdir")
	e.Set("dnsHostName", s.opts.hostName)
	e.Set("isSynchronized", "TRUE")
	return e
}

func (s *Server) handleSearch(w *gldap.ResponseWriter, r *gldap.Request) {
	s.searches.Add(1)
	s.sleep()
	m, err := r.GetSearchMessage()
	if err != nil {
		_ = w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultProtocolError)))
		return
	}
	f, err := ldapfilter.Parse(m.Filter)
	if err != nil {
		_ = w.Write(withDiag(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultProtocolError)), err.Error()))
		return
	}
	if m.BaseDN == "" && m.Scope == gldap.BaseObject {
		s.rootDSE.Add(1)
		root := s.rootDSEEntry()
		if (&matcher{dir: s.Dir}).match(f, root) {
			_ = w.Write(s.entryResponse(r, root, m.Attributes))
		}
		_ = w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
		return
	}
	if dn, _ := s.boundDN(r.ConnectionID()); dn == "" && !s.opts.anonSearch {
		_ = w.Write(withDiag(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultOperationsError)), unboundDiag))
		return
	}
	entries, err := s.Dir.Search(m.BaseDN, Scope(m.Scope), f)
	if err != nil {
		code := gldap.ResultOperationsError
		if errors.Is(err, ErrNoSuchObject) {
			code = gldap.ResultNoSuchObject
		}
		_ = w.Write(withDiag(r.NewSearchDoneResponse(gldap.WithResponseCode(code)), err.Error()))
		return
	}
	code := gldap.ResultSuccess
	if m.SizeLimit > 0 && int64(len(entries)) > m.SizeLimit {
		entries = entries[:m.SizeLimit]
		code = gldap.ResultSizeLimitExceeded
	}
	var paging *gldap.ControlPaging
	for _, c := range m.Controls {
		if p, ok := c.(*gldap.ControlPaging); ok {
			paging = p
		}
	}
	var respCtl *gldap.ControlPaging
	if paging != nil {
		var page []*Entry
		page, respCtl, err = s.page(entries, paging)
		if err != nil {
			_ = w.Write(withDiag(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultUnwillingToPerform)), err.Error()))
			return
		}
		entries = page
	}
	for _, e := range entries {
		if err := w.Write(s.entryResponse(r, e, m.Attributes)); err != nil {
			return
		}
	}
	done := r.NewSearchDoneResponse(gldap.WithResponseCode(code))
	if respCtl != nil {
		done.SetControls(respCtl)
	}
	_ = w.Write(done)
}

// page slices entries for the paged results control. The cookie is the
// decimal offset of the next page; an empty cookie ends the sequence.
func (s *Server) page(entries []*Entry, ctl *gldap.ControlPaging) ([]*Entry, *gldap.ControlPaging, error) {
	resp := &gldap.ControlPaging{}
	if ctl.PagingSize == 0 {
		return nil, resp, nil // abandon
	}
	offset := 0
	if len(ctl.Cookie) > 0 {
		n, err := strconv.Atoi(string(ctl.Cookie))
		if err != nil || n < 0 || n > len(entries) {
			return nil, nil, errors.New("invalid paging cookie")
		}
		offset = n
	}
	size := int(ctl.PagingSize)
	if s.opts.maxPageSize > 0 && size > s.opts.maxPageSize {
		size = s.opts.maxPageSize
	}
	end := offset + size
	if end >= len(entries) {
		return entries[offset:], resp, nil
	}
	resp.Cookie = []byte(strconv.Itoa(end))
	return entries[offset:end], resp, nil
}

// entryResponse builds a search entry with the requested attributes.
// Passwords are never returned.
func (s *Server) entryResponse(r *gldap.Request, e *Entry, requested []string) *gldap.SearchResponseEntry {
	resp := r.NewSearchResponseEntry(e.DN)
	all := len(requested) == 0
	want := map[string]bool{}
	for _, a := range requested {
		switch a {
		case "*":
			all = true
		case "1.1":
		default:
			want[strings.ToLower(a)] = true
		}
	}
	for _, a := range e.Attrs {
		lower := strings.ToLower(a.Name)
		if lower == "userpassword" || lower == "unicodepwd" {
			continue
		}
		if all || want[lower] {
			resp.AddAttribute(a.Name, a.Values)
		}
	}
	return resp
}

func (s *Server) handleStartTLS(w *gldap.ResponseWriter, r *gldap.Request) {
	if s.opts.noStartTLS {
		res := withDiag(r.NewExtendedResponse(gldap.WithResponseCode(gldap.ResultUnavailableCriticalExtension)), "StartTLS not supported")
		res.SetResponseName(gldap.ExtendedOperationStartTLS)
		_ = w.Write(res)
		return
	}
	if s.opts.tls {
		res := withDiag(r.NewExtendedResponse(gldap.WithResponseCode(gldap.ResultOperationsError)), "already encrypted")
		res.SetResponseName(gldap.ExtendedOperationStartTLS)
		_ = w.Write(res)
		return
	}
	res := r.NewExtendedResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	res.SetResponseName(gldap.ExtendedOperationStartTLS)
	if err := w.Write(res); err != nil {
		return
	}
	_ = r.StartTLS(s.certs.serverConfig())
}

// handleReadOnly answers add/modify/delete with insufficientAccessRights.
func (s *Server) handleReadOnly(w *gldap.ResponseWriter, r *gldap.Request) {
	app := gldap.ApplicationExtendedResponse
	switch {
	case func() bool { _, err := r.GetAddMessage(); return err == nil }():
		app = gldap.ApplicationAddResponse
	case func() bool { _, err := r.GetModifyMessage(); return err == nil }():
		app = gldap.ApplicationModifyResponse
	case func() bool { _, err := r.GetDeleteMessage(); return err == nil }():
		app = gldap.ApplicationDelResponse
	}
	resp := r.NewResponse(gldap.WithResponseCode(gldap.ResultInsufficientAccessRights), gldap.WithApplicationCode(app))
	resp.SetDiagnosticMessage("directory is read-only")
	_ = w.Write(resp)
}

func (s *Server) handleDefault(w *gldap.ResponseWriter, r *gldap.Request) {
	_ = w.Write(r.NewResponse(gldap.WithResponseCode(gldap.ResultUnwillingToPerform)))
}
