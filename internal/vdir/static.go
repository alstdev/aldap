// Package vdir is the virtual directory: it answers Bind and Search for one
// profile by rewriting client requests into upstream searches and upstream
// results into the virtual tree of SPEC §4.1: root DSE, minimal subschema,
// container entries, users under ou=users (allowlist, renames, computed and
// masked attributes, object class mapping), virtual groups under ou=groups
// with member/memberOf, honeytokens, honeypot and mock modes.
package vdir

import (
	"sort"
	"strings"

	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/profile"
)

// OIDs advertised in the root DSE.
const (
	oidPagedResults = "1.2.840.113556.1.4.319"
	oidStartTLS     = "1.3.6.1.4.1.1466.20037"
)

// entry is an in-memory entry with case-insensitive attribute lookup.
type entry struct {
	dn    string
	attrs []listener.Attribute
	// dnCanon memoizes the canonical form of DN-syntax attribute values
	// (lower-case attribute name → canonical values), so a filter with many
	// member/memberOf terms parses every value once per entry, not per term.
	dnCanon map[string][]string
}

// canonValues returns the canonical DN forms of the values of a DN-syntax
// attribute, computed once per entry (match.go equal).
func (e *entry) canonValues(attr string) []string {
	key := strings.ToLower(attr)
	if v, ok := e.dnCanon[key]; ok {
		return v
	}
	vals := e.get(attr)
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if dn, err := ldapfilter.ParseDN(v); err == nil {
			out = append(out, dn.Canonical())
		}
	}
	if e.dnCanon == nil {
		e.dnCanon = map[string][]string{}
	}
	e.dnCanon[key] = out
	return out
}

func (e *entry) add(name string, values ...string) {
	if len(values) == 0 {
		return
	}
	delete(e.dnCanon, strings.ToLower(name))
	for i := range e.attrs {
		if strings.EqualFold(e.attrs[i].Name, name) {
			e.attrs[i].Values = append(e.attrs[i].Values, values...)
			return
		}
	}
	e.attrs = append(e.attrs, listener.Attribute{Name: name, Values: values})
}

// set replaces the values of an attribute (removing it when none are given).
func (e *entry) set(name string, values ...string) {
	delete(e.dnCanon, strings.ToLower(name))
	for i := range e.attrs {
		if strings.EqualFold(e.attrs[i].Name, name) {
			if len(values) == 0 {
				e.attrs = append(e.attrs[:i], e.attrs[i+1:]...)
				return
			}
			e.attrs[i].Values = append([]string(nil), values...)
			return
		}
	}
	e.add(name, values...)
}

func (e *entry) get(name string) []string {
	for _, a := range e.attrs {
		if strings.EqualFold(a.Name, name) {
			return a.Values
		}
	}
	return nil
}

// project returns the entry with only the requested attributes (empty =
// all), in listener form. Operational attributes are returned only when
// named explicitly, like every other attribute.
func (e *entry) project(want map[string]bool, all bool) listener.Entry {
	out := listener.Entry{DN: e.dn}
	for _, a := range e.attrs {
		if all || want[strings.ToLower(a.Name)] {
			out.Attrs = append(out.Attrs, listener.Attribute{Name: a.Name, Values: append([]string(nil), a.Values...)})
		}
	}
	return out
}

// containerEntry builds the entry of the virtual base or one of its OUs.
func containerEntry(dn *ldapfilter.DN, description string) *entry {
	e := &entry{dn: dn.String()}
	rdn := dn.RDN()
	e.add("objectClass", "top")
	if len(rdn.AVAs) == 1 {
		ava := rdn.AVAs[0]
		switch strings.ToLower(ava.Type) {
		case "ou":
			e.add("objectClass", "organizationalUnit")
		case "dc":
			e.add("objectClass", "domain")
		case "o":
			e.add("objectClass", "organization")
		default:
			e.add("objectClass", "container")
		}
		e.add(ava.Type, ava.Value)
	} else {
		e.add("objectClass", "container")
	}
	if description != "" {
		e.add("description", description)
	}
	return e
}

// rootDSE builds the root DSE (SPEC §4.1).
func rootDSE(r *profile.Rules, version string, startTLS bool) *entry {
	e := &entry{dn: ""}
	e.add("objectClass", "top")
	e.add("namingContexts", r.VirtualBase.String())
	e.add("defaultNamingContext", r.VirtualBase.String())
	e.add("subschemaSubentry", profile.Subschema)
	e.add("supportedLDAPVersion", "3")
	e.add("supportedControl", oidPagedResults)
	if startTLS {
		e.add("supportedExtension", oidStartTLS)
	}
	e.add("vendorName", "ALDAP")
	if version != "" {
		e.add("vendorVersion", version)
	}
	return e
}

// Well-known attribute type OIDs used in the minimal subschema. Attributes
// of attrs.allow without an entry here are left out of the schema rather
// than given an invented OID (docs/DECISIONS.md).
var attributeOIDs = map[string]struct{ oid, syntax string }{
	"objectclass":       {"2.5.4.0", "1.3.6.1.4.1.1466.115.121.1.38"},
	"cn":                {"2.5.4.3", "1.3.6.1.4.1.1466.115.121.1.15"},
	"sn":                {"2.5.4.4", "1.3.6.1.4.1.1466.115.121.1.15"},
	"c":                 {"2.5.4.6", "1.3.6.1.4.1.1466.115.121.1.15"},
	"l":                 {"2.5.4.7", "1.3.6.1.4.1.1466.115.121.1.15"},
	"st":                {"2.5.4.8", "1.3.6.1.4.1.1466.115.121.1.15"},
	"street":            {"2.5.4.9", "1.3.6.1.4.1.1466.115.121.1.15"},
	"o":                 {"2.5.4.10", "1.3.6.1.4.1.1466.115.121.1.15"},
	"ou":                {"2.5.4.11", "1.3.6.1.4.1.1466.115.121.1.15"},
	"title":             {"2.5.4.12", "1.3.6.1.4.1.1466.115.121.1.15"},
	"description":       {"2.5.4.13", "1.3.6.1.4.1.1466.115.121.1.15"},
	"telephonenumber":   {"2.5.4.20", "1.3.6.1.4.1.1466.115.121.1.50"},
	"member":            {"2.5.4.31", "1.3.6.1.4.1.1466.115.121.1.12"},
	"givenname":         {"2.5.4.42", "1.3.6.1.4.1.1466.115.121.1.15"},
	"initials":          {"2.5.4.43", "1.3.6.1.4.1.1466.115.121.1.15"},
	"uid":               {"0.9.2342.19200300.100.1.1", "1.3.6.1.4.1.1466.115.121.1.15"},
	"mail":              {"0.9.2342.19200300.100.1.3", "1.3.6.1.4.1.1466.115.121.1.26"},
	"dc":                {"0.9.2342.19200300.100.1.25", "1.3.6.1.4.1.1466.115.121.1.26"},
	"mobile":            {"0.9.2342.19200300.100.1.41", "1.3.6.1.4.1.1466.115.121.1.50"},
	"displayname":       {"2.16.840.1.113730.3.1.241", "1.3.6.1.4.1.1466.115.121.1.15"},
	"employeenumber":    {"2.16.840.1.113730.3.1.3", "1.3.6.1.4.1.1466.115.121.1.15"},
	"employeetype":      {"2.16.840.1.113730.3.1.4", "1.3.6.1.4.1.1466.115.121.1.15"},
	"department":        {"1.2.840.113556.1.2.141", "1.3.6.1.4.1.1466.115.121.1.15"},
	"company":           {"1.2.840.113556.1.2.146", "1.3.6.1.4.1.1466.115.121.1.15"},
	"memberof":          {"1.2.840.113556.1.2.102", "1.3.6.1.4.1.1466.115.121.1.12"},
	"objectguid":        {"1.2.840.113556.1.4.2", "1.3.6.1.4.1.1466.115.121.1.40"},
	"samaccountname":    {"1.2.840.113556.1.4.221", "1.3.6.1.4.1.1466.115.121.1.15"},
	"userprincipalname": {"1.2.840.113556.1.4.656", "1.3.6.1.4.1.1466.115.121.1.15"},
	"gidnumber":         {"1.3.6.1.1.1.1.1", "1.3.6.1.4.1.1466.115.121.1.27"},
	"uidnumber":         {"1.3.6.1.1.1.1.0", "1.3.6.1.4.1.1466.115.121.1.27"},
}

// objectClassDefs are the object classes of the virtual tree.
var objectClassDefs = []string{
	"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
	"( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou MAY description )",
	"( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top STRUCTURAL MUST dc MAY description )",
	"( 2.5.6.4 NAME 'organization' SUP top STRUCTURAL MUST o MAY description )",
	"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( telephoneNumber $ description ) )",
	"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ( title $ ou $ st $ l $ street ) )",
	"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( displayName $ employeeNumber $ employeeType $ givenName $ initials $ mail $ mobile $ uid ) )",
	"( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( member $ cn ) MAY description )",
	"( 1.3.6.1.1.1.2.2 NAME 'posixGroup' SUP top STRUCTURAL MUST ( cn $ gidNumber ) MAY description )",
}

// subschema builds the minimal cn=Subschema entry: the attribute types the
// profile exposes (when their OID is known) and the object classes of the
// virtual tree.
func subschema(r *profile.Rules) *entry {
	e := &entry{dn: profile.Subschema}
	e.add("objectClass", "top", "subschema")
	e.add("cn", "Subschema")
	names := append(r.AllowedAttrs(), "objectClass", "cn", "ou", "dc", "o", "description", "member")
	sort.Strings(names)
	seen := map[string]bool{}
	for _, n := range names {
		l := strings.ToLower(n)
		def, ok := attributeOIDs[l]
		if !ok || seen[l] {
			continue
		}
		seen[l] = true
		e.add("attributeTypes", "( "+def.oid+" NAME '"+n+"' SYNTAX "+def.syntax+" )")
	}
	e.add("objectClasses", objectClassDefs...)
	return e
}
