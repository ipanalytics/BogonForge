package bogonforge

import "strings"

func DataPolicy(r IPRecord) []string {
	if r.Facts.Stability == "terminated" {
		return []string{"warn_if_seen_on_public_edge"}
	}
	var p []string
	if isFalse(r.Facts.GloballyReachable) {
		p = append(p, "exclude_from_geoip", "exclude_from_reputation", "exclude_from_provider_map")
	}
	if r.Class == "documentation" {
		p = appendUnique(p, "allow_in_examples")
	}
	if isFalse(r.Facts.SourceValid) || isFalse(r.Facts.DestinationValid) || r.Class == "loopback" || r.Class == "link-local" || r.Class == "reserved" {
		p = appendUnique(p, "warn_if_seen_on_public_edge")
	}
	return p
}

func EdgeDrop(records []IPRecord) []string {
	var out []string
	for _, r := range records {
		if r.Facts.Stability == "terminated" {
			continue
		}
		if isFalse(r.Facts.SourceValid) || r.Class == "private-use" || r.Class == "shared-address-space" || r.Class == "loopback" || r.Class == "link-local" || r.Class == "documentation" || r.Class == "reserved" || r.Class == "benchmarking" {
			out = append(out, r.Prefix)
		}
	}
	return uniqueSorted(out)
}

func LabAllow(records []IPRecord) []string {
	var out []string
	for _, r := range records {
		if r.Facts.Stability == "permanent" && r.Class == "documentation" {
			out = append(out, r.Prefix)
		}
	}
	return uniqueSorted(out)
}

func GeoIPExclude(records []IPRecord) []string {
	var out []string
	for _, r := range records {
		if contains(r.DatasetPolicy, "exclude_from_geoip") {
			out = append(out, r.Prefix)
		}
	}
	return uniqueSorted(out)
}

func ASNPolicy(r ASNRecord) []string {
	p := []string{"exclude_from_public_asn_identity"}
	if r.Class == "documentation" {
		p = append(p, "allow_in_examples")
	}
	return p
}

func classifyIP(name, prefix string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "documentation") || strings.Contains(n, "test-net"):
		return "documentation"
	case strings.Contains(n, "private-use") || strings.Contains(n, "unique-local"):
		return "private-use"
	case strings.Contains(n, "shared address"):
		return "shared-address-space"
	case strings.Contains(n, "loopback"):
		return "loopback"
	case strings.Contains(n, "link local") || strings.Contains(n, "link-local"):
		return "link-local"
	case strings.Contains(n, "benchmarking"):
		return "benchmarking"
	case strings.Contains(n, "reserved") || prefix == "240.0.0.0/4":
		return "reserved"
	case strings.Contains(n, "broadcast"):
		return "limited-broadcast"
	case strings.Contains(n, "as112"):
		return "as112"
	case strings.Contains(n, "deprecated"):
		return "deprecated"
	default:
		return slug(name)
	}
}

func classifyASN(reason string) string {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "documentation") || strings.Contains(r, "sample code"):
		return "documentation"
	case strings.Contains(r, "private use"):
		return "private-use"
	case strings.Contains(r, "as112"):
		return "as112"
	case strings.Contains(r, "as_trans"):
		return "as-trans"
	default:
		return "reserved"
	}
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func isFalse(v BoolValue) bool {
	return v != nil && !*v
}

func appendUnique(in []string, v string) []string {
	if contains(in, v) {
		return in
	}
	return append(in, v)
}

func contains(in []string, v string) bool {
	for _, x := range in {
		if x == v {
			return true
		}
	}
	return false
}
