package parser

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func Parse(resource dns.RR, zone string, timestamp time.Time, nameserver string) map[string]interface{} {
	observer := map[string]interface{}{
		"hostname": nameserver,
		"type":     "dns",
	}
	if ip, err := net.ResolveIPAddr("ip", nameserver); err == nil {
		observer["ip"] = ip.IP
	}
	// Parse the resource record
	parsed := rr(resource)
	return map[string]interface{}{
		"dns": parsed,
		"ecs": map[string]interface{}{
			"version": "1.4",
		},
		"event": map[string]interface{}{
			"category": "web",
			"dataset":  zone,
			"created":  timestamp.UTC(),
			"ingested": time.Now().UTC(),
			"kind":     "state",
			"original": resource.String(),
			"provider": "dns",
			"type":     "info",
		},
		"observer": observer,
	}
}

func rr(resource dns.RR) map[string]interface{} {
	// Default RR
	result := map[string]interface{}{
		"name": resource.Header().Name,
		"type": dns.TypeToString[resource.Header().Rrtype],
	}
	tld, sld := name(resource.Header().Name)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	// RR Type
	if t, ok := dns.TypeToString[resource.Header().Rrtype]; ok {
		result["type"] = t
	} else {
		result["type"] = resource.Header().Rrtype
	}
	// RR Class
	if c, ok := dns.ClassToString[resource.Header().Class]; ok {
		result["class"] = c
	} else {
		result["class"] = resource.Header().Class
	}
	// RDATA
	switch resource.Header().Rrtype {
	case dns.TypeA:
		if original, ok := resource.(*dns.A); ok {
			result["rdata"] = a(original)
		}
	case dns.TypeNS:
		if original, ok := resource.(*dns.NS); ok {
			result["rdata"] = ns(original)
		}
	case dns.TypeMD:
		if original, ok := resource.(*dns.MD); ok {
			result["rdata"] = md(original)
		}
	case dns.TypeMF:
		if original, ok := resource.(*dns.MF); ok {
			result["rdata"] = mf(original)
		}
	case dns.TypeCNAME:
		if original, ok := resource.(*dns.CNAME); ok {
			result["rdata"] = cname(original)
		}
	case dns.TypeSOA:
		if original, ok := resource.(*dns.SOA); ok {
			result["rdata"] = soa(original)
		}
	case dns.TypeMB:
		if original, ok := resource.(*dns.MB); ok {
			result["rdata"] = mb(original)
		}
	case dns.TypeMG:
		if original, ok := resource.(*dns.MG); ok {
			result["rdata"] = mg(original)
		}
	case dns.TypeMR:
		if original, ok := resource.(*dns.MR); ok {
			result["rdata"] = mr(original)
		}
	case dns.TypeNULL:
		if original, ok := resource.(*dns.NULL); ok {
			result["rdata"] = null(original)
		}
	case dns.TypePTR:
		if orignal, ok := resource.(*dns.PTR); ok {
			result["rdata"] = ptr(orignal)
		}
	case dns.TypeHINFO:
		if original, ok := resource.(*dns.HINFO); ok {
			result["rdata"] = hinfo(original)
		}
	case dns.TypeMINFO:
		if original, ok := resource.(*dns.MINFO); ok {
			result["rdata"] = minfo(original)
		}
	case dns.TypeMX:
		if original, ok := resource.(*dns.MX); ok {
			result["rdata"] = mx(original)
		}
	case dns.TypeTXT:
		if original, ok := resource.(*dns.TXT); ok {
			result["rdata"] = txt(original)
		}
	case dns.TypeRP:
		if original, ok := resource.(*dns.RP); ok {
			result["rdata"] = rp(original)
		}
	case dns.TypeAFSDB:
		if original, ok := resource.(*dns.AFSDB); ok {
			result["rdata"] = afsdb(original)
		}
	case dns.TypeX25:
		if original, ok := resource.(*dns.X25); ok {
			result["rdata"] = x25(original)
		}
	case dns.TypeRT:
		if original, ok := resource.(*dns.RT); ok {
			result["rdata"] = rt(original)
		}
	case dns.TypeNSAPPTR:
		if original, ok := resource.(*dns.NSAPPTR); ok {
			result["rdata"] = nsapptr(original)
		}
	case dns.TypeSIG:
		if original, ok := resource.(*dns.SIG); ok {
			result["rdata"] = sig(original)
		}
	case dns.TypeKEY:
		if original, ok := resource.(*dns.KEY); ok {
			result["rdata"] = key(original)
		}
	case dns.TypePX:
		if original, ok := resource.(*dns.PX); ok {
			result["rdata"] = px(original)
		}
	case dns.TypeGPOS:
		if original, ok := resource.(*dns.GPOS); ok {
			result["rdata"] = gpos(original)
		}
	case dns.TypeAAAA:
		if original, ok := resource.(*dns.AAAA); ok {
			result["rdata"] = aaaa(original)
		}
	case dns.TypeLOC:
		if original, ok := resource.(*dns.LOC); ok {
			result["rdata"] = loc(original)
		}
	case dns.TypeEID:
		if original, ok := resource.(*dns.EID); ok {
			result["rdata"] = eid(original)
		}
	case dns.TypeNIMLOC:
		if original, ok := resource.(*dns.NIMLOC); ok {
			result["rdata"] = nimloc(original)
		}
	case dns.TypeSRV:
		if original, ok := resource.(*dns.SRV); ok {
			result["rdata"] = srv(original)
		}
	case dns.TypeNAPTR:
		if original, ok := resource.(*dns.NAPTR); ok {
			result["rdata"] = naptr(original)
		}
	case dns.TypeKX:
		if original, ok := resource.(*dns.KX); ok {
			result["rdata"] = kx(original)
		}
	case dns.TypeCERT:
		if original, ok := resource.(*dns.CERT); ok {
			result["rdata"] = cert(original)
		}
	case dns.TypeDNAME:
		if original, ok := resource.(*dns.DNAME); ok {
			result["rdata"] = dname(original)
		}
	case dns.TypeOPT:
		if original, ok := resource.(*dns.OPT); ok {
			result["rdata"] = opt(original)
		}
	case dns.TypeDS:
		if original, ok := resource.(*dns.DS); ok {
			result["rdata"] = ds(original)
		}
	case dns.TypeSSHFP:
		if original, ok := resource.(*dns.SSHFP); ok {
			result["rdata"] = sshfp(original)
		}
	case dns.TypeRRSIG:
		if original, ok := resource.(*dns.RRSIG); ok {
			result["rdata"] = rrsig(original)
		}
	case dns.TypeNSEC:
		if original, ok := resource.(*dns.NSEC); ok {
			result["rdata"] = nsec(original)
		}
	case dns.TypeDNSKEY:
		if original, ok := resource.(*dns.DNSKEY); ok {
			result["rdata"] = dnskey(original)
		}
	case dns.TypeDHCID:
		if original, ok := resource.(*dns.DHCID); ok {
			result["rdata"] = dhcid(original)
		}
	case dns.TypeNSEC3:
		if original, ok := resource.(*dns.NSEC3); ok {
			result["rdata"] = nsec3(original)
		}
	case dns.TypeNSEC3PARAM:
		if original, ok := resource.(*dns.NSEC3PARAM); ok {
			result["rdata"] = nsec3param(original)
		}
	case dns.TypeTLSA:
		if original, ok := resource.(*dns.TLSA); ok {
			result["rdata"] = tlsa(original)
		}
	case dns.TypeSMIMEA:
		if original, ok := resource.(*dns.SMIMEA); ok {
			result["rdata"] = smimea(original)
		}
	case dns.TypeHIP:
		if original, ok := resource.(*dns.HIP); ok {
			result["rdata"] = hip(original)
		}
	case dns.TypeNINFO:
		if original, ok := resource.(*dns.NINFO); ok {
			result["rdata"] = ninfo(original)
		}
	case dns.TypeRKEY:
		if original, ok := resource.(*dns.RKEY); ok {
			result["rdata"] = rkey(original)
		}
	case dns.TypeTALINK:
		if original, ok := resource.(*dns.TALINK); ok {
			result["rdata"] = talink(original)
		}
	case dns.TypeCDS:
		if original, ok := resource.(*dns.CDS); ok {
			result["rdata"] = cds(original)
		}
	case dns.TypeCDNSKEY:
		if original, ok := resource.(*dns.CDNSKEY); ok {
			result["rdata"] = cdnskey(original)
		}
	case dns.TypeOPENPGPKEY:
		if original, ok := resource.(*dns.OPENPGPKEY); ok {
			result["rdata"] = openpgpkey(original)
		}
	case dns.TypeCSYNC:
		if original, ok := resource.(*dns.CSYNC); ok {
			result["rdata"] = csync(original)
		}
	case dns.TypeSPF:
		if original, ok := resource.(*dns.SPF); ok {
			result["rdata"] = spf(original)
		}
	case dns.TypeUINFO:
		if original, ok := resource.(*dns.UINFO); ok {
			result["rdata"] = uinfo(original)
		}
	case dns.TypeUID:
		if original, ok := resource.(*dns.UID); ok {
			result["rdata"] = uid(original)
		}
	case dns.TypeGID:
		if original, ok := resource.(*dns.GID); ok {
			result["rdata"] = gid(original)
		}
	case dns.TypeNID:
		if original, ok := resource.(*dns.NID); ok {
			result["rdata"] = nid(original)
		}
	case dns.TypeL32:
		if original, ok := resource.(*dns.L32); ok {
			result["rdata"] = l32(original)
		}
	case dns.TypeL64:
		if original, ok := resource.(*dns.L64); ok {
			result["rdata"] = l64(original)
		}
	case dns.TypeLP:
		if original, ok := resource.(*dns.LP); ok {
			result["rdata"] = lp(original)
		}
	case dns.TypeEUI48:
		if original, ok := resource.(*dns.EUI48); ok {
			result["rdata"] = eui48(original)
		}
	case dns.TypeEUI64:
		if original, ok := resource.(*dns.EUI64); ok {
			result["rdata"] = eui64(original)
		}
	case dns.TypeURI:
		if original, ok := resource.(*dns.URI); ok {
			result["rdata"] = uri(original)
		}
	case dns.TypeCAA:
		if original, ok := resource.(*dns.CAA); ok {
			result["rdata"] = caa(original)
		}
	case dns.TypeAVC:
		if original, ok := resource.(*dns.AVC); ok {
			result["rdata"] = avc(original)
		}
	}
	return result
}

func a(rr *dns.A) map[string]interface{} {
	return map[string]interface{}{
		"ip": rr.A,
	}
}

func ns(rr *dns.NS) map[string]interface{} {
	result := map[string]interface{}{
		"name": rr.Ns,
	}
	tld, sld := name(rr.Ns)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func md(rr *dns.MD) map[string]interface{} {
	result := map[string]interface{}{
		"name": rr.Md,
	}
	tld, sld := name(rr.Md)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func mf(rr *dns.MF) map[string]interface{} {
	result := map[string]interface{}{
		"name": rr.Mf,
	}
	tld, sld := name(rr.Mf)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func cname(rr *dns.CNAME) map[string]interface{} {
	result := map[string]interface{}{
		"name": rr.Target,
	}
	tld, sld := name(rr.Target)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func soa(rr *dns.SOA) map[string]interface{} {
	result := map[string]interface{}{
		"name":    rr.Ns,
		"expire":  rr.Expire,
		"mbox":    rr.Mbox,
		"ttl":     rr.Minttl,
		"refresh": rr.Refresh,
		"retry":   rr.Retry,
		"serial":  rr.Serial,
	}
	tld, sld := name(rr.Ns)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func mb(rr *dns.MB) map[string]interface{} {
	result := map[string]interface{}{
		"name": rr.Mb,
	}
	tld, sld := name(rr.Mb)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func mg(rr *dns.MG) map[string]interface{} {
	result := map[string]interface{}{
		"name": rr.Mg,
	}
	tld, sld := name(rr.Mg)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func mr(rr *dns.MR) map[string]interface{} {
	result := map[string]interface{}{
		"name": rr.Mr,
	}
	tld, sld := name(rr.Mr)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func null(rr *dns.NULL) map[string]interface{} {
	return map[string]interface{}{
		"txt": rr.Data,
	}
}

func ptr(rr *dns.PTR) map[string]interface{} {
	result := map[string]interface{}{
		"name": rr.Ptr,
	}
	tld, sld := name(rr.Ptr)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func hinfo(rr *dns.HINFO) map[string]interface{} {
	return map[string]interface{}{
		"cpu": rr.Cpu,
		"os":  rr.Os,
	}
}

func minfo(rr *dns.MINFO) map[string]interface{} {
	return map[string]interface{}{
		"email": rr.Email,
		"rmail": rr.Rmail,
	}
}

func mx(rr *dns.MX) map[string]interface{} {
	result := map[string]interface{}{
		"name":       rr.Mx,
		"preference": rr.Preference,
	}
	tld, sld := name(rr.Mx)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func txt(rr *dns.TXT) map[string]interface{} {
	return map[string]interface{}{
		"txt": rr.Txt,
	}
}

func rp(rr *dns.RP) map[string]interface{} {
	return map[string]interface{}{
		"txt":  rr.Txt,
		"mbox": rr.Mbox,
	}
}

func afsdb(rr *dns.AFSDB) map[string]interface{} {
	result := map[string]interface{}{
		"name":    rr.Hostname,
		"subtype": rr.Subtype,
	}
	tld, sld := name(rr.Hostname)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func x25(rr *dns.X25) map[string]interface{} {
	return map[string]interface{}{
		"txt": rr.PSDNAddress,
	}
}

func rt(rr *dns.RT) map[string]interface{} {
	result := map[string]interface{}{
		"preference": rr.Preference,
		"name":       rr.Host,
	}
	tld, sld := name(rr.Host)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func nsapptr(rr *dns.NSAPPTR) map[string]interface{} {
	result := map[string]interface{}{
		"name": rr.Ptr,
	}
	tld, sld := name(rr.Ptr)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func sig(rr *dns.SIG) map[string]interface{} {
	result := map[string]interface{}{
		"expiration": rr.Expiration,
		"inception":  rr.Inception,
		"key_tag":    rr.KeyTag,
		"labels":     rr.Labels,
		"ttl":        rr.OrigTtl,
		"signature":  rr.Signature,
		"name":       rr.SignerName,
		"type":       rr.TypeCovered,
	}
	if algorithm, ok := dns.AlgorithmToString[rr.Algorithm]; ok {
		result["algoritm"] = algorithm
	} else {
		result["algoritm"] = rr.Algorithm
	}
	tld, sld := name(rr.SignerName)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func key(rr *dns.KEY) map[string]interface{} {
	result := map[string]interface{}{
		"flags":      fmt.Sprintf("%b", rr.Flags),
		"protocol":   rr.Protocol,
		"public_key": rr.PublicKey,
	}
	if algorithm, ok := dns.AlgorithmToString[rr.Algorithm]; ok {
		result["algoritm"] = algorithm
	} else {
		result["algoritm"] = rr.Algorithm
	}
	return result
}

func px(rr *dns.PX) map[string]interface{} {
	return map[string]interface{}{
		"preference": rr.Preference,
		"map882":     rr.Map822,
		"mapx400":    rr.Mapx400,
	}
}

func gpos(rr *dns.GPOS) map[string]interface{} {
	return map[string]interface{}{
		"altitude":  rr.Altitude,
		"latitude":  rr.Latitude,
		"longitude": rr.Longitude,
	}
}

func aaaa(rr *dns.AAAA) map[string]interface{} {
	return map[string]interface{}{
		"ip": rr.AAAA,
	}
}

func loc(rr *dns.LOC) map[string]interface{} {
	return map[string]interface{}{
		"longitude": rr.Longitude,
		"latitude":  rr.Latitude,
		"altitude":  rr.Altitude,
		"horiz_pre": rr.HorizPre,
		"size":      rr.Size,
		"version":   rr.Version,
		"vert_pre":  rr.VertPre,
	}
}

func eid(rr *dns.EID) map[string]interface{} {
	return map[string]interface{}{
		"endpoint": rr.Endpoint,
	}
}

func nimloc(rr *dns.NIMLOC) map[string]interface{} {
	return map[string]interface{}{
		"locator": rr.Locator,
	}
}

func srv(rr *dns.SRV) map[string]interface{} {
	result := map[string]interface{}{
		"port":     rr.Port,
		"priority": rr.Priority,
		"weight":   rr.Weight,
		"name":     rr.Target,
	}
	tld, sld := name(rr.Target)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func naptr(rr *dns.NAPTR) map[string]interface{} {
	return map[string]interface{}{
		"preference":  rr.Preference,
		"flags":       rr.Flags,
		"order":       rr.Order,
		"regexp":      rr.Regexp,
		"replacement": rr.Replacement,
		"service":     rr.Service,
	}
}

func kx(rr *dns.KX) map[string]interface{} {
	result := map[string]interface{}{
		"preference": rr.Preference,
		"name":       rr.Exchanger,
	}
	tld, sld := name(rr.Exchanger)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func cert(rr *dns.CERT) map[string]interface{} {
	result := map[string]interface{}{
		"key_tag":     rr.KeyTag,
		"certificate": rr.Certificate,
		"type":        rr.Type,
	}
	if algorithm, ok := dns.AlgorithmToString[rr.Algorithm]; ok {
		result["algorithm"] = algorithm
	} else {
		result["algorithm"] = rr.Algorithm
	}
	return result
}

func dname(rr *dns.DNAME) map[string]interface{} {
	result := map[string]interface{}{
		"name": rr.Target,
	}
	tld, sld := name(rr.Target)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func opt(rr *dns.OPT) map[string]interface{} {
	options := make([]uint16, len(rr.Option))
	for _, option := range rr.Option {
		options = append(options, option.Option())
	}
	return map[string]interface{}{
		"option": options,
	}
}

func ds(rr *dns.DS) map[string]interface{} {
	result := map[string]interface{}{
		"key_tag":     rr.KeyTag,
		"digest":      rr.Digest,
		"digest_type": rr.DigestType,
	}
	if algorithm, ok := dns.AlgorithmToString[rr.Algorithm]; ok {
		result["algorithm"] = algorithm
	} else {
		result["algorithm"] = algorithm
	}
	return result
}

func sshfp(rr *dns.SSHFP) map[string]interface{} {
	result := map[string]interface{}{
		"type":         rr.Type,
		"finger_print": rr.FingerPrint,
	}
	if algorithm, ok := dns.AlgorithmToString[rr.Algorithm]; ok {
		result["algorithm"] = algorithm
	} else {
		result["algorithm"] = algorithm
	}
	return result
}

func rrsig(rr *dns.RRSIG) map[string]interface{} {
	result := map[string]interface{}{
		"key_tag":    rr.KeyTag,
		"type":       rr.TypeCovered,
		"name":       rr.SignerName,
		"signature":  rr.Signature,
		"ttl":        rr.OrigTtl,
		"labels":     rr.Labels,
		"inception":  rr.Inception,
		"expiration": rr.Expiration,
	}
	if algorithm, ok := dns.AlgorithmToString[rr.Algorithm]; ok {
		result["algorithm"] = algorithm
	} else {
		result["algorithm"] = algorithm
	}
	tld, sld := name(rr.SignerName)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func nsec(rr *dns.NSEC) map[string]interface{} {
	result := map[string]interface{}{
		"name":         rr.NextDomain,
		"type_bit_map": rr.TypeBitMap,
	}
	tld, sld := name(rr.NextDomain)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func dnskey(rr *dns.DNSKEY) map[string]interface{} {
	result := map[string]interface{}{
		"public_key": rr.PublicKey,
		"protocol":   rr.Protocol,
		"flags":      fmt.Sprintf("%b", rr.Flags),
	}
	if algorithm, ok := dns.AlgorithmToString[rr.Algorithm]; ok {
		result["algorithm"] = algorithm
	} else {
		result["algorithm"] = algorithm
	}
	return result
}

func dhcid(rr *dns.DHCID) map[string]interface{} {
	return map[string]interface{}{
		"digest": rr.Digest,
	}
}

func nsec3(rr *dns.NSEC3) map[string]interface{} {
	result := map[string]interface{}{
		"type_bit_map": rr.TypeBitMap,
		"name":         rr.NextDomain,
		"flags":        fmt.Sprintf("%b", rr.Flags),
		"hash_length":  rr.HashLength,
		"hash":         rr.Hash,
		"salt_length":  rr.SaltLength,
		"salt":         rr.Salt,
		"iterations":   rr.Iterations,
	}
	tld, sld := name(rr.NextDomain)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func nsec3param(rr *dns.NSEC3PARAM) map[string]interface{} {
	return map[string]interface{}{
		"iterations":  rr.Iterations,
		"hash":        rr.Hash,
		"salt":        rr.Salt,
		"salt_length": rr.SaltLength,
		"flags":       fmt.Sprintf("%b", rr.Flags),
	}
}

func tlsa(rr *dns.TLSA) map[string]interface{} {
	return map[string]interface{}{
		"certificate": rr.Certificate,
		"type":        rr.MatchingType,
		"selector":    rr.Selector,
		"usage":       rr.Usage,
	}
}

func smimea(rr *dns.SMIMEA) map[string]interface{} {
	return map[string]interface{}{
		"certificate": rr.Certificate,
		"type":        rr.MatchingType,
		"selector":    rr.Selector,
		"usage":       rr.Usage,
	}
}

func hip(rr *dns.HIP) map[string]interface{} {
	result := map[string]interface{}{
		"public_key":        rr.PublicKey,
		"hit":               rr.Hit,
		"hit_length":        rr.HitLength,
		"public_key_length": rr.PublicKeyLength,
		"name":              rr.RendezvousServers,
	}
	if algorithm, ok := dns.AlgorithmToString[rr.PublicKeyAlgorithm]; ok {
		result["algorithm"] = algorithm
	} else {
		result["algorithm"] = rr.PublicKeyAlgorithm
	}
	tld, sld := name(rr.RendezvousServers...)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func ninfo(rr *dns.NINFO) map[string]interface{} {
	return map[string]interface{}{
		"txt": rr.ZSData,
	}
}

func rkey(rr *dns.RKEY) map[string]interface{} {
	result := map[string]interface{}{
		"public_key": rr.PublicKey,
		"protocol":   rr.Protocol,
		"flags":      fmt.Sprintf("%b", rr.Flags),
	}
	if algorithm, ok := dns.AlgorithmToString[rr.Algorithm]; ok {
		result["algorithm"] = algorithm
	} else {
		result["algorithm"] = rr.Algorithm
	}
	return result
}

func talink(rr *dns.TALINK) map[string]interface{} {
	n := []string{
		rr.NextName,
		rr.PreviousName,
	}
	result := map[string]interface{}{
		"next_name":     rr.NextName,
		"previous_name": rr.PreviousName,
		"name":          n,
	}
	tld, sld := name(n...)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func cds(rr *dns.CDS) map[string]interface{} {
	result := map[string]interface{}{
		"digest":      rr.Digest,
		"key_tag":     rr.KeyTag,
		"digest_type": rr.DigestType,
	}
	if algorithm, ok := dns.AlgorithmToString[rr.Algorithm]; ok {
		result["algorithm"] = algorithm
	} else {
		result["algorithm"] = rr.Algorithm
	}
	return result
}

func cdnskey(rr *dns.CDNSKEY) map[string]interface{} {
	result := map[string]interface{}{
		"protocol":   rr.Protocol,
		"public_key": rr.PublicKey,
		"flags":      fmt.Sprintf("%b", rr.Flags),
	}
	if algorithm, ok := dns.AlgorithmToString[rr.Algorithm]; ok {
		result["algorithm"] = algorithm
	} else {
		result["algorithm"] = rr.Algorithm
	}
	return result
}

func openpgpkey(rr *dns.OPENPGPKEY) map[string]interface{} {
	return map[string]interface{}{
		"public_key": rr.PublicKey,
	}
}

func csync(rr *dns.CSYNC) map[string]interface{} {
	return map[string]interface{}{
		"type_bit_map": rr.TypeBitMap,
		"flags":        fmt.Sprintf("%b", rr.Flags),
		"serial":       rr.Serial,
	}
}

func spf(rr *dns.SPF) map[string]interface{} {
	return map[string]interface{}{
		"txt": rr.Txt,
	}
}

func uinfo(rr *dns.UINFO) map[string]interface{} {
	return map[string]interface{}{
		"txt": rr.Uinfo,
	}
}

func uid(rr *dns.UID) map[string]interface{} {
	return map[string]interface{}{
		"uid": rr.Uid,
	}
}

func gid(rr *dns.GID) map[string]interface{} {
	return map[string]interface{}{
		"gid": rr.Gid,
	}
}

func nid(rr *dns.NID) map[string]interface{} {
	return map[string]interface{}{
		"node_id":    rr.NodeID,
		"preference": rr.Preference,
	}
}

func l32(rr *dns.L32) map[string]interface{} {
	return map[string]interface{}{
		"preference": rr.Preference,
		"ip":         rr.Locator32,
	}
}

// TODO: Convert int64 to IPv6
func l64(rr *dns.L64) map[string]interface{} {
	return map[string]interface{}{
		"preference": rr.Preference,
		"txt":        rr.Locator64,
	}
}

func lp(rr *dns.LP) map[string]interface{} {
	result := map[string]interface{}{
		"name":       rr.Fqdn,
		"preference": rr.Preference,
	}
	tld, sld := name(rr.Fqdn)
	if len(tld) > 0 {
		result["tld"] = tld
	}
	if len(sld) > 0 {
		result["sld"] = sld
	}
	return result
}

func eui48(rr *dns.EUI48) map[string]interface{} {
	return map[string]interface{}{
		"address": rr.Address,
	}
}

func eui64(rr *dns.EUI64) map[string]interface{} {
	return map[string]interface{}{
		"address": rr.Address,
	}
}

func uri(rr *dns.URI) map[string]interface{} {
	return map[string]interface{}{
		"target":   rr.Target,
		"weight":   rr.Weight,
		"priority": rr.Priority,
	}
}

func caa(rr *dns.CAA) map[string]interface{} {
	return map[string]interface{}{
		"flag":  fmt.Sprintf("%b", rr.Flag),
		"tag":   rr.Tag,
		"value": rr.Value,
	}
}

func avc(rr *dns.AVC) map[string]interface{} {
	return map[string]interface{}{
		"txt": rr.Txt,
	}
}

func name(names ...string) (tld, sld []string) {
	separator := func(c rune) bool {
		return c == '.'
	}
	for _, name := range names {
		parts := strings.FieldsFunc(name, separator)
		if len(parts) >= 1 {
			tld = append(tld, fmt.Sprintf("%s.", parts[len(parts)-1]))
			if len(parts) >= 2 {
				sld = append(sld, fmt.Sprintf("%s.%s.", parts[len(parts)-2], parts[len(parts)-1]))
			}
		}
	}
	return tld, sld
}
