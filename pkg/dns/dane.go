package dns

import "fmt"

//TLSAResourceData TLSA resource data structure
//https://tools.ietf.org/html/rfc6698#section-2.1
type TLSAResourceData struct {
	Usage     uint8  //Certificate Usage: 0: CA constraint, 1: service cert constraint, 2:  trust anchor assertion, 3:  domain-issued cert
	Selector  uint8  // Selector: 0: full cert, 1: subject public key info
	MatchType uint8  // Matching Type: 0: exact match of full content, 1: SHA-256 match, 2: SHA-512 match
	Data      string // Certificate association Data field (hex encoding)
	Name      string
}

// A TLSAResource is a TLSA Resource record.
type TLSAResource struct {
	Name         string
	Alias        []string
	ResourceData []*TLSAResourceData
}

func (r *TLSAResourceData) realType() Type {
	return TypeTLSA
}

// pack appends the wire format of the TLSAResource to msg.
func (r *TLSAResourceData) pack(msg []byte, compression map[string]int, compressionOff int) ([]byte, error) {
	return []byte{}, nil //todo - at the moment we don't care about sending data
}

// GoString implements fmt.GoStringer.GoString.
func (r *TLSAResourceData) GoString() string {
	return fmt.Sprintf("dns.TLSAResourceData{Usage: %d, Selector: %d, MatchType: %d, Data: %s}", r.Usage, r.Selector, r.MatchType, r.Data)
}

func unpackTLSAResourceData(msg []byte, off int, length uint16) (TLSAResourceData, error) {

	remainder := uint16(len(msg[off:]))
	if remainder < length {
		return TLSAResourceData{}, fmt.Errorf("Invalid TLSA resource. Expected data of at least length %d, but got message of length %d", length, remainder)
	}
	tlsa := TLSAResourceData{
		Usage:     msg[off],
		Selector:  msg[off+1],
		MatchType: msg[off+2],
		Data:      fmt.Sprintf("%x", msg[off+3:uint16(off)+length]),
	}

	return tlsa, nil
}
