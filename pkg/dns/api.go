package dns

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

var (

	//maxCopy is finger in the air prevention from some malicious dns overflowing us.
	//However, is reasonable given that 512 bytes is the limit for DNS over UDP
	maxCopy = 512
)

//AuditDANE gets an audit of a server's DANE records on the specified port and protocol
func AuditDANE(port int, protocol, server string, config Config) (DANEResult, error) {
	var result DANEResult
	server = strings.TrimSuffix(strings.TrimSpace(server), ".") + "." //ensure server ends with a .
	name := fmt.Sprintf("_%d._%s.%s", port, protocol, server)
	msg := Message{

		Header: Header{
			Response:         false,
			ID:               0xADE,
			RecursionDesired: true,
		},
		Questions: []Question{
			{
				Type:  Type(TypeTLSA),
				Class: ClassINET,
				Name:  MustNewName(name),
			},
		},
	}

	resolver := fmt.Sprintf("%s:%d", config.Resolver.IP, config.Resolver.Port)

	conn, err := net.Dial(config.Resolver.Protocol, resolver)

	if err != nil {
		log.Fatal("Failed to connect:", err)
		return result, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		log.Fatal("Unable to set deadline: ", err)
		return result, err
	}

	m, err := msg.Pack()
	if err != nil {
		log.Fatal("Error packing DNS request: ", err)
		return result, err
	}

	conn.Write(m)

	resp := make([]byte, maxCopy)
	n := 0
	if n, err = bufio.NewReader(conn).Read(resp); err != nil {
		log.Printf("Read %d bytes with error %s\n", n, err.Error())
		return result, err
	}

	dnsResp := Message{}
	if err := dnsResp.Unpack(resp); err != nil {
		log.Printf("Error unpacking DNS response: %e\n", err)
		return result, err
	}

	tlsa := TLSAResource{
		Name: name,
	}
	for _, a := range dnsResp.Answers {
		if tlsaRR, ok := a.Body.(*TLSAResourceData); ok {
			if tlsaRR.Name != name {
				tlsa.Alias = append(tlsa.Alias, tlsaRR.Name)
			}
			tlsa.ResourceData = append(tlsa.ResourceData, tlsaRR)
		}
	}

	result.TLSAResource = tlsa

	return result, nil
}
