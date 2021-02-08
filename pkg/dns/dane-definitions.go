package dns

//DANE certificate usage modes
const (
	//Certificate Usage: 0: CA constraint, 1: service cert constraint, 2:  trust anchor assertion, 3:  domain-issued cert
	CAConstraint         = 0
	ServiceCRTConstraint = 1
	TrustAnchorAssertion = 2
	DomainIssuedCert     = 4
)
