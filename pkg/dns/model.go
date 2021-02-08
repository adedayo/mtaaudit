package dns

//Config various config options
type Config struct {
	Resolver Resolver //e.g. 8.8.8.8:53
}

//Resolver is a DNS resolver e.g. {8.8.8.8, 53, udp}
type Resolver struct {
	IP       string
	Port     int
	Protocol string
}

//DANEResult a summary of DANE configuration posture of a mail server
type DANEResult struct {
	TLSAResource TLSAResource
}
