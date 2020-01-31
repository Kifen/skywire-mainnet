package skyenv

// Constants for default services.
const (
	DefaultTpDiscAddr      = "http://transport.discovery.skywire.skycoin.com"
	DefaultDmsgDiscAddr    = "http://dmsg.discovery.skywire.skycoin.com"
	DefaultRouteFinderAddr = "http://routefinder.skywire.skycoin.com"
	DefaultSetupPK         = "026c5a07de617c5c488195b76e8671bf9e7ee654d0633933e202af9e111ffa358d"
)

// Constants for testing deployment.
const (
	TestTpDiscAddr      = "http://transport.discovery.skywire.cc"
	TestDmsgDiscAddr    = "http://dmsg.discovery.skywire.cc"
	TestRouteFinderAddr = "http://routefinder.skywire.cc"
)

// Default dmsg ports.
const (
	DmsgSetupPort      = uint16(36)  // Listening port of a setup node.
	DmsgAwaitSetupPort = uint16(136) // Listening port of a visor for setup operations.
	DmsgTransportPort  = uint16(45)  // Listening port of a visor for incoming transports.
)

// Default dmsgpty constants.
const (
	DefaultDmsgPtyPort    = uint16(233)
	DefaultDmsgPtyCLINet  = "unix"
	DefaultDmsgPtyCLIAddr = "/tmp/dmsgpty.sock"
)

// Default skywire app constants.
const (
	SkychatName = "skychat"
	SkychatPort = uint16(1)
	SkychatAddr = ":8000"

	SkysocksName = "skysocks"
	SkysocksPort = uint16(3)

	SkysocksClientName = "skysocks-client"
	SkysocksClientPort = uint16(13)
	SkysocksClientAddr = ":1080"
	// TODO(evanlinjin): skysocks-client requires
)

// Default RetrierConfig constants
const (
	BackoffTime = 3
	Times       = 2
	Factor      = 1
)
