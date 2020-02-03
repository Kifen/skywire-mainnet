package commands

import (
	"fmt"
	"net/http"
	"os"

	"github.com/SkycoinProject/dmsg"
	"github.com/SkycoinProject/dmsg/disc"

	"github.com/SkycoinProject/skycoin/src/util/logging"
	"github.com/spf13/cobra"

	"github.com/SkycoinProject/skywire-mainnet/pkg/hypervisor"
	"github.com/SkycoinProject/skywire-mainnet/pkg/util/buildinfo"
	"github.com/SkycoinProject/skywire-mainnet/pkg/util/pathutil"
)

const configEnv = "SW_HYPERVISOR_CONFIG"

// nolint:gochecknoglobals
var (
	log = logging.MustGetLogger("hypervisor")

	configPath     string
	mock           bool
	mockEnableAuth bool
	mockVisors     int
	mockMaxTps     int
	mockMaxRoutes  int
)

// nolint:gochecknoinits
func init() {
	rootCmd.Flags().StringVarP(&configPath, "config", "c", "./hypervisor-config.json", "hypervisor config path")
	rootCmd.Flags().BoolVarP(&mock, "mock", "m", false, "whether to run hypervisor with mock data")
	rootCmd.Flags().BoolVar(&mockEnableAuth, "mock-enable-auth", false, "whether to enable user management in mock mode")
	rootCmd.Flags().IntVar(&mockVisors, "mock-visors", 5, "number of visors to have in mock mode")
	rootCmd.Flags().IntVar(&mockMaxTps, "mock-max-tps", 10, "max number of transports per mock visor")
	rootCmd.Flags().IntVar(&mockMaxRoutes, "mock-max-routes", 30, "max number of routes per visor")
}

// nolint:gochecknoglobals
var rootCmd = &cobra.Command{
	Use:   "hypervisor",
	Short: "Manages Skywire Visors",
	Run: func(_ *cobra.Command, args []string) {
		if _, err := buildinfo.Get().WriteTo(os.Stdout); err != nil {
			log.Printf("Failed to output build info: %v", err)
		}

		if configPath == "" {
			configPath = pathutil.FindConfigPath(args, -1, configEnv, pathutil.HypervisorDefaults())
		}

		var config hypervisor.Config
		config.FillDefaults()
		if err := config.Parse(configPath); err != nil {
			log.WithError(err).Fatalln("failed to parse config file")
		}

		fmt.Println("Config: \n", config)

		var (
			httpAddr = config.Interfaces.HTTPAddr
			rpcAddr  = config.Interfaces.RPCAddr
		)

		m, err := hypervisor.New(config)
		if err != nil {
			log.Fatalln("Failed to start hypervisor:", err)
		}

		log.Infof("serving RPC on '%s'", rpcAddr)
		go func() {
			_, rpcPort, err := config.Interfaces.SplitRPCAddr()
			if err != nil {
				log.Fatalln("Failed to parse rpc port from rpc address:", err)
			}

			dmsgC := dmsg.NewClient(config.PK, config.SK, disc.NewHTTP(config.DmsgDiscovery), dmsg.DefaultConfig())
			go dmsgC.Serve()

			l, err := dmsgC.Listen(rpcPort)
			if err != nil {
				log.Fatalln("Failed to bind tcp port:", err)
			}

			if err := m.ServeRPC(l); err != nil {
				log.Fatalln("Failed to serve RPC:", err)
			}
		}()

		if mock {
			err := m.AddMockData(hypervisor.MockConfig{
				Visors:            mockVisors,
				MaxTpsPerVisor:    mockMaxTps,
				MaxRoutesPerVisor: mockMaxRoutes,
				EnableAuth:        mockEnableAuth,
			})
			if err != nil {
				log.Fatalln("Failed to add mock data:", err)
			}
		}

		log.Infof("serving HTTP on '%s'", httpAddr)
		if err := http.ListenAndServe(httpAddr, m); err != nil {
			log.Fatalln("Hypervisor exited with error:", err)
		}

		log.Println("Good bye!")
	},
}

// Execute executes root CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
