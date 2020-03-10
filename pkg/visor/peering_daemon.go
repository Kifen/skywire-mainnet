package visor

import (
	"fmt"
	"net"
	"net/rpc"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/SkycoinProject/dmsg/cipher"
	skycoin_cipher "github.com/SkycoinProject/skycoin/src/cipher"
	"github.com/SkycoinProject/skycoin/src/util/logging"
	spd "github.com/SkycoinProject/skywire-peering-daemon/pkg/daemon"

	"github.com/SkycoinProject/skywire-mainnet/pkg/snet"
)

var (
	logger          = logging.MustGetLogger("SPD")
	rpcDialTimeout  = time.Duration(5 * time.Second)
	rpcConnDuration = time.Duration(60 * time.Second)
	spdMu           sync.Mutex
)

func execute(cmd *exec.Cmd, pubKey, lAddr, socketFile string) error {
	pk := fmt.Sprintf("SPD_PUBKEY=%s", pubKey)
	la := fmt.Sprintf("SPD_LADDR=%s", lAddr)
	sf := fmt.Sprintf("SPD_SOCKETFILE=%s", socketFile)

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, pk, la, sf)
	cmd.Stdout = os.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}

	return nil
}

func client(rpcAddr string) (RPCClient, error) {
	conn, err := net.DialTimeout("tcp", rpcAddr, rpcDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("RPC connection failed: %s", err)
	}
	if err := conn.SetDeadline(time.Now().Add(rpcConnDuration)); err != nil {
		return nil, fmt.Errorf("RPC connection failed: %s", err)
	}
	return NewRPCClient(rpc.NewClient(conn), RPCPrefix), nil
}

// transport establshes an stcp transport to a remote visor
func createTransport(pubKey string, rpcAddr string) (*TransportSummary, error) {
	client, err := client(rpcAddr)
	if err != nil {
		return nil, err
	}

	logger.Infof("Establishing transport to remote visor")
	rPK := skycoin_cipher.MustPubKeyFromHex(pubKey)
	tpSummary, err := client.AddTransport(cipher.PubKey(rPK), snet.STcpType, true, 0)
	if err != nil {
		return nil, fmt.Errorf("Unable to establish stcp transport: %s", err)
	}

	return tpSummary, nil
}

func serveSpd(file string, m map[cipher.PubKey]string, rpcAddr string) error {
	listener, err := net.Listen("unix", file)
	if err != nil {
		return err
	}

	defer func() {
		err := listener.Close()
		if err != nil {
			logger.WithError(err)
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go readPacket(conn, m, rpcAddr)
	}
}

func readPacket(conn net.Conn, m map[cipher.PubKey]string, rpcAddr string) {
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			logger.Warnf("error on read: %s", err)
			break
		}

		packet, err := spd.Deserialize(buf[:n])
		if err != nil {
			logger.Error(err)
		}

		spdMu.Lock()
		rpk := skycoin_cipher.MustPubKeyFromHex(packet.PublicKey)
		m[cipher.PubKey(rpk)] = packet.IP
		spdMu.Unlock()

		logger.Infof("Packets received from skywire-peering-daemon:\n\t{%s: %s}", packet.PublicKey, packet.IP)
		tp, err := createTransport(packet.PublicKey, rpcAddr)
		if err != nil {
			logger.Errorf("Couldn't establish transport to remote visor: %s", err)
		} else {
			logger.Infof("Transport established to remote visor: \n%s", tp.Remote)
		}
	}
}
