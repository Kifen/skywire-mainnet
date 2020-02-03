# This script needs to be `source`d from bash-compatible shell
# E.g. `source ./integration/proxy/env-vars.sh` or `. ./integration/proxy/env-vars.sh`
export PK_A=$(jq -r ".visor.static_public_key" ./integration/proxy/visorA.json)
export RPC_A=$(jq -r ".interfaces.rpc" ./integration/proxy/visorA.json)
export PK_B=$(jq -r ".visor.static_public_key" ./integration/intermediary-visorB.json)
export RPC_B=$(jq -r ".interfaces.rpc" ./integration/intermediary-visorB.json)
export PK_C=$(jq -r ".visor.static_public_key" ./integration/proxy/visorC.json)
export RPC_C=$(jq -r ".interfaces.rpc" ./integration/proxy/visorC.json)

alias CLI_A='./skywire-cli --rpc $RPC_A'
alias CLI_B='./skywire-cli --rpc $RPC_B'
alias CLI_C='./skywire-cli --rpc $RPC_C'

export MSGD=https://dmsg.discovery.skywire.skycoin.com
export TRD=https://transport.discovery.skywire.skycoin.com
export RF=https://routefinder.skywire.skycoin.com

alias RUN_A='go run ./cmd/skywire-visor ./integration/messaging/visorA.json --tag VisorA'
alias RUN_B='go run ./cmd/skywire-visor ./integration/intermediary-visorB.json --tag VisorB'
alias RUN_C='go run ./cmd/skywire-visor ./integration/messaging/visorC.json --tag VisorC'

echo PK_A: $PK_A
echo PK_B: $PK_B
echo PK_C: $PK_C
