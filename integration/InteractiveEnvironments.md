# Interactive test environments

## Table of contents

- [Interactive test environments](#interactive-test-environments)
  - [Table of contents](#table-of-contents)
  - [Code structure](#code-structure)
  - [Dependencies](#dependencies)
  - [Environments & scenarios](#environments--scenarios)
    - [Base Environment](#base-environment)
    - [Generic Test Environment](#generic-test-environment)
    - [Proxy test environment](#proxy-test-environment)
      - [Preparation](#preparation)
      - [Scenario. Proxy test #1](#scenario-proxy-test-1)
  - [Notes & recipes](#notes--recipes)
    - [Delays](#delays)
    - [Tmux for new users](#tmux-for-new-users)
    - [Guidelines for new test creation](#guidelines-for-new-test-creation)

## Code structure

```text
integration
├── generic                            #  Generic environment
│   ├── env-vars.sh                    #  
│   ├── visorA.json                    #
│   └── visorC.json                    #
├── messaging                          #  Messaging testing environment
│   ├── env-vars.sh                    # 
│   ├── visorA.json                    # 
│   └── visorC.json                    # 
├── proxy                              #  Proxy testing environment
│   ├── env-vars.sh                    #
│   ├── visorA.json                    #
│   └── visorC.json                    #
├── InteractiveEnvironments.md         #  You're reading it
├── intermediary-visorB.json           #  VisorB configurationS
├── run-base-env.sh                    #  base environment in detached tmux session
├── run-generic-env.sh                 #  generic environment in tmux
├── run-proxy-env.sh                   #  proxy  environment in tmux
├── start-restart-visorB.sh            #  script for restart in cycle VisorB
├── startup.sh                         #  add transports between visors
├── tear-down.sh                       #  tear down everything
├── test-messaging-loop.sh             #  Test script for messaging in infinite loop
├── test-messaging.sh                  #  Test one message between VisorA-VisorC, VisorC-VisorA
└── test-proxy.sh                      #  Test script for proxy
```

## Dependencies

1. `tmux` (required for `integration/run-*-env.sh` scripts)
2. `jq` (required for `integration/*/env-vars.sh` scripts)
3. `bash` v3.x or greater (or compatible shell)

**Notes for Mac OSX users**

1. Running `tmux` in `iterm2` is known to be faulty. Consider switching to an alternative terminal emulator.
2. To install `jq` and `tmux` via brew: `brew install jq tmux`


## Environments & scenarios

### Base Environment

Base environment with `skywire-services` running on localhost

Usage:
- as base for other environments as  `source ./intergration/run-base-env.sh` in other `run-*-env.sh` scripts
- standalone: `./integration/run-base-env.sh && tmux attach -t skywire`

### Generic Test Environment

The generic test environment will define the following:

- skywire-services running on localhost
- 3 `skywire-visor`s:
  - VisorA, VisorC running all apps
  - VisorB - intermediary visor without apps

**Run**

```bash
# Tear down everything
$ make integration-teardown

# Start all services and visors
$ make integration-run-generic

# Adds pre-defined transports
$ make integration-startup
```

**Stop**

This is the recommended way to stop environment:

```bash
$ tmux kill-session -t skywire
```

And optionally:

```bash
$ make integration-teardown
```

**Commands**

Instead of `../skywire/skywire-cli --rpc localhost:port [command]`, one can use:

- `CLI_A visor ls-tp` - list transports from visorA
- `CLI_B visor add-tp $PK_A` - add transport on visorB to visorA

Consult with `./integration/env-vars.sh` for details.

**Tests**

These tests assume that the generic environment is running (via the aforementioned steps).

- **TEST 1: Send messages back and forth once.**
    ```bash
    # To be run in the 'shell' tab of tmux.
    ./integration/test-messaging.sh 
    ```
- **TEST 2: Test send/receive with unstable VisorB.**
   1. Stop VisorB by switching to the 7th tmux window (`Ctrl+B` & `6`) and sending SIGTERM (`Ctrl-C`).
   2. Run the following in the same window:
      ```bash
      $ ./integration/start-restart-visorB.sh
      ```
   3. Switch to the `shell` window and run:
      ```bash
      ./integration/test-messaging-loop.sh
      ```

**Detailed Description**

The following steps will be performed:

1. copy sw*.json and start-restart-visorB.sh into skywire directory
2. Create 9 tmux windows:
   1. MSGD: dmsg-discovery
   2. MSG: dmsg-server
   3. TRD: transport-discovery
   4. RF: route-finder
   5. SN: setup-node
   6. VisorA: first skywire-visor with generic/visorA.json
   7. VisorB: first skywire-visor with intermediary-visorB.json
   8. VisorC: first skywire-visor with generic/visorC.json
   9. shell: new shell for interactive exploration
3. ENV-vars in shell-window:
   1. $MSG_PK, $SN_PK - public keys of dmsg-server and setup-node
   2. $PK_A, $PK_B, $PK_C - public keys of visor_A, visor_B, visor_C
   3. $RPC_A, $RPC_B, $RPC_C - `--rpc` param for ../skywire/skywire-cli
   4. $CHAT_A, $CHAT_B - addresses and ports for `skychat`-apps on visor_A and visor_C
4. Aliases in shell-window: `CLI_A`, `CLI_B`, `CLI_C`

### Proxy test environment

The proxy test environment will define the following:

- skywire-services running on localhost
- 3 `skywire-visor`s:
  - VisorA - running `proxy` app
  - VsorB - intermediary visor without apps
  - VisorC - running `proxy-client` app

#### Preparation

It's really tricky to make socks5 proxy work now from clean start.

Because `skysocks-client` needs:
- transport to VisorA
- VisorA must be running **before** start of `skysocks-client`

Recipe for clean start:

1. Run `make integration-teardown`
2. Start `./integration/run-proxy-env.sh`
3. Run `make integration-startup`
4. Stop VisorA, VisorB, VisorC
5. Restart all visors
6. Wait for message in VisorC logs about successful start of
skysocks-client
7. Check `lsof -i :9999` that it's really started
8. Check `curl -v --retry 5 --retry-connrefused 1  --connect-timeout 5 -x socks5://123456:@localhost:9999 https://www.google.com`


#### Scenario. Proxy test #1

1. `./integration/run-proxy-env.sh`
2. In `shell` window run: `./integration/test-proxy.sh`
3. Examine `./logs/proxy`

## Notes & recipes

### Delays

It's possible that a service could start earlier or later than needed.

Examine windows,  in case of failed service - restart it (E.g. `KeyUp`-`Enter`)

### Tmux for new users

1. Read `man tmux`
2. Run `tmux list-keys`
3. Find your `send-prefix` key: `tmux list-keys | grep send-prefix`
4. Use this prefix for switching between windows

### Guidelines for new test creation 

1. **Decide**:   
   - new test is new scenario in existing environments 
   - or new environment with new scenario
2. If existing environment is sufficient: 
   - create new script in `./integration` with name `test-[name of test].sh`
   - use existing `./integration/run*.sh` for inspiration
   - add section describing this scenario in this document
3. In case of need in special environment:
   - `cp -r ./integration/generic ./integration/[new environment]`
   - `cp  ./integraton/run-generic-env.sh ./integration/run-[new environment].sh`
   - modify whats needed
   - add section describing new environment and scenario(s) in this document
