# Ethereum Engine API Proxy

## Installation

- Go 1.18 installed

```
go install github.com/rauljordan/engine-proxy@latest
```

## Usage

Launches a proxy middleware server for spoofing engine API calls between Ethereum consensus and execution clients via JSON-RPC. Allows for customizing in-flight responses using custom triggers.

Listens on localhost:8546 by default, so point a consensus client to http://localhost:8546 to see it in action. With default settings, it will just serve as a passthrough proxy to an execution client, so normal operations will be unaffected.

Supports passing in a -spoofing-config file path to a YAML file with the following format:

```yaml
requests:
  - method: engine_newPayloadV1
    fields:
      parentHash: "0x0000000000000000000000000000000000000000000000000000000000000000"
responses:
  - method: engine_exchangeTransitionConfigurationV1
    fields:
      terminalBlockHash: "0x0000000000000000000000000000000000000000000000000000000000000000"
```

Specifying which fields of requests and/or responses to engine API calls we want to modify. **NOTE**: nested fields are not yet supported.

**Flags**
- --eth-rpc-endpoint string: execution client endpoint (default: "http://127.0.0.1:8545")
- --host string: host for the HTTP proxy server (default: "127.0.0.1")
- --port int: port for the HTTP proxy server (default: 8546)
- --spoofing-config string: path to a YAML file containing a spoofing config
- --jwt-secret string: path to file containing a JWT secret hex-string used for authentication via HTTP. WORK IN PROGRESS

## Developing

Github actions run tests, lint, and building. Ensure your code is formatted with gofmt and goimports before submitting a pull request. Tests can be run with:
```
go test ./... -v
```

## License

MIT