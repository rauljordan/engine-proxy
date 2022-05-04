# Ethereum Engine API Proxy

## Installation

- Go 1.18 installed

```
go install github.com/rauljordan/engine-proxy@latest
```

## Usage

Launches a proxy middleware server for spoofing engine API calls between Ethereum consensus and execution clients via JSON-RPC. Allows for customizing in-flight responses using custom triggers.

GLOBAL OPTIONS:
--eth-rpc-endpoint value  (default: "http://127.0.0.1:8545")
--host value              host for the HTTP proxy server (default: "127.0.0.1")
--port value              port for the HTTP proxy server (default: 8546)
--help, -h                show help (default: false)
--version, -v             print the version (default: false)


## Developing

```
go test ./... -v
```

## License

MIT