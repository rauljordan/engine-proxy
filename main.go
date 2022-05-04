package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	"github.com/rauljordan/engine-proxy/proxy"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
)

var (
	endpointFlag = &cli.StringFlag{
		Name:  "eth-rpc-endpoint",
		Value: "http://127.0.0.1:8545",
	}
	hostFlag = &cli.StringFlag{
		Name:  "host",
		Value: "127.0.0.1",
		Usage: "host for the HTTP proxy server",
	}
	portFlag = &cli.IntFlag{
		Name:  "port",
		Value: 8546,
		Usage: "port for the HTTP proxy server",
	}
	jwtSecretFlag = &cli.StringFlag{
		Name:  "jwt-secret",
		Usage: "path to file containing a hex-string JWT secret for authenticating with an execution client via HTTP",
	}
	spoofingConfig = &cli.StringFlag{
		Name:  "spoofing-config",
		Usage: "path to YAML file containing a configuration for spoofing engine API requests. See README.md for details",
	}
)

func main() {
	app := cli.NewApp()
	app.Name = "engine-proxy"
	app.Usage = "runs a proxy server for testing the Ethereum engine API"
	app.Version = "0.0.1"
	app.Description = "Launches a proxy middleware server for spoofing engine API calls between Ethereum consensus and " +
		"execution clients via JSON-RPC. Allows for customizing in-flight responses using custom triggers."
	app.Authors = []*cli.Author{
		{Name: "Raul Jordan", Email: "raul@prysmaticlabs.com"},
	}
	app.Flags = []cli.Flag{
		endpointFlag,
		hostFlag,
		portFlag,
		spoofingConfig,
		jwtSecretFlag,
	}
	app.Copyright = "2022"
	app.Action = runProxy
	if err := app.Run(os.Args); err != nil {
		logrus.Errorf("Could not run app: %v", err)
	}
}

func runProxy(c *cli.Context) error {
	ctx, cancel := context.WithCancel(c.Context)
	// Graceful shutdown of server on signal interruption via context cancellation.
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		cancel()
	}()
	host := c.String(hostFlag.Name)
	port := c.Int(portFlag.Name)
	destinationAddress := c.String(endpointFlag.Name)
	spoofingConfigPath := c.String(spoofingConfig.Name)

	opts := []proxy.Option{
		proxy.WithHost(host),
		proxy.WithPort(port),
		proxy.WithDestinationAddress(destinationAddress),
	}
	if spoofingConfigPath != "" {
		cfg, err := parseSpoofingConfig(spoofingConfigPath)
		if err != nil {
			return errors.Wrap(err, "could not parse spoofing config yaml file")
		}
		opts = append(opts, proxy.WithSpootingConfig(cfg))
	}

	srv, err := proxy.New(opts...)
	if err != nil {
		return errors.Wrap(err, "failed to initialize proxy server")
	}
	if err = srv.Start(ctx); err != nil {
		return errors.Wrap(err, "failed to start proxy server")
	}
	return nil
}

func parseSpoofingConfig(filePath string) (*proxy.SpoofingConfig, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = f.Close(); err != nil {
			panic(err)
		}
	}()
	cfg := &proxy.SpoofingConfig{}
	if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}