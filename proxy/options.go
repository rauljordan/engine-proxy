package proxy

import (
	"net/url"

	"github.com/pkg/errors"
)

type config struct {
	proxyPort      int
	proxyHost      string
	spoofing       *SpoofingConfig
	spoofCallbacks *SpoofingCallbacks
	destinationUrl *url.URL
	jwtSecret      []byte
}

type Option func(p *Proxy) error

// WithHost sets the proxy server host.
func WithHost(host string) Option {
	return func(p *Proxy) error {
		p.cfg.proxyHost = host
		return nil
	}
}

// WithPort sets the proxy server port.
func WithPort(port int) Option {
	return func(p *Proxy) error {
		p.cfg.proxyPort = port
		return nil
	}
}

// WithSpoofingConfig sets the proxy spoofing config.
func WithSpoofingConfig(c *SpoofingConfig) Option {
	return func(p *Proxy) error {
		p.cfg.spoofing = c
		return nil
	}
}

// WithSpoofingCallbacks sets the proxy spoofing callbacks.
func WithSpoofingCallbacks(c *SpoofingCallbacks) Option {
	return func(p *Proxy) error {
		p.cfg.spoofCallbacks = c
		return nil
	}
}

// WithDestinationAddress sets the forwarding address requests will be proxied to.
func WithDestinationAddress(addr string) Option {
	return func(p *Proxy) error {
		if addr == "" {
			return errors.New("must provide a destination address for proxy")
		}
		u, err := url.Parse(addr)
		if err != nil {
			return errors.Wrapf(err, "could not parse URL for destination address: %s", addr)
		}
		p.cfg.destinationUrl = u
		return nil
	}
}

// WithJWTSecret sets a JWT secret
func WithJWTSecret(secret []byte) Option {
	return func(p *Proxy) error {
		p.cfg.jwtSecret = secret
		return nil
	}
}
