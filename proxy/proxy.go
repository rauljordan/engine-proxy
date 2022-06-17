// Package proxy provides a proxy middleware for engine API requests between Ethereum
// consensus clients and execution clients via JSON-RPC. Allows for customizing
// in-flight responses using custom triggers. Useful for performing advanced tests.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	defaultProxyHost = "127.0.0.1"
	defaultProxyPort = 8545
)

type SpoofingConfig struct {
	Requests  []*Spoof `yaml:"requests"`
	Responses []*Spoof `yaml:"responses"`
}

type SpoofingCallbacks struct {
	// Map of method names to callbacks, where the callback will receive the request bytes as only parameter
	RequestCallbacks map[string]func([]byte) *Spoof
	// Map of method names to callbacks, where the callback will receive the response bytes as 1st parameter,
	// and original request bytes as 2nd parameter
	ResponseCallbacks map[string]func([]byte, []byte) *Spoof
}

type Spoof struct {
	Method string                 `yaml:"method"`
	Fields map[string]interface{} `yaml:"fields"`
}

type jsonRPCObject struct {
	Jsonrpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      uint64        `json:"id"`
	Result  interface{}   `json:"result"`
}

// Proxy server that sits as a middleware between an Ethereum consensus client and an execution client,
// allowing us to modify in-flight requests and responses for testing purposes.
type Proxy struct {
	cfg     *config
	address string
	srv     *http.Server
	lock    sync.RWMutex
}

// New creates a proxy server forwarding requests from a consensus client to an execution client.
func New(opts ...Option) (*Proxy, error) {
	p := &Proxy{
		cfg: &config{
			proxyHost:      defaultProxyHost,
			proxyPort:      defaultProxyPort,
			spoofing:       &SpoofingConfig{},
			spoofCallbacks: &SpoofingCallbacks{},
		},
	}
	for _, o := range opts {
		if err := o(p); err != nil {
			return nil, err
		}
	}
	if p.cfg.destinationUrl == nil {
		return nil, errors.New("must provide a destination address for request proxying")
	}
	mux := http.NewServeMux()
	mux.Handle("/", p)
	addr := fmt.Sprintf("%s:%d", p.cfg.proxyHost, p.cfg.proxyPort)
	srv := &http.Server{
		Handler: mux,
		Addr:    addr,
	}
	p.address = addr
	p.srv = srv
	return p, nil
}

// Address for the proxy server.
func (p *Proxy) Address() string {
	return p.address
}

// Start a proxy server.
func (p *Proxy) Start(ctx context.Context) error {
	p.srv.BaseContext = func(listener net.Listener) context.Context {
		return ctx
	}
	logrus.WithFields(logrus.Fields{
		"forwardingAddress": p.cfg.destinationUrl.String(),
	}).Infof("Engine proxy now listening on address %s", p.address)
	go func() {
		if err := p.srv.ListenAndServe(); err != nil {
			logrus.Error(err)
		}
	}()
	for {
		<-ctx.Done()
		return p.srv.Shutdown(ctx)
	}
}

// UpdateSpoofingConfig for use at runtime.
func (p *Proxy) UpdateSpoofingConfig(config *SpoofingConfig) {
	p.lock.Lock()
	p.cfg.spoofing = config
	p.lock.Unlock()
}

// UpdateSpoofingConfig for use at runtime.
func (p *Proxy) UpdateSpoofingCallbacks(callbacks *SpoofingCallbacks) {
	p.lock.Lock()
	p.cfg.spoofCallbacks = callbacks
	p.lock.Unlock()
}

// ServeHTTP by proxying requests from an Ethereum consensus client to an execution client.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	spoofing := p.spoofing()
	spoofCallbacks := p.spoofingCallbacks()
	requestBytes, err := parseRequestBytes(r)
	if err != nil {
		logrus.WithError(err).Error("Could not parse request")
		return
	}

	modifiedReq, err := spoofRequest(spoofing, spoofCallbacks, requestBytes)
	if err != nil {
		logrus.WithError(err).Error("Failed to Spoof request")
		return
	}

	// Create a new proxy request to the execution client.
	url := r.URL
	url.Host = p.cfg.destinationUrl.String()
	proxyReq, err := http.NewRequest(r.Method, url.Host, r.Body)
	if err != nil {
		logrus.WithError(err).Error("Could create new request")
		return
	}

	// Set the modified request as the proxy request body.
	proxyReq.Body = ioutil.NopCloser(bytes.NewBuffer(modifiedReq))

	// Required proxy headers for forwarding JSON-RPC requests to the execution client.
	proxyReq.Header.Set("Host", r.Host)
	proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
	proxyReq.Header.Set("Content-Type", "application/json")

	if len(p.cfg.jwtSecret) > 0 {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iat": time.Now().Unix(),
		})
		tokenString, err := token.SignedString(p.cfg.jwtSecret)
		if err != nil {
			logrus.WithError(err).Error("Failed to create JWT token")
		}
		proxyReq.Header.Set("Authorization", "Bearer "+tokenString)
	}

	client := &http.Client{}
	proxyRes, err := client.Do(proxyReq)
	if err != nil {
		logrus.WithError(err).Error("Could not do client proxy")
		return
	}
	// Forward the headers from the destination response to our proxy response.
	for k, vv := range proxyRes.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// We optionally Spoof the response as desired.
	modifiedResp, err := spoofResponse(spoofing, spoofCallbacks, requestBytes, proxyRes.Body)
	if err != nil {
		logrus.WithError(err).Error("Failed to Spoof response")
		return
	}

	if err = proxyRes.Body.Close(); err != nil {
		logrus.WithError(err).Error("Could not do client proxy")
		return
	}

	// Set the modified response as the proxy response body.
	proxyRes.Body = ioutil.NopCloser(bytes.NewBuffer(modifiedResp))

	// Pipe the proxy response to the original caller.
	if _, err = io.Copy(w, proxyRes.Body); err != nil {
		logrus.WithError(err).Error("Could not copy proxy request body")
		return
	}
}

// Reads the spoofing config (thread-safe).
func (p *Proxy) spoofing() *SpoofingConfig {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return p.cfg.spoofing
}

// Reads the spoofing config (thread-safe).
func (p *Proxy) spoofingCallbacks() *SpoofingCallbacks {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return p.cfg.spoofCallbacks
}

// Parses the request from thec consensus client and checks if user desires
// to Spoof it based on the JSON-RPC method. If so, it returns the modified
// request bytes which will be proxied to the execution client.
func spoofRequest(config *SpoofingConfig, callbacks *SpoofingCallbacks, requestBytes []byte) ([]byte, error) {
	// If the JSON request is not a JSON-RPC object, return the request as-is.
	jsonRequest, err := unmarshalRPCObject(requestBytes)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "cannot unmarshal array"):
			return requestBytes, nil
		default:
			return nil, err
		}
	}
	if len(jsonRequest.Params) == 0 {
		return requestBytes, nil
	}
	desiredMethodsToSpoof := make(map[string]*Spoof)
	for method, spoofCallback := range callbacks.RequestCallbacks {
		if method == jsonRequest.Method {
			spoofReq := spoofCallback(requestBytes)
			if spoofReq != nil {
				desiredMethodsToSpoof[jsonRequest.Method] = spoofReq
			}
		}
	}
	for _, spoofReq := range config.Requests {
		desiredMethodsToSpoof[spoofReq.Method] = spoofReq
	}
	// If we don't want to Spoof the request, just return the request as-is.
	spoofDetails, ok := desiredMethodsToSpoof[jsonRequest.Method]
	if !ok {
		return requestBytes, nil
	}

	// TODO: Support methods with multiple params.
	params := make(map[string]interface{})
	if err := extractObjectFromJSONRPC(jsonRequest.Params[0], &params); err != nil {
		return nil, err
	}
	for fieldToModify, fieldValue := range spoofDetails.Fields {
		if _, ok := params[fieldToModify]; !ok {
			continue
		}
		params[fieldToModify] = fieldValue
	}
	logrus.WithField("method", jsonRequest.Method).Infof("Spoofing request %v", params)
	jsonRequest.Params[0] = params
	return json.Marshal(jsonRequest)
}

// Parses the response body from the execution client and checks if user desires
// to Spoof it based on the JSON-RPC method. If so, it returns the modified
// response bytes which will be proxied to the consensus client.
func spoofResponse(config *SpoofingConfig, callbacks *SpoofingCallbacks, requestBytes []byte, responseBody io.Reader) ([]byte, error) {
	responseBytes, err := ioutil.ReadAll(responseBody)
	if err != nil {
		return nil, err
	}
	// If the JSON request is not a JSON-RPC object, return the request as-is.
	jsonRequest, err := unmarshalRPCObject(requestBytes)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "cannot unmarshal array"):
			return responseBytes, nil
		case strings.Contains(err.Error(), "invalid character"):
			return nil, errors.New(string(responseBytes))
		default:
			return nil, err
		}
	}
	jsonResponse, err := unmarshalRPCObject(responseBytes)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "cannot unmarshal array"):
			return responseBytes, nil
		case strings.Contains(err.Error(), "invalid character"):
			return nil, errors.New(string(responseBytes))
		default:
			return nil, err
		}
	}
	desiredMethodsToSpoof := make(map[string]*Spoof)
	for method, spoofCallback := range callbacks.ResponseCallbacks {
		if method == jsonRequest.Method {
			spoofReq := spoofCallback(responseBytes, requestBytes)
			if spoofReq != nil {
				desiredMethodsToSpoof[jsonRequest.Method] = spoofReq
			}
		}
	}
	for _, spoofReq := range config.Responses {
		desiredMethodsToSpoof[spoofReq.Method] = spoofReq
	}
	// If we don't want to Spoof the request, just return the request as-is.
	spoofDetails, ok := desiredMethodsToSpoof[jsonRequest.Method]
	if !ok {
		return responseBytes, nil
	}

	// TODO: Support nested objects.
	params := make(map[string]interface{})
	if err := extractObjectFromJSONRPC(jsonResponse.Result, &params); err != nil {
		return nil, err
	}
	for fieldToModify, fieldValue := range spoofDetails.Fields {
		if _, ok := params[fieldToModify]; !ok {
			continue
		}
		params[fieldToModify] = fieldValue
	}
	logrus.WithField("method", jsonRequest.Method).Infof("Spoofing response %v", params)
	jsonResponse.Result = params
	return json.Marshal(jsonResponse)
}

// Peek into the bytes of an HTTP request's body.
func parseRequestBytes(req *http.Request) ([]byte, error) {
	requestBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	if err = req.Body.Close(); err != nil {
		return nil, err
	}
	req.Body = ioutil.NopCloser(bytes.NewBuffer(requestBytes))
	return requestBytes, nil
}

func unmarshalRPCObject(b []byte) (*jsonRPCObject, error) {
	r := &jsonRPCObject{}
	if err := json.Unmarshal(b, r); err != nil {
		return nil, err
	}
	return r, nil
}

func extractObjectFromJSONRPC(src interface{}, dst interface{}) error {
	rawResp, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(rawResp, dst)
}
