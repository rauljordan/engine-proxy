package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	logTest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

type ForkchoiceState struct {
	HeadBlockHash      []byte `json:"headBlockHash"`
	SafeBlockHash      []byte `json:"safeBlockHash"`
	FinalizedBlockHash []byte `json:"finalizedBlockHash"`
}

func TestProxy(t *testing.T) {
	t.Run("forwards http headers from destination server", func(t *testing.T) {
		ctx := context.Background()
		customDestinationHeaders := map[string]string{
			"hello": "world",
		}
		wantDestinationResponse := &ForkchoiceState{
			HeadBlockHash:      []byte("foo"),
			SafeBlockHash:      []byte("bar"),
			FinalizedBlockHash: []byte("baz"),
		}
		srv := destinationServerSetup(t, wantDestinationResponse, customDestinationHeaders)
		defer srv.Close()

		proxy, err := New(
			WithPort(rand.Intn(10000)),
			WithDestinationAddress(srv.URL),
		)
		require.NoError(t, err)

		go func() {
			if err := proxy.Start(ctx); err != nil {
				t.Log(err)
			}
		}()

		time.Sleep(time.Millisecond * 100)

		// If we make a request to the destination server directly, we should expect
		// the right header in the HTTP response.
		client := &http.Client{
			Transport: http.DefaultTransport,
		}
		resp, err := client.Get(srv.URL)
		require.NoError(t, err)
		require.Equal(t, "world", resp.Header.Get("hello"))

		// Making a request to the proxy should also forward the expected
		// headers from the destination server.
		buf := bytes.NewBuffer(make([]byte, 0))
		req := &jsonRPCObject{
			Jsonrpc: "2.0",
			Method:  "engine_newPayloadV1",
			Params:  nil,
			ID:      1,
		}
		require.NoError(t, json.NewEncoder(buf).Encode(req))
		resp, err = client.Post("http://"+proxy.Address(), "application/json", buf)
		require.NoError(t, err)
		require.Equal(t, "world", resp.Header.Get("hello"))
	})
	t.Run("fails to proxy if destination is down", func(t *testing.T) {
		hook := logTest.NewGlobal()
		defer hook.Reset()
		ctx := context.Background()
		proxy, err := New(
			WithPort(rand.Intn(10000)),
			WithDestinationAddress("http://localhost:43239"), // Nothing running at destination server.
		)
		require.NoError(t, err)
		go func() {
			if err := proxy.Start(ctx); err != nil {
				t.Log(err)
			}
		}()
		time.Sleep(time.Millisecond * 100)

		rpcClient, err := rpc.DialHTTP("http://" + proxy.Address())
		require.NoError(t, err)

		err = rpcClient.CallContext(ctx, nil, "someEngineMethod")
		require.ErrorContains(t, err, "EOF")

		require.Equal(t, true, len(hook.Entries) > 0)
		var found bool
		for _, entry := range hook.Entries {
			if strings.Contains(entry.Message, "Could not do client proxy") {
				found = true
				break
			}
		}
		// Expect issues when reaching destination server.
		require.Equal(t, true, found)
	})
	t.Run("properly proxies request/response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		wantDestinationResponse := &ForkchoiceState{
			HeadBlockHash:      []byte("foo"),
			SafeBlockHash:      []byte("bar"),
			FinalizedBlockHash: []byte("baz"),
		}
		srv := destinationServerSetup(t, wantDestinationResponse, nil)
		defer srv.Close()

		// Destination address server responds to JSON-RPC requests.
		proxy, err := New(
			WithPort(rand.Intn(50000)),
			WithDestinationAddress(srv.URL),
		)
		require.NoError(t, err)
		go func() {
			if err := proxy.Start(ctx); err != nil {
				t.Log(err)
			}
		}()
		time.Sleep(time.Millisecond * 100)

		// Dials the proxy.
		rpcClient, err := rpc.DialHTTP("http://" + proxy.Address())
		require.NoError(t, err)

		// Expect the result from the proxy is the same as that one returned
		// by the destination address.
		proxyResult := &ForkchoiceState{}
		err = rpcClient.CallContext(ctx, proxyResult, "someEngineMethod")
		require.NoError(t, err)
		require.Equal(t, wantDestinationResponse, proxyResult)
	})
}

func TestProxy_CustomInterceptors(t *testing.T) {
	t.Run("triggers interceptor response correctly", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		type syncingResponse struct {
			Syncing bool `json:"syncing"`
		}

		wantDestinationResponse := &syncingResponse{Syncing: true}
		srv := destinationServerSetup(t, wantDestinationResponse, nil)
		defer srv.Close()

		// Destination address server responds to JSON-RPC requests.
		proxy, err := New(
			WithPort(rand.Intn(50000)),
			WithDestinationAddress(srv.URL),
			WithSpoofingConfig(&SpoofingConfig{
				Responses: []*Spoof{
					{
						Method: "eth_syncing",
						Fields: map[string]interface{}{
							"syncing": true,
						},
					},
				},
			}),
		)
		require.NoError(t, err)
		go func() {
			if err := proxy.Start(ctx); err != nil {
				t.Log(err)
			}
		}()
		time.Sleep(time.Millisecond * 100)

		// Dials the proxy.
		rpcClient, err := rpc.DialHTTP("http://" + proxy.Address())
		require.NoError(t, err)

		// Expect the result from the proxy is the same as that one returned
		// by the destination address.
		proxyResult := &syncingResponse{}
		err = rpcClient.CallContext(ctx, proxyResult, "eth_syncing")
		require.NoError(t, err)
		require.Equal(t, wantDestinationResponse, proxyResult)
	})
}

func destinationServerSetup(t *testing.T, response interface{}, destinationServerHeaders map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for hd, val := range destinationServerHeaders {
			w.Header().Set(hd, val)
		}
		defer func() {
			require.NoError(t, r.Body.Close())
		}()
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  response,
		}
		err := json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
}
