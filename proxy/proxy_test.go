package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type ForkchoiceState struct {
	HeadBlockHash      []byte `json:"headBlockHash"`
	SafeBlockHash      []byte `json:"safeBlockHash"`
	FinalizedBlockHash []byte `json:"finalizedBlockHash"`
}

func TestProxy(t *testing.T) {
	t.Run("fails to proxy if destination is down", func(t *testing.T) {
		logger := logrus.New()
		output := bytes.NewBuffer(make([]byte, 0))
		logger.Out = output
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

		// Expect issues when reaching destination server.
		require.Contains(t, output.String(), "Could not forward request to destination server")
	})
	t.Run("properly proxies request/response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		wantDestinationResponse := &ForkchoiceState{
			HeadBlockHash:      []byte("foo"),
			SafeBlockHash:      []byte("bar"),
			FinalizedBlockHash: []byte("baz"),
		}
		srv := destinationServerSetup(t, wantDestinationResponse)
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
		srv := destinationServerSetup(t, wantDestinationResponse)
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

func destinationServerSetup(t *testing.T, response interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
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
