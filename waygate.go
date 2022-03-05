package waygate

import (
	"context"
	"net/http"
)

type Tunnel struct {
	TunnelType string   `json:"tunnel_type"`
	Domains    []string `json:"domains"`
}

type SSHTunnel struct {
	TunnelType       string   `json:"tunnel_type"`
	Domains          []string `json:"domains"`
	ServerAddress    string   `json:"server_address"`
	ServerPort       int      `json:"server_port"`
	ServerTunnelPort int      `json:"server_tunnel_port"`
	ServerPublicKey  string   `json:"server_public_key"`
	Username         string   `json:"username"`
	ClientPrivateKey string   `json:"client_private_key"`
}

type Waygate struct {
	Domains []string `json:"domains"`
}

type TokenData struct {
	WaygateId string `json:"waygate_id"`
}

type HttpServer struct {
	WaygateServerUri string
	Handler          http.Handler
}

func (s *HttpServer) ListenAndServe() error {
	return ListenAndServe(s.WaygateServerUri, s.Handler)
}
func (s *HttpServer) Shutdown(ctx context.Context) error {
	return nil
}
