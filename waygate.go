package waygate

import (
	"context"
	"crypto/rand"
	"math/big"
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
	Domains     []string `json:"domains"`
	Description string   `json:"description"`
	AdminUrl    string   `json:"admin_url"`
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

func genRandomCode() (string, error) {

	const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	id := ""
	for i := 0; i < 32; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		id += string(chars[randIndex.Int64()])
	}
	return id, nil
}
