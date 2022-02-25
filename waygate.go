package waygate

import ()

type Tunnel struct {
        TunnelType string `json:"tunnel_type"`
}

type SSHTunnel struct {
        TunnelType string `json:"tunnel_type"`

        Domains           []string `json:"domains"`
	ServerAddress    string `json:"server_address"`
	ServerPort       int    `json:"server_port"`
	ServerPublicKey  string `json:"server_public_key"`
	Username         string `json:"username"`
	ClientPrivateKey string `json:"client_private_key"`
}

type WaygateTunnel struct {
	Domains []string
}

type WaygateTalisman struct {
	WaygateId string
}
