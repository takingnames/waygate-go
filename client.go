package waygate

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"

	"golang.org/x/oauth2"
)

type ClientDatabase interface {
	SetTunnelRequest(requestId string, req TunnelRequest)
}

type Client struct {
	Database    ClientDatabase
	ProviderUri string
	mut         *sync.Mutex
}

type TunnelRequest struct {
}

type memDb struct {
	tunnelRequests map[string]TunnelRequest
	mut            *sync.Mutex
}

func (d *memDb) SetTunnelRequest(requestId string, req TunnelRequest) {
	d.mut.Lock()
	defer d.mut.Unlock()

	d.tunnelRequests[requestId] = req
}

func NewClient() *Client {

	c := &Client{
		Database:    &memDb{make(map[string]TunnelRequest), &sync.Mutex{}},
		ProviderUri: "takingnames.io/waygate",
		mut:         &sync.Mutex{},
	}

	return c
}

func (c *Client) buildOauthConfig(outOfBand bool) *oauth2.Config {

	domain := "localhost:9001"

	oauthConf := &oauth2.Config{
		ClientID:     domain,
		ClientSecret: "fake-secret",
		Scopes:       []string{"tunnel"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s/authorize", c.ProviderUri),
			TokenURL: fmt.Sprintf("https://%s/token", c.ProviderUri),
		},
	}

	if outOfBand {
		oauthConf.RedirectURL = "urn:ietf:wg:oauth:2.0:oob"
	} else {
		oauthConf.RedirectURL = fmt.Sprintf("%s/waygate/callback", domain)
	}

	return oauthConf
}

func (c *Client) TunnelRequestLink(outOfBand bool) string {
	c.mut.Lock()
	defer c.mut.Unlock()

	oauthConf := c.buildOauthConfig(outOfBand)

	requestId, _ := genRandomKey()

	req := TunnelRequest{}

	c.Database.SetTunnelRequest(requestId, req)

	oauthUrl := oauthConf.AuthCodeURL(requestId, oauth2.AccessTypeOffline)

	return oauthUrl
}

func genRandomKey() (string, error) {

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
