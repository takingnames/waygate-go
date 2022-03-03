package waygate

import (
	"bufio"
	"net"
	"os"
	"strings"
	//"time"
	//"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
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
		ProviderUri: "takingnames.io",
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
			AuthURL:  fmt.Sprintf("https://%s/waygate/authorize", c.ProviderUri),
			TokenURL: fmt.Sprintf("https://%s/waygate/token", c.ProviderUri),
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

func GetTokenCLI(server string) string {
	client := NewClient()
	client.ProviderUri = server
	outOfBand := true
	url := client.TunnelRequestLink(outOfBand)
	fmt.Println(url)

	token := prompt("Enter the token: ")
	return token
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

func CreateListener(server, token string) (net.Listener, error) {

	httpClient := &http.Client{
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := fmt.Sprintf("https://%s/waygate/open?type=ssh&talisman=%s", server, token)

	res, err := httpClient.Post(url, "text/plain", nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("Status %d returned", res.StatusCode))
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var tun Tunnel
	err = json.Unmarshal(bodyBytes, &tun)
	if err != nil {
		return nil, err
	}

	switch tun.TunnelType {
	case "ssh":
		var sshTunnel SSHTunnel
		err = json.Unmarshal(bodyBytes, &sshTunnel)
		if err != nil {
			return nil, err
		}

		listener, err := MakeSshListener(sshTunnel)
		if err != nil {
			return nil, err
		}

		return listener, err

	default:
		return nil, errors.New("Unsupported tunnel type")
	}

	return nil, errors.New("Unknown error")
}

func prompt(promptText string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(promptText)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}
