package waygate

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	//"time"
	//"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

var ClientStoreFactory = func() ClientStore {
	return NewClientJsonStore()
}

type ClientStore interface {
	SetState(string)
	GetState() string
	GetAccessToken() (string, error)
	SetAccessToken(token string)
}

type Client struct {
	Store       ClientStore
	ProviderUri string
	mut         *sync.Mutex
}

type TunnelRequest struct {
}

type memClientDb struct {
	tunnelRequests map[string]TunnelRequest
	mut            *sync.Mutex
}

func (d *memClientDb) SetTunnelRequest(requestId string, req TunnelRequest) {
	d.mut.Lock()
	defer d.mut.Unlock()

	d.tunnelRequests[requestId] = req
}

func NewClient() *Client {

	c := &Client{
		Store:       ClientStoreFactory(),
		ProviderUri: "takingnames.io",
		mut:         &sync.Mutex{},
	}

	return c
}

func (c *Client) buildOauthConfig(outOfBand bool, bindAddr string) *oauth2.Config {

	oauthConf := &oauth2.Config{
		ClientID:     bindAddr,
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
		oauthConf.RedirectURL = fmt.Sprintf("%s/waygate/callback", bindAddr)
	}

	return oauthConf
}

func buildOauthConfig(providerUri string, outOfBand bool, bindAddr string) *oauth2.Config {

	oauthConf := &oauth2.Config{
		ClientID:     bindAddr,
		ClientSecret: "fake-secret",
		Scopes:       []string{"tunnel"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s/waygate/authorize", providerUri),
			TokenURL: fmt.Sprintf("https://%s/waygate/token", providerUri),
		},
	}

	if outOfBand {
		oauthConf.RedirectURL = "urn:ietf:wg:oauth:2.0:oob"
	} else {
		oauthConf.RedirectURL = fmt.Sprintf("%s/waygate/callback", bindAddr)
	}

	return oauthConf
}

func (c *Client) TunnelRequestLink(outOfBand bool, bindAddr string) string {
	c.mut.Lock()
	defer c.mut.Unlock()

	oauthConf := c.buildOauthConfig(outOfBand, bindAddr)

	requestId, _ := genRandomCode()

	c.Store.SetState(requestId)

	oauthUrl := oauthConf.AuthCodeURL(requestId, oauth2.AccessTypeOffline)

	return oauthUrl
}

func GetTokenCLI(server string) string {
	client := NewClient()
	client.ProviderUri = server
	outOfBand := true
	url := client.TunnelRequestLink(outOfBand, "dummy-uri")
	fmt.Println(url)

	token := prompt("Enter the token: ")
	return token
}

func GetTokenBrowser(server, bindAddr string) string {
	client := NewClient()
	client.ProviderUri = server
	outOfBand := true
	url := client.TunnelRequestLink(outOfBand, bindAddr)
	fmt.Println(url)

	browser.OpenURL(url)

	mux := http.NewServeMux()

	var token string

	srv := &http.Server{
		Addr:    bindAddr,
		Handler: mux,
	}

	mux.HandleFunc("/waygate/callback", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("lolz", r.URL.Path)

		srv.Shutdown(context.Background())
	})

	err := srv.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}

	return token
}

func ListenAndServe(serverAddr string, handler http.Handler) error {

	listener, err := Listen(serverAddr)
	if err != nil {
		return err
	}

	return http.Serve(listener, handler)
}

func Listen(serverAddr string) (net.Listener, error) {

	db := ClientStoreFactory()

	token, err := db.GetAccessToken()
	if err != nil {
		outOfBand := false
		bindAddr := "localhost:9001"
		oauthConf := buildOauthConfig(serverAddr, outOfBand, bindAddr)
		requestId, _ := genRandomCode()
		db.SetState(requestId)
		oauthUrl := oauthConf.AuthCodeURL(requestId, oauth2.AccessTypeOffline)

		fmt.Println(oauthUrl)

		browser.OpenURL(oauthUrl)

		mux := http.NewServeMux()

		srv := &http.Server{
			Addr:    bindAddr,
			Handler: mux,
		}

		mux.HandleFunc("/waygate/callback", func(w http.ResponseWriter, r *http.Request) {

			defer func() {
				go srv.Shutdown(context.Background())
			}()

			r.ParseForm()

			code := r.Form.Get("code")
			if code == "" {
				w.WriteHeader(400)
				fmt.Fprintf(w, "Missing code param")
				return
			}

			state := r.Form.Get("state")
			pendingState := db.GetState()

			db.SetState("")

			if state != pendingState {
				w.WriteHeader(400)
				fmt.Fprintf(w, "State does not match")
				return
			}

			ctx := context.Background()
			tok, err := oauthConf.Exchange(ctx, code)
			if err != nil {
				fmt.Println(err.Error())
			}

			token = tok.AccessToken
			db.SetAccessToken(token)
		})

		err := srv.ListenAndServe()
		if err != nil {
			fmt.Println(err)
		}
	}

	return CreateListener(serverAddr, token)
}

func GetToken(server, oauthFlow string) (string, error) {

	switch oauthFlow {
	case "browser":
	default:
		return "", errors.New("Invalid flow type")
	}

	return "", errors.New("Unknown error")
}

func RefreshToken(server, refreshToken string) (string, error) {
	return "", nil
}

func CreateListener(server, token string) (net.Listener, error) {

	httpClient := &http.Client{
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := fmt.Sprintf("https://%s/waygate/open?type=ssh&token=%s", server, token)

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
