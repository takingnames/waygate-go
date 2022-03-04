package waygate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type ServerDatabase interface {
	GetWaygateToken(string) (Token, error)
	GetWaygateTunnel(string) (Waygate, error)
	GetWaygates() map[string]Waygate
	SetTokenCode(tok, code string) error
	GetTokenByCode(code string) (string, error)
}

type Server struct {
	SshConfig *SshConfig
	db        ServerDatabase
	mux       *http.ServeMux
}

type SshConfig struct {
	ServerAddress      string
	ServerPort         int
	Username           string
	AuthorizedKeysPath string
}

type AuthRequest struct {
	ClientId    string
	RedirectUri string
	Scope       string
	State       string
}

type PendingToken struct {
	Token string `json:"token"`
}

type Oauth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func NewServer(db ServerDatabase) *Server {

	s := &Server{
		db: db,
	}

	mux := &http.ServeMux{}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.URL.Path)
	})

	mux.HandleFunc("/open", func(w http.ResponseWriter, r *http.Request) {
		s.open(w, r)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		s.token(w, r)
	})

	s.mux = mux

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) GetSSHPortForDomain(domain string) (int, error) {

	waygates := s.db.GetWaygates()

	var waygateId string

	for id, wg := range waygates {
		for _, d := range wg.Domains {
			if d == domain {
				waygateId = id
				break
			}
		}
	}

	portMap, err := parseAuthorizedKeysFile(s.SshConfig.AuthorizedKeysPath)
	if err != nil {
		return 0, err
	}

	port, exists := portMap[waygateId]
	if !exists {
		return 0, errors.New("No tunnel for domain")
	}

	return port, nil
}

func (s *Server) HandleDomain(domain string, conn net.Conn) error {

	waygates := s.db.GetWaygates()

	var waygateId string

	for id, wg := range waygates {
		for _, d := range wg.Domains {
			if d == domain {
				waygateId = id
				break
			}
		}
	}

	portMap, err := parseAuthorizedKeysFile(s.SshConfig.AuthorizedKeysPath)
	if err != nil {
		return err
	}

	port, exists := portMap[waygateId]
	if !exists {
		return errors.New("No tunnel for domain")
	}

	go handleConnection(conn, "localhost", port)

	return nil
}

func (s *Server) open(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		w.WriteHeader(405)
		fmt.Fprintf(w, "Invalid method")
		return
	}

	token, err := extractToken("token", r)
	if err != nil {
		w.WriteHeader(401)
		fmt.Fprintf(w, err.Error())
		return
	}

	tokenData, err := s.db.GetWaygateToken(token)
	if err != nil {
		w.WriteHeader(403)
		fmt.Fprintf(w, err.Error())
		return
	}

	waygate, err := s.db.GetWaygateTunnel(tokenData.WaygateId)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, err.Error())
		return
	}

	r.ParseForm()

	tunnelType := r.Form.Get("type")

	if tunnelType != "ssh" {
		w.WriteHeader(500)
		fmt.Fprintf(w, "No supported tunnel types")
		return
	}

	if s.SshConfig == nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "No SSH config set")
		return
	}

	deleteFromAuthorizedKeys(s.SshConfig.AuthorizedKeysPath, tokenData.WaygateId)

	tunnelPort, err := randomOpenPort()
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, err.Error())
		return
	}

	privKey, err := addToAuthorizedKeys(tokenData.WaygateId, tunnelPort, false, s.SshConfig.AuthorizedKeysPath)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, err.Error())
		return
	}

	tun := SSHTunnel{
		TunnelType:       "ssh",
		Domains:          waygate.Domains,
		ServerAddress:    s.SshConfig.ServerAddress,
		ServerPort:       s.SshConfig.ServerPort,
		ServerTunnelPort: tunnelPort,
		Username:         s.SshConfig.Username,
		ClientPrivateKey: privKey,
	}

	json.NewEncoder(w).Encode(tun)
}

func ExtractAuthRequest(r *http.Request) (*AuthRequest, error) {
	r.ParseForm()

	clientId := r.Form.Get("client_id")
	if clientId == "" {
		return nil, errors.New("Missing client_id param")
	}

	redirectUri := r.Form.Get("redirect_uri")
	if redirectUri == "" {
		return nil, errors.New("Missing redirect_uri param")
	}

	if !strings.HasPrefix(redirectUri, clientId) && redirectUri != "urn:ietf:wg:oauth:2.0:oob" {
		return nil, errors.New("redirect_uri must be on the same domain as client_id")
	}

	scope := r.Form.Get("scope")
	if scope == "" {
		return nil, errors.New("Missing scope param")
	}

	state := r.Form.Get("state")
	if state == "" {
		return nil, errors.New("state param can't be empty")
	}

	req := &AuthRequest{
		ClientId:    clientId,
		RedirectUri: redirectUri,
		Scope:       scope,
		State:       state,
	}

	return req, nil
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	code := r.Form.Get("code")

	token, err := s.db.GetTokenByCode(code)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	resp := Oauth2TokenResponse{
		AccessToken: token,
		TokenType:   "bearer",
	}

	jsonStr, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")

	w.Write(jsonStr)
}

// Looks for auth token in query string, then headers, then cookies
func extractToken(tokenName string, r *http.Request) (string, error) {

	query := r.URL.Query()

	queryToken := query.Get(tokenName)
	if queryToken != "" {
		return queryToken, nil
	}

	tokenHeader := r.Header.Get(tokenName)
	if tokenHeader != "" {
		return tokenHeader, nil
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		tokenHeader := strings.Split(authHeader, " ")[1]
		return tokenHeader, nil
	}

	tokenCookie, err := r.Cookie(tokenName)
	if err == nil {
		return tokenCookie.Value, nil
	}

	return "", errors.New("No token found")
}

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}

func parseAuthorizedKeysFile(path string) (map[string]int, error) {
	akBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	akStr := string(akBytes)

	lines := strings.Split(akStr, "\n")

	portMap := make(map[string]int)

	for _, line := range lines {
		_, comment, _, _, _ := ssh.ParseAuthorizedKey([]byte(line))
		if strings.HasPrefix(comment, "waygate-") {
			parts := strings.Split(comment, "-")
			port, err := strconv.Atoi(parts[2])
			if err != nil {
				return nil, err
			}

			portMap[parts[1]] = port
		}
	}

	return portMap, nil
}

func addToAuthorizedKeys(waygateId string, port int, allowExternalTcp bool, authKeysPath string) (string, error) {

	//authKeysPath := fmt.Sprintf("%s/.ssh/authorized_keys", homeDir)

	akFile, err := os.OpenFile(authKeysPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return "", err
	}
	defer akFile.Close()

	akBytes, err := io.ReadAll(akFile)
	if err != nil {
		return "", err
	}

	akStr := string(akBytes)

	var privKey string
	var pubKey string

	pubKey, privKey, err = MakeSSHKeyPair()
	if err != nil {
		return "", err
	}

	pubKey = strings.TrimSpace(pubKey)

	bindAddr := "127.0.0.1"
	if allowExternalTcp {
		bindAddr = "0.0.0.0"
	}

	options := fmt.Sprintf(`command="echo This key permits tunnels only",permitopen="fakehost:1",permitlisten="%s:%d"`, bindAddr, port)

	tunnelId := fmt.Sprintf("waygate-%s-%d", waygateId, port)

	newAk := fmt.Sprintf("%s%s %s %s\n", akStr, options, pubKey, tunnelId)

	// Clear the file
	err = akFile.Truncate(0)
	if err != nil {
		return "", err
	}
	_, err = akFile.Seek(0, 0)
	if err != nil {
		return "", err
	}

	_, err = akFile.Write([]byte(newAk))
	if err != nil {
		return "", err
	}

	return privKey, nil
}

// TODO: probably not thread safe
func deleteFromAuthorizedKeys(authKeysPath, waygateId string) error {

	akBytes, err := ioutil.ReadFile(authKeysPath)
	if err != nil {
		return err
	}

	akStr := string(akBytes)

	lines := strings.Split(akStr, "\n")

	tunnelId := fmt.Sprintf("waygate-%s-", waygateId)

	outLines := []string{}

	for _, line := range lines {
		if strings.Contains(line, tunnelId) {
			continue
		}

		outLines = append(outLines, line)
	}

	outStr := strings.Join(outLines, "\n")

	err = ioutil.WriteFile(authKeysPath, []byte(outStr), 0600)
	if err != nil {
		return err
	}

	return nil
}

// Adapted from https://stackoverflow.com/a/34347463/943814
// MakeSSHKeyPair make a pair of public and private keys for SSH access.
// Public key is encoded in the format for inclusion in an OpenSSH authorized_keys file.
// Private Key generated is PEM encoded
func MakeSSHKeyPair() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return "", "", err
	}

	// generate and write private key as PEM
	var privKeyBuf strings.Builder

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(&privKeyBuf, privateKeyPEM); err != nil {
		return "", "", err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	pubKey := string(ssh.MarshalAuthorizedKey(pub))

	return pubKey, privKeyBuf.String(), nil
}

func randomOpenPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	addrParts := strings.Split(listener.Addr().String(), ":")
	port, err := strconv.Atoi(addrParts[len(addrParts)-1])
	if err != nil {
		return 0, err
	}

	listener.Close()

	return port, nil
}
