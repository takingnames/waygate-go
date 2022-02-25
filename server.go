package waygate

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type ServerDatabase interface {
}

type Server struct {
	db  ServerDatabase
	mux *http.ServeMux
}

type AuthRequest struct {
	ClientId    string
	RedirectUri string
	Scope       string
	State       string
}

func NewServer(db ServerDatabase) *Server {

	s := &Server{
		db: db,
	}

	mux := &http.ServeMux{}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.URL.Path)
	})

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {

	})

	s.mux = mux

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
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
