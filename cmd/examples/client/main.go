package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/takingnames/waygate-go"
)

func main() {

	fmt.Println("Starting up")

	server := flag.String("server", "", "Waygate server")
	var token string
	flag.StringVar(&token, "token", "", "Waygate token")
	//localPort := flag.Int("local-port", 9001, "Local port")
	flag.Parse()

	if token == "" {
		token = waygate.GetTokenCLI(*server)
	}

	listener, err := waygate.CreateListener(*server, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.URL.Path)
	})
	http.Serve(listener, nil)

}
