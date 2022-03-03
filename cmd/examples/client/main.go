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
	flag.Parse()

	listener, err := waygate.ListenCustom(*server)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.URL.Path)
	})

	fmt.Println("Running")
	http.Serve(listener, nil)

}
