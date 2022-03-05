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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.URL.Path)
	})

	fmt.Println("Running")
	err := waygate.ListenAndServe(*server, nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
