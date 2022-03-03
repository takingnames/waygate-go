package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/takingnames/waygate-go"
)

func main() {

	fmt.Println("Starting up")

	server := flag.String("server", "", "Waygate server")
	token := flag.String("token", "", "Waygate token")
	//localPort := flag.Int("local-port", 9001, "Local port")
	flag.Parse()

	if *token == "" {
		client := waygate.NewClient()
		client.ProviderUri = *server
		outOfBand := true
		url := client.TunnelRequestLink(outOfBand)
		fmt.Println(url)

		t := prompt("Enter the token: ")
		token = &t
	}

	listener, err := waygate.CreateListener(*server, *token)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.URL.Path)
	})
	http.Serve(listener, nil)

}

func prompt(promptText string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(promptText)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}
