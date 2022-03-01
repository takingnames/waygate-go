package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/takingnames/waygate-go"
)

func main() {

	fmt.Println("Starting up")

	server := flag.String("server", "", "Waygate server")
	token := flag.String("token", "", "Waygate token")
	localPort := flag.Int("local-port", 9001, "Local port")
	flag.Parse()

	err := waygate.ConnectTunnel(*server, *token, *localPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	//client := waygate.NewClient()
	//client.ProviderUri = "bpadmin.takingnames.live/waygate"

	//outOfBand := true
	//url := client.TunnelRequestLink(outOfBand)

	//fmt.Println(url)
}
