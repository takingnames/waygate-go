package main

import (
	"fmt"

	"github.com/takingnames/waygate-go"
)

func main() {
	client := waygate.NewClient()
	client.ProviderUri = "bpadmin.takingnames.live/waygate"

	outOfBand := true
	url := client.TunnelRequestLink(outOfBand)

	fmt.Println(url)
}
