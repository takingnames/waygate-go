package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/takingnames/waygate-go"
)

func main() {

	fmt.Println("Starting up")

	server := flag.String("server", "", "Waygate server")
	//token := flag.String("token", "", "Waygate token")
	localPort := flag.Int("local-port", 9001, "Local port")
	flag.Parse()

	client := waygate.NewClient()
	client.ProviderUri = fmt.Sprintf("%s/waygate", *server)

	outOfBand := true
	url := client.TunnelRequestLink(outOfBand)

	fmt.Println(url)

	token := prompt("Enter the token:")

	err := waygate.ConnectTunnel(*server, token, *localPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

}

func prompt(promptText string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(promptText)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}
