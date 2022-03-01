package waygate

import (
	"context"
	"errors"
	"fmt"

	"github.com/caddyserver/certmagic"
	"golang.org/x/crypto/ssh"
)

func BoreSshTunnel(ctx context.Context, tunnel SSHTunnel, localPort int) error {

	// Use random unprivileged port for ACME challenges. This is necessary
	// because of the way certmagic works, in that if it fails to bind
	// HTTPSPort (443 by default) and doesn't detect anything else binding
	// it, it fails. Obviously the boringproxy client is likely to be
	// running on a machine where 443 isn't bound, so we need a different
	// port to hack around this. See here for more details:
	// https://github.com/caddyserver/certmagic/issues/111
	var err error
	certmagic.HTTPSPort, err = randomOpenPort()
	if err != nil {
		return errors.New("Failed get random port for TLS challenges")
	}
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	certConfig := certmagic.NewDefault()

	signer, err := ssh.ParsePrivateKey([]byte(tunnel.ClientPrivateKey))
	if err != nil {
		return errors.New(fmt.Sprintf("Unable to parse private key: %v", err))
	}

	//var hostKey ssh.PublicKey

	config := &ssh.ClientConfig{
		User: tunnel.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		//HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshHost := fmt.Sprintf("%s:%d", tunnel.ServerAddress, tunnel.ServerPort)
	client, err := ssh.Dial("tcp", sshHost, config)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to dial: ", err))
	}
	defer client.Close()

	bindAddr := "127.0.0.1"

	tunnelAddr := fmt.Sprintf("%s:%d", bindAddr, tunnel.ServerTunnelPort)
	listener, err := client.Listen("tcp", tunnelAddr)
	if err != nil {
		return errors.New(fmt.Sprintf("Unable to register tcp forward for %s:%d %v", bindAddr, tunnel.ServerTunnelPort, err))
	}
	defer listener.Close()

	fmt.Println("Listen")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// TODO: Currently assuming an error means the
				// tunnel was manually deleted, but there
				// could be other errors that we should be
				// attempting to recover from rather than
				// breaking.
				break
				//continue
			}

			fmt.Println("Got a conn")

			unwrapTls := true
			go ProxyTcp(conn, "localhost", localPort, unwrapTls, certConfig)
		}
	}()

	// TODO: There's still quite a bit of duplication with what the server does. Could we
	// encapsulate it into a type?
	err = certConfig.ManageSync(ctx, []string{tunnel.Domains[0]})
	if err != nil {
		fmt.Println("CertMagic error at startup")
		fmt.Println(err)
	}

	<-ctx.Done()

	return nil
}
