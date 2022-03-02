package waygate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/caddyserver/certmagic"
	"golang.org/x/crypto/ssh"
	//"go.uber.org/zap"
)

type acceptResult struct {
	tlsConn *tls.Conn
	err     error
}

// Listener that owns an SSH client, which is closed when the listener closes.
type sshListener struct {
	client     *ssh.Client
	listener   net.Listener
	acceptChan chan acceptResult
}

func NewSshListener(client *ssh.Client, listener net.Listener) *sshListener {
	// Use random unprivileged port for ACME challenges. This is necessary
	// because of the way certmagic works, in that if it fails to bind
	// HTTPSPort (443 by default) and doesn't detect anything else binding
	// it, it fails. Obviously the boringproxy client is likely to be
	// running on a machine where 443 isn't bound, so we need a different
	// port to hack around this. See here for more details:
	// https://github.com/caddyserver/certmagic/issues/111
	//var err error
	//certmagic.HTTPSPort, err = randomOpenPort()
	//if err != nil {
	//	return errors.New("Failed get random port for TLS challenges")
	//}
	certmagic.DefaultACME.DisableHTTPChallenge = true
	//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(name string) error {
			return nil
		},
	}

	//logger, _ := zap.NewDevelopment()
	//certmagic.Default.Logger = logger

	certConfig := certmagic.NewDefault()

	tlsConfig := &tls.Config{
		GetCertificate: certConfig.GetCertificate,
	}

	tlsConfig.NextProtos = append([]string{"http/1.1", "h2", "acme-tls/1"}, tlsConfig.NextProtos...)

	acceptChan := make(chan acceptResult)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				acceptChan <- acceptResult{
					tlsConn: nil,
					err:     err,
				}
				break
			}

			tlsConn := tls.Server(conn, tlsConfig)

			go func(innerTlsConn *tls.Conn) {
				innerTlsConn.Handshake()
				if innerTlsConn.ConnectionState().NegotiatedProtocol == "acme-tls/1" {
					innerTlsConn.Close()
				} else {
					acceptChan <- acceptResult{
						tlsConn: innerTlsConn,
						err:     nil,
					}
				}
			}(tlsConn)
		}
	}()

	return &sshListener{
		client:     client,
		listener:   listener,
		acceptChan: acceptChan,
	}

}
func (l *sshListener) Accept() (net.Conn, error) {
	result := <-l.acceptChan
	return result.tlsConn, result.err
}
func (l *sshListener) Addr() net.Addr {
	return l.listener.Addr()
}
func (l *sshListener) Close() error {
	err := l.client.Close()
	if err != nil {
		return err
	}
	return l.listener.Close()
}

func MakeSshListener(tunnel SSHTunnel) (net.Listener, error) {
	signer, err := ssh.ParsePrivateKey([]byte(tunnel.ClientPrivateKey))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to parse private key: %v", err))
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
		return nil, errors.New(fmt.Sprintf("Failed to dial: ", err))
	}
	//defer client.Close()

	bindAddr := "127.0.0.1"

	tunnelAddr := fmt.Sprintf("%s:%d", bindAddr, tunnel.ServerTunnelPort)
	listener, err := client.Listen("tcp", tunnelAddr)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to register tcp forward for %s:%d %v", bindAddr, tunnel.ServerTunnelPort, err))
	}

	l := NewSshListener(client, listener)

	return l, nil
}

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
	//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	certConfig := certmagic.NewDefault()

	listener, err := MakeSshListener(tunnel)
	if err != nil {
		return errors.New(fmt.Sprintf("Unable to register tcp forward %v", err))
	}
	defer listener.Close()

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

	fmt.Println("Tunnel opened on port", localPort)

	<-ctx.Done()

	return nil
}
