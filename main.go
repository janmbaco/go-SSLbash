package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/janmbaco/go-infrastructure/errorhandler"
	"github.com/janmbaco/go-infrastructure/logs"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	certFile            = flag.String("cert", "public.crt", "A PEM eoncoded certificate file.")
	keyFile             = flag.String("key", "private.key", "A PEM encoded private key file.")
	caFile              = flag.String("CA", "caRoot.crt", "A PEM eoncoded CA's certificate file.")
	proxyUrl            = flag.String("ProxyUrl", "localhost:443", "The proxy URL.")
	basicAuthentication = flag.String("BasicAuthentication", "user@passwrod", "The basic Authentication for Proxy.")
	sshUrl              = flag.String("sshUrl", "localhost:22", "The proxy URL.")
	sshUser             = flag.String("sshUser", "User", "User for ssh.")
)

func SetLogFile() {
	logs.Log.SetDir("./logs")
	logs.Log.SetFileLogLevel(logs.Warning)
}

func GetTlsConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	errorhandler.TryPanic(err)

	caCert, err := ioutil.ReadFile(*caFile)
	errorhandler.TryPanic(err)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}
}

func ConnectToProxy(conn net.Conn) {
	req, _ := http.NewRequest("CONNECT", *sshUrl, nil)
	req.RequestURI = *sshUrl
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(*basicAuthentication)))

	dumpReq, err := httputil.DumpRequest(req, false)
	errorhandler.TryPanic(err)

	_, err = conn.Write(dumpReq)
	errorhandler.TryPanic(err)

	reply := make([]byte, 256)
	length, err := conn.Read(reply)
	errorhandler.TryPanic(err)
	response := string(reply[:length])

	if !strings.Contains(response, "200 OK") {
		panic(response)
	}

	logs.Log.Info("proxy tls connected")
}

func GetSshConfig() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            *sshUser,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func GetSSHTerminalModes() ssh.TerminalModes {
	return ssh.TerminalModes{
		ssh.ECHO:          1,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
}

func PrepareTerminal() (int, *terminal.State) {
	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	errorhandler.TryPanic(err)
	return fd, state
}

func main() {
	flag.Parse()

	SetLogFile()

	conn, err := tls.Dial("tcp", *proxyUrl, GetTlsConfig())
	errorhandler.TryPanic(err)
	errorhandler.TryFinally(func() {

		ConnectToProxy(conn)

		sshconn, channel, request, err := ssh.NewClientConn(conn, "127.0.0.1:22", GetSshConfig())
		errorhandler.TryPanic(err)
		errorhandler.TryFinally(func() {

			sshClient := ssh.NewClient(sshconn, channel, request)
			errorhandler.TryFinally(func() {

				session, err := sshClient.NewSession()
				errorhandler.TryPanic(err)
				errorhandler.TryFinally(func() {

					fd, state := PrepareTerminal()
					errorhandler.TryFinally(func() {

						w, h, err := terminal.GetSize(fd)
						errorhandler.TryPanic(err)

						term := os.Getenv("TERM")
						if term == "" {
							term = "xterm-256color"
						}

						errorhandler.TryPanic(session.RequestPty(term, h, w, GetSSHTerminalModes()))

						session.Stdout = os.Stdout
						session.Stderr = os.Stderr
						session.Stdin = os.Stdin

						errorhandler.TryPanic(session.Shell())

						errorhandler.TryPanic(session.Wait())

					}, func() {
						logs.Log.TryError(terminal.Restore(fd, state))
					})

				}, func() {
					logs.Log.TryError(session.Close())
				})

			},
				func() {
					logs.Log.TryError(sshClient.Close())
				})

		}, func() {
			logs.Log.TryError(sshconn.Close())
		})

	}, func() {
		logs.Log.TryError(conn.Close())
	})
}
