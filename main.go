package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/janmbaco/go-infrastructure/errorhandler"
	"github.com/janmbaco/go-infrastructure/logs"
	"golang.org/x/crypto/ssh"
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
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
}

func ConnectPipes(dst io.Writer, src io.Reader) {
	_, err := io.Copy(dst, src)
	logs.Log.TryError(err)
}

func PreparePipes(session *ssh.Session) io.WriteCloser {
	stdin, err := session.StdinPipe()
	errorhandler.TryPanic(err)

	stdout, err := session.StdoutPipe()
	errorhandler.TryPanic(err)
	go ConnectPipes(os.Stdout, stdout)

	stderr, err := session.StderrPipe()
	errorhandler.TryPanic(err)
	go ConnectPipes(os.Stderr, stderr)

	return stdin
}

func readFromPrompt(stdin io.WriteCloser) {
	cmds := read(os.Stdin)
	for cmd := range cmds {
		_, err := stdin.Write([]byte(cmd + "\n"))
		errorhandler.TryPanic(err)
		if cmd == "exit" {
			break
		}
	}
}

func read(r io.Reader) <-chan string {
	lines := make(chan string)
	go func() {
		defer close(lines)
		scan := bufio.NewScanner(r)
		for scan.Scan() {
			lines <- scan.Text()
		}
	}()
	return lines
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

					errorhandler.TryPanic(session.RequestPty("bash", 80, 40, GetSSHTerminalModes()))

					stdIn := PreparePipes(session)

					errorhandler.TryPanic(session.Shell())

					readFromPrompt(stdIn)

					errorhandler.TryPanic(session.Wait())

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
