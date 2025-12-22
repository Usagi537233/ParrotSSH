package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	listenAddr       = flag.String("listen", "", "listen address (e.g., :2222 for all interfaces, 192.168.1.100:2222 for specific IP)")
	realSSHAddr      = flag.String("real", "", "real SSH address (e.g., 127.0.0.1:22)")
	requiredAttempts = flag.Int("attempts", 2, "number of consecutive identical passwords required")
	keyFile          = flag.String("keyfile", "ssh_host_key", "host key file")
	saveFailInfo     = flag.String("savefailinfo", "", "file to save failed attempts (IP: User: Pass)")
)

type sessionState struct {
	username     string
	password     string
	attemptCount int
	mu           sync.Mutex
}

var states = struct {
	sync.Mutex
	m map[string]*sessionState
}{m: make(map[string]*sessionState)}

var failFile *os.File

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of ParrotSSH:\n")
		fmt.Fprintf(os.Stderr, "  A transparent SSH proxy that requires consecutive identical passwords before forwarding to a real SSH server.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  parrotssh -listen :2222 -real 127.0.0.1:22\n")
		fmt.Fprintf(os.Stderr, "  parrotssh -listen 192.168.1.100:2222 -real example.com:22 -attempts=3 -savefailinfo failed.log\n")
		os.Exit(1)
	}

	flag.Parse()

	if *listenAddr == "" || *realSSHAddr == "" {
		flag.Usage()
	}

	if *saveFailInfo != "" {
		var err error
		failFile, err = os.OpenFile(*saveFailInfo, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open save file: %v", err)
		}
		defer failFile.Close()
		log.Printf("Failed attempts will be saved to: %s", *saveFailInfo)
	}

	signer := loadOrGenerateHostKey(*keyFile)

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("Public key authentication not allowed")
		},
		PasswordCallback: passwordCallback,
	}

	config.AddHostKey(signer)

	config.ServerVersion = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	log.Printf("ParrotSSH started")
	log.Printf("Listening on %s → %s (requires %d consecutive identical passwords)", *listenAddr, *realSSHAddr, *requiredAttempts)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handle(conn, config)
	}
}

func passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	ipFull := conn.RemoteAddr().String()
	ipNoPort := strings.Split(ipFull, ":")[0]

	state := getState(ipFull)

	state.mu.Lock()
	defer state.mu.Unlock()

	pass := string(password)
	username := conn.User()

	log.Printf("[%s] User %s password attempt (%d): %s", ipFull, username, state.attemptCount+1, pass)

	if *saveFailInfo != "" {
		line := fmt.Sprintf("IP: %s | User: %s | Pass: %s\n", ipNoPort, username, pass)
		_, err := failFile.WriteString(line)
		if err != nil {
			log.Printf("Failed to write to save file: %v", err)
		}
	}

	if state.attemptCount == 0 {
		state.username = username
		state.password = pass
		state.attemptCount = 1
		return nil, fmt.Errorf("Permission denied, please try again.")
	}

	if pass == state.password {
		state.attemptCount++
		log.Printf("[%s] User %s password matched (attempt %d)", ipFull, username, state.attemptCount)
		if state.attemptCount >= *requiredAttempts {
			log.Printf("[%s] User %s passed verification (%d consecutive identical passwords), forwarding to real SSH", ipFull, username, *requiredAttempts)
			return &ssh.Permissions{}, nil
		}
	} else {
		log.Printf("[%s] User %s password mismatch, resetting attempts", ipFull, username)
	}

	state.attemptCount = 0
	state.password = ""
	return nil, fmt.Errorf("Permission denied, please try again.")
}

func handle(client net.Conn, config *ssh.ServerConfig) {
	defer client.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(client, config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	ipFull := sshConn.RemoteAddr().String()
	ipNoPort := strings.Split(ipFull, ":")[0]

	log.Printf("[%s] New connection established, user: %s", ipFull, sshConn.User())

	state := getState(ipFull)
	state.mu.Lock()
	username := state.username
	password := state.password
	state.mu.Unlock()

	realConn, err := net.DialTimeout("tcp", *realSSHAddr, 10*time.Second)
	if err != nil {
		log.Printf("[%s] Failed to connect to real SSH: %v", ipFull, err)
		if *saveFailInfo != "" {
			line := fmt.Sprintf("IP: %s | User: %s | Pass: %s (connection failed)\n", ipNoPort, username, password)
			_, err := failFile.WriteString(line)
			if err != nil {
				log.Printf("Failed to write to save file: %v", err)
			}
		}
		return
	}
	defer realConn.Close()

	clientConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	realSSH, realChans, realReqs, err := ssh.NewClientConn(realConn, *realSSHAddr, clientConfig)
	if err != nil {
		log.Printf("[%s] Real SSH authentication failed (user: %s): %v", ipFull, username, err)
		if *saveFailInfo != "" {
			line := fmt.Sprintf("IP: %s | User: %s | Pass: %s (auth failed)\n", ipNoPort, username, password)
			_, err := failFile.WriteString(line)
			if err != nil {
				log.Printf("Failed to write to save file: %v", err)
			}
		}
		return
	}
	defer realSSH.Close()

	log.Printf("[%s] User %s successfully connected to real backend SSH", ipFull, username)

	go ssh.DiscardRequests(reqs)
	go ssh.DiscardRequests(realReqs)

	go func() {
		for newChan := range realChans {
			newChan.Reject(ssh.Prohibited, "channel type not supported")
		}
	}()

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		clientChan, clientReqs, err := newChan.Accept()
		if err != nil {
			continue
		}

		realChan, realReqsChan, err := realSSH.OpenChannel("session", nil)
		if err != nil {
			clientChan.Close()
			continue
		}

		done := make(chan struct{})
		go func() {
			io.Copy(clientChan, realChan)
			done <- struct{}{}
		}()
		go func() {
			io.Copy(realChan, clientChan)
			done <- struct{}{}
		}()

		go func() {
			<-done
			clientChan.Close()
			realChan.Close()
		}()

		go func() {
			for req := range clientReqs {
				if req.WantReply {
					ok, _ := realChan.SendRequest(req.Type, true, req.Payload)
					req.Reply(ok, nil)
				} else {
					realChan.SendRequest(req.Type, false, req.Payload)
				}
			}
		}()

		go func() {
			for req := range realReqsChan {
				if req.WantReply {
					ok, _ := clientChan.SendRequest(req.Type, true, req.Payload)
					req.Reply(ok, nil)
				} else {
					clientChan.SendRequest(req.Type, false, req.Payload)
				}
			}
		}()
	}
}

func loadOrGenerateHostKey(path string) ssh.Signer {
	if _, err := os.Stat(path); err == nil {
		data, _ := os.ReadFile(path)
		s, _ := ssh.ParsePrivateKey(data)
		return s
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	pemData := pem.EncodeToMemory(pemBlock)
	os.WriteFile(path, pemData, 0600)

	s, _ := ssh.NewSignerFromKey(priv)
	return s
}

func getState(ip string) *sessionState {
	states.Lock()
	defer states.Unlock()
	if s, ok := states.m[ip]; ok {
		return s
	}
	s := &sessionState{}
	states.m[ip] = s
	return s
}
