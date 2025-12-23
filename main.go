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
	"strconv"
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
	knockSeq         = flag.String("knock-seq", "", "port knocking sequence (comma-separated ports, e.g. 7000,8000,9000)")
	knockOpen        = flag.Int("knock-open", 30, "seconds to keep SSH port open after successful knock sequence")
	knockTimeout     = flag.Int("knock-timeout", 10, "seconds timeout for the knocking sequence")
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

var knockState = struct {
	sync.Mutex
	m map[string]struct {
		step     int
		lastTime time.Time
	}
}{m: make(map[string]struct {
	step     int
	lastTime time.Time
})}

var knockSequence []int

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of ParrotSSH:\n")
		fmt.Fprintf(os.Stderr, "  A transparent SSH proxy that requires consecutive identical passwords before forwarding to a real SSH server.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	flag.Parse()

	if *listenAddr == "" || *realSSHAddr == "" {
		flag.Usage()
	}

	if *knockSeq != "" {
		seqStr := strings.Split(*knockSeq, ",")
		for _, s := range seqStr {
			p, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || p <= 0 || p > 65535 {
				log.Fatalf("Invalid knock port: %s", s)
			}
			knockSequence = append(knockSequence, p)
		}
		for _, p := range knockSequence {
			go listenKnockPort(p)
		}
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

func listenKnockPort(port int) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Printf("Failed to listen on knock port %d: %v", port, err)
		return
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

		knockState.Lock()
		entry, exists := knockState.m[host]
		if !exists {
			entry.step = 0
			entry.lastTime = time.Now()
		}

		if time.Since(entry.lastTime) > time.Duration(*knockTimeout)*time.Second {
			entry.step = 0
		}

		expected := knockSequence[entry.step]
		if port == expected {
			entry.step++
			entry.lastTime = time.Now()
			log.Printf("[%s] Port knock progress: %d/%d (%d)", host, entry.step, len(knockSequence), port)
		} else {
			log.Printf("[%s] Invalid knock sequence on port %d, ignoring", host, port)
			entry.step = 0
			entry.lastTime = time.Now()
		}

		knockState.m[host] = entry
		knockState.Unlock()
		conn.Close()
	}
}

func isAllowedByKnock(ipFull string) bool {
	if *knockSeq == "" {
		return true
	}

	host, _, _ := net.SplitHostPort(ipFull)
	if host == "127.0.0.1" || host == "::1" {
		return true
	}

	knockState.Lock()
	defer knockState.Unlock()

	entry, exists := knockState.m[host]
	if !exists {
		return false
	}

	if time.Since(entry.lastTime) > time.Duration(*knockOpen)*time.Second {
		delete(knockState.m, host)
		return false
	}

	return entry.step == len(knockSequence)
}

func passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	ipFull := conn.RemoteAddr().String()
	host, _, _ := net.SplitHostPort(ipFull)

	state := getState(ipFull)
	state.mu.Lock()
	defer state.mu.Unlock()

	pass := string(password)
	username := conn.User()

	log.Printf("[%s] User %s password attempt (%d): %s", ipFull, username, state.attemptCount+1, pass)

	if *saveFailInfo != "" {
		line := fmt.Sprintf("IP: %s | User: %s | Pass: %s\n", host, username, pass)
		failFile.WriteString(line)
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
	}

	state.attemptCount = 0
	state.password = ""
	return nil, fmt.Errorf("Permission denied, please try again.")
}

func handle(client net.Conn, config *ssh.ServerConfig) {
	defer client.Close()

	ipFull := client.RemoteAddr().String()
	if !isAllowedByKnock(ipFull) {
		return
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(client, config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	state := getState(ipFull)
	state.mu.Lock()
	username := state.username
	password := state.password
	state.mu.Unlock()

	realConn, err := net.DialTimeout("tcp", *realSSHAddr, 10*time.Second)
	if err != nil {
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
