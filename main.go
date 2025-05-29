package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the YAML configuration structure
type Config struct {
	Listen struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"listen"`
	Network struct {
		InterfaceIP string `yaml:"interface_ip"`
		DNS         string `yaml:"dns,omitempty"`
		Retry       struct {
			MaxRetries    int `yaml:"max_retries"`
			RetryDelay    int `yaml:"retry_delay_seconds"`
			BackoffFactor int `yaml:"backoff_factor"`
		} `yaml:"retry"`
	} `yaml:"network"`
	Logging struct {
		Level string `yaml:"level"`
		File  string `yaml:"file"`
	} `yaml:"logging"`
}

// ProxyServer represents the main proxy server
type ProxyServer struct {
	config     *Config
	logger     *log.Logger
	httpClient *http.Client
	server     *http.Server
}

// NewProxyServer creates a new proxy server instance
func NewProxyServer(configPath string) (*ProxyServer, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	logger, err := setupLogger(config)
	if err != nil {
		return nil, fmt.Errorf("failed to setup logger: %w", err)
	}

	// Create HTTP client with specific interface binding
	transport, err := createTransport(config.Network.InterfaceIP)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	ps := &ProxyServer{
		config:     config,
		logger:     logger,
		httpClient: httpClient,
	}

	// Setup HTTP server
	addr := fmt.Sprintf("%s:%d", config.Listen.Host, config.Listen.Port)
	ps.server = &http.Server{
		Addr:         addr,
		Handler:      ps,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return ps, nil
}

// loadConfig loads configuration from YAML file
func loadConfig(configPath string) (*Config, error) {
	// If configPath is empty, try to find config.yaml in executable directory
	if configPath == "" {
		exePath, err := os.Executable()
		if err != nil {
			return nil, err
		}
		configPath = filepath.Join(filepath.Dir(exePath), "config.yaml")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Set defaults
	if config.Listen.Host == "" {
		config.Listen.Host = "127.0.0.1"
	}
	if config.Listen.Port == 0 {
		config.Listen.Port = 8080
	}
	if config.Logging.Level == "" {
		config.Logging.Level = "error"
	}
	if config.Logging.File == "" {
		config.Logging.File = "./proxy.log"
	}
	// Set retry defaults
	if config.Network.Retry.MaxRetries == 0 {
		config.Network.Retry.MaxRetries = 3
	}
	if config.Network.Retry.RetryDelay == 0 {
		config.Network.Retry.RetryDelay = 2
	}
	if config.Network.Retry.BackoffFactor == 0 {
		config.Network.Retry.BackoffFactor = 2
	}

	return &config, nil
}

// setupLogger creates and configures the logger
func setupLogger(config *Config) (*log.Logger, error) {
	var output io.Writer = os.Stdout

	if config.Logging.File != "" && config.Logging.File != "stdout" {
		file, err := os.OpenFile(config.Logging.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, err
		}
		output = file
	}

	logger := log.New(output, "[PROXY] ", log.LstdFlags|log.Lshortfile)
	return logger, nil
}

// createTransport creates HTTP transport with interface binding
func createTransport(interfaceIP string) (*http.Transport, error) {
	if interfaceIP == "" {
		return http.DefaultTransport.(*http.Transport).Clone(), nil
	}

	// Parse the interface IP
	ip := net.ParseIP(interfaceIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid interface IP: %s", interfaceIP)
	}

	// Create custom dialer that binds to specific interface
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP: ip,
		},
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}

	return transport, nil
}

// ServeHTTP implements http.Handler interface
func (ps *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		ps.handleHTTPS(w, r)
	} else {
		ps.handleHTTP(w, r)
	}
}

// handleHTTP handles regular HTTP requests
func (ps *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Remove proxy-specific headers
	r.RequestURI = ""
	
	// Ensure we have a complete URL
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	// Create new request
	outReq := r.Clone(r.Context())
	
	// Remove hop-by-hop headers
	removeHopByHopHeaders(outReq.Header)
	
	// Forward the request with retry mechanism
	resp, err := ps.retryableHTTPRequest(outReq)
	if err != nil {
		ps.logger.Printf("HTTP request failed after retries: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		ps.logger.Printf("Failed to copy response body: %v", err)
	}
}

// handleHTTPS handles HTTPS CONNECT requests
func (ps *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	// Parse target host and port
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			host = r.Host
			port = "443"
		} else {
			ps.logger.Printf("Invalid host: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
	}

	// Create connection to target server with retry mechanism
	targetAddr := net.JoinHostPort(host, port)
	
	targetConn, err := ps.retryableTCPDial("tcp", targetAddr)
	if err != nil {
		ps.logger.Printf("Failed to connect to target %s after retries: %v", targetAddr, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		ps.logger.Printf("Hijacking not supported")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		ps.logger.Printf("Failed to hijack connection: %v", err)
		return
	}
	defer clientConn.Close()

	// Send 200 Connection Established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		ps.logger.Printf("Failed to send connection established: %v", err)
		return
	}

	// Start bidirectional copying
	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		io.Copy(targetConn, clientConn)
	}()

	io.Copy(clientConn, targetConn)
}

// retryableHTTPClient creates an HTTP client with retry mechanism
func (ps *ProxyServer) retryableHTTPRequest(req *http.Request) (*http.Response, error) {
	var lastErr error
	maxRetries := ps.config.Network.Retry.MaxRetries
	retryDelay := time.Duration(ps.config.Network.Retry.RetryDelay) * time.Second
	backoffFactor := ps.config.Network.Retry.BackoffFactor

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry with exponential backoff
			delay := retryDelay * time.Duration(1<<(attempt-1)*backoffFactor)
			ps.logger.Printf("Retry attempt %d/%d after %v delay", attempt, maxRetries, delay)
			time.Sleep(delay)
		}

		resp, err := ps.httpClient.Do(req)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		ps.logger.Printf("Request attempt %d failed: %v", attempt+1, err)

		// Check if error is retryable (network-related)
		if !isRetryableError(err) {
			ps.logger.Printf("Non-retryable error, stopping retries: %v", err)
			break
		}
	}

	return nil, fmt.Errorf("max retries exceeded, last error: %w", lastErr)
}

// isRetryableError determines if an error is worth retrying
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())
	retryableErrors := []string{
		"connection refused",
		"network is unreachable",
		"no route to host",
		"connection timed out",
		"temporary failure",
		"operation timed out",
		"broken pipe",
		"connection reset",
		"interface not found",
	}

	for _, retryable := range retryableErrors {
		if strings.Contains(errStr, retryable) {
			return true
		}
	}

	// Check for net.Error interface (timeout, temporary)
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout() || netErr.Temporary()
	}

	return false
}

// retryableTCPDial creates TCP connection with retry mechanism
func (ps *ProxyServer) retryableTCPDial(network, address string) (net.Conn, error) {
	var lastErr error
	maxRetries := ps.config.Network.Retry.MaxRetries
	retryDelay := time.Duration(ps.config.Network.Retry.RetryDelay) * time.Second
	backoffFactor := ps.config.Network.Retry.BackoffFactor

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := retryDelay * time.Duration(1<<(attempt-1)*backoffFactor)
			ps.logger.Printf("TCP dial retry attempt %d/%d after %v delay", attempt, maxRetries, delay)
			time.Sleep(delay)
		}

		var conn net.Conn
		var err error

		if ps.config.Network.InterfaceIP != "" {
			dialer := &net.Dialer{
				LocalAddr: &net.TCPAddr{
					IP: net.ParseIP(ps.config.Network.InterfaceIP),
				},
				Timeout: 10 * time.Second,
			}
			conn, err = dialer.Dial(network, address)
		} else {
			conn, err = net.DialTimeout(network, address, 10*time.Second)
		}

		if err == nil {
			return conn, nil
		}

		lastErr = err
		ps.logger.Printf("TCP dial attempt %d failed: %v", attempt+1, err)

		if !isRetryableError(err) {
			ps.logger.Printf("Non-retryable TCP error, stopping retries: %v", err)
			break
		}
	}

	return nil, fmt.Errorf("max TCP dial retries exceeded, last error: %w", lastErr)
}
func removeHopByHopHeaders(header http.Header) {
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

// Start starts the proxy server
func (ps *ProxyServer) Start() error {
	ps.logger.Printf("Starting proxy server on %s", ps.server.Addr)
	ps.logger.Printf("Using interface IP: %s", ps.config.Network.InterfaceIP)
	
	return ps.server.ListenAndServe()
}

// Stop stops the proxy server gracefully
func (ps *ProxyServer) Stop(ctx context.Context) error {
	ps.logger.Printf("Stopping proxy server...")
	return ps.server.Shutdown(ctx)
}

func main() {
	// Parse command line arguments
	configPath := ""
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	// Create proxy server
	proxy, err := NewProxyServer(configPath)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		if err := proxy.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	proxy.logger.Printf("Received shutdown signal")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := proxy.Stop(ctx); err != nil {
		proxy.logger.Printf("Server shutdown error: %v", err)
	} else {
		proxy.logger.Printf("Server shutdown complete")
	}
}