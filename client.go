// Package apns2 is a go Apple Push Notification Service (APNs) provider that
// allows you to send remote notifications to your iOS, tvOS, and OS X
// apps, using the new APNs HTTP/2 network protocol.
package apns2

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/faceair/apns2/token"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// Apple HTTP/2 Development & Production urls
const (
	HostDevelopment = "https://api.development.push.apple.com"
	HostProduction  = "https://api.push.apple.com"
)

// DefaultHost is a mutable var for testing purposes
var DefaultHost = HostDevelopment

var (
	// TLSDialTimeout is the maximum amount of time a dial will wait for a connect
	// to complete.
	TLSDialTimeout = 20 * time.Second
	// HTTPClientTimeout specifies a time limit for requests made by the
	// HTTPClient. The timeout includes connection time, any redirects,
	// and reading the response body.
	HTTPClientTimeout = 30 * time.Second
	// TCPKeepAlive specifies the keep-alive period for an active network
	// connection. If zero, keep-alives are not enabled.
	TCPKeepAlive = 10 * time.Second
	// PingPongFrequency is the interval with which a client will PING APNs
	// servers.
	PingPongFrequency = 10 * time.Second
)

// Client represents a connection with the APNs
type Client struct {
	Host            string
	Certificate     tls.Certificate
	Token           *token.Token
	HTTPClient      *http.Client
	proxyURL        *url.URL
	proxyDialer     proxy.Dialer
	pinging         bool
	enablePingChan  chan net.Conn
	disablePingChan chan struct{}
	m               sync.Mutex
}

type connectionCloser interface {
	CloseIdleConnections()
}

// NewClient returns a new Client with an underlying http.Client configured with
// the correct APNs HTTP/2 transport settings. It does not connect to the APNs
// until the first Notification is sent via the Push method.
//
// As per the Apple APNs Provider API, you should keep a handle on this client
// so that you can keep your connections with APNs open across multiple
// notifications; don’t repeatedly open and close connections. APNs treats rapid
// connection and disconnection as a denial-of-service attack.
//
// If your use case involves multiple long-lived connections, consider using
// the ClientManager, which manages clients for you.
//
// Alternatively, you can keep the clients connection healthy by calling
// EnablePinging, which will send PING frames to APNs servers with the interval
// specified via PingPongFrequency.
func NewClient(certificate tls.Certificate) *Client {
	c := &Client{
		Certificate:     certificate,
		Host:            DefaultHost,
		enablePingChan:  make(chan net.Conn, 1),
		disablePingChan: make(chan struct{}, 1),
	}
	c.ResetHTTPClient()
	return c
}

func (c *Client) ResetHTTPClient() {
	c.m.Lock()
	defer c.m.Unlock()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{c.Certificate},
	}
	if len(c.Certificate.Certificate) > 0 {
		tlsConfig.BuildNameToCertificate()
	}

	c.HTTPClient = &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: tlsConfig,
			DialTLS:         c.DialTLS,
		},
		Timeout: HTTPClientTimeout,
	}
}

// NewTokenClient returns a new Client with an underlying http.Client configured
// with the correct APNs HTTP/2 transport settings. It does not connect to the APNs
// until the first Notification is sent via the Push method.
//
// As per the Apple APNs Provider API, you should keep a handle on this client
// so that you can keep your connections with APNs open across multiple
// notifications; don’t repeatedly open and close connections. APNs treats rapid
// connection and disconnection as a denial-of-service attack.
func NewTokenClient(token *token.Token) *Client {
	c := &Client{
		Token:           token,
		Host:            DefaultHost,
		enablePingChan:  make(chan net.Conn, 1),
		disablePingChan: make(chan struct{}, 1),
	}
	c.ResetHTTPClient()
	return c
}

// Development sets the Client to use the APNs development push endpoint.
func (c *Client) Development() *Client {
	c.Host = HostDevelopment
	return c
}

// Production sets the Client to use the APNs production push endpoint.
func (c *Client) Production() *Client {
	c.Host = HostProduction
	return c
}

func (c *Client) EnableProxy(proxyURI string) error {
	proxyURL, err := url.Parse(proxyURI)
	c.proxyURL = proxyURL
	return err
}

func (c *Client) getNetDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   TLSDialTimeout,
		KeepAlive: TCPKeepAlive,
	}
}

func (c *Client) getProxyDialer(dialer *net.Dialer) proxy.Dialer {
	if c.proxyURL != nil {
		return proxyDialer(dialer, c.proxyURL)
	}
	return nil
}

// DialTLS is the default dial function for creating TLS connections for
// non-proxied HTTPS requests.
func (c *Client) DialTLS(network, addr string, cfg *tls.Config) (conn net.Conn, err error) {
	dialer := c.getNetDialer()
	pdialer := c.getProxyDialer(dialer)

	conn, err = tlsDialWithDialer(dialer, pdialer, network, addr, cfg)
	if err == nil && c.pinging {
		c.enablePingChan <- conn
	}
	return conn, err
}

// Push sends a Notification to the APNs gateway. If the underlying http.Client
// is not currently connected, this method will attempt to reconnect
// transparently before sending the notification. It will return a Response
// indicating whether the notification was accepted or rejected by the APNs
// gateway, or an error if something goes wrong.
//
// Use PushWithContext if you need better cancellation and timeout control.
func (c *Client) Push(n *Notification) (*Response, error) {
	return c.PushWithContext(nil, n)
}

// PushWithContext sends a Notification to the APNs gateway. Context carries a
// deadline and a cancellation signal and allows you to close long running
// requests when the context timeout is exceeded. Context can be nil, for
// backwards compatibility.
//
// If the underlying http.Client is not currently connected, this method will
// attempt to reconnect transparently before sending the notification. It will
// return a Response indicating whether the notification was accepted or
// rejected by the APNs gateway, or an error if something goes wrong.
func (c *Client) PushWithContext(ctx Context, n *Notification) (*Response, error) {
	payload, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%v/3/device/%v", c.Host, n.DeviceToken)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(payload))

	if c.Token != nil {
		c.setTokenHeader(req)
	}

	setHeaders(req, n)

	httpRes, err := c.requestWithContext(ctx, req)
	if err != nil {
		return nil, err
	}
	defer httpRes.Body.Close()

	response := &Response{}
	response.StatusCode = httpRes.StatusCode
	response.ApnsID = httpRes.Header.Get("apns-id")

	decoder := json.NewDecoder(httpRes.Body)
	if err := decoder.Decode(&response); err != nil && err != io.EOF {
		return &Response{}, err
	}
	return response, nil
}

// CloseIdleConnections closes any underlying connections which were previously
// connected from previous requests but are now sitting idle. It will not
// interrupt any connections currently in use.
func (c *Client) CloseIdleConnections() {
	c.HTTPClient.Transport.(connectionCloser).CloseIdleConnections()
}

func (c *Client) setTokenHeader(r *http.Request) {
	c.Token.GenerateIfExpired()
	r.Header.Set("authorization", fmt.Sprintf("bearer %v", c.Token.Bearer))
}

// EnablePinging tries to send PING frames to APNs servers whenever the client
// has a valid connection. If the willHandleDrops parameter is set to true, this
// function returns a read-only channel that gets notified when pinging fails.
// This allows the user to take actions to preemptively reinitialize the client's
// connection. The second return value indicates whether the call has successfully
// enabled pinging.
func (c *Client) EnablePinging(willHandleDrops bool) (<-chan struct{}, bool) {
	c.m.Lock()
	defer c.m.Unlock()

	if c.pinging {
		return nil, false
	}
	dropSignal := make(chan struct{}, 1)
	c.pinging = true

	go func() {
		// 8 bytes of random data used for PING-PONG, as per HTTP/2 spec.
		var data [8]byte
		rand.Read(data[:])

		var timer *time.Ticker
		var framer *http2.Framer

		timer = time.NewTicker(time.Hour * 24 * 30)
		for {
			select {
			case <-timer.C:
				if framer == nil {
					timer.Stop()
					continue
				}

				c.pinging = true
				err := framer.WritePing(false, data)
				if err != nil {
					// Could not PING the APNs server, stop trying
					// and notify the drop handler, if there is any.
					c.disablePingChan <- struct{}{}

					if willHandleDrops {
						dropSignal <- struct{}{}
					}
				}
			case conn := <-c.enablePingChan:
				c.m.Lock()

				timer.Stop()
				framer = http2.NewFramer(conn, conn)
				timer = time.NewTicker(PingPongFrequency)

				c.m.Unlock()
			case <-c.disablePingChan:
				c.m.Lock()

				c.pinging = false
				timer.Stop()
				framer = nil

				c.m.Unlock()
				return
			}
		}
	}()

	return dropSignal, true
}

// DisablePinging stops the pinging operation associated with the client, if
// there's any, and returns a boolean that indicates if the call has successfully
// stopped the pinging operation.
func (c *Client) DisablePinging() bool {
	if c.pinging {
		c.disablePingChan <- struct{}{}
	}
	return c.pinging
}

func setHeaders(r *http.Request, n *Notification) {
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	if n.Topic != "" {
		r.Header.Set("apns-topic", n.Topic)
	}
	if n.ApnsID != "" {
		r.Header.Set("apns-id", n.ApnsID)
	}
	if n.CollapseID != "" {
		r.Header.Set("apns-collapse-id", n.CollapseID)
	}
	if n.Priority > 0 {
		r.Header.Set("apns-priority", fmt.Sprintf("%v", n.Priority))
	}
	if !n.Expiration.IsZero() {
		r.Header.Set("apns-expiration", fmt.Sprintf("%v", n.Expiration.Unix()))
	}
}
