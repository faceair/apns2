package apns2

import (
	"crypto/tls"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var emptyConfig tls.Config

func tlsDialWithDialer(dialer *net.Dialer, pdialer proxy.Dialer, network, addr string, config *tls.Config) (*tls.Conn, error) {
	// We want the Timeout and Deadline values from dialer to cover the
	// whole process: TCP connection and TLS handshake. This means that we
	// also need to start our own timers now.
	timeout := dialer.Timeout

	if !dialer.Deadline.IsZero() {
		deadlineTimeout := time.Until(dialer.Deadline)
		if timeout == 0 || deadlineTimeout < timeout {
			timeout = deadlineTimeout
		}
	}

	var errChannel chan error

	if timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(timeout, func() {
			errChannel <- timeoutError{}
		})
	}

	// Modified for support proxy
	var rawConn net.Conn
	var err error
	if pdialer == nil {
		rawConn, err = dialer.Dial(network, addr)
	} else {
		rawConn, err = pdialer.Dial(network, addr)
	}
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = &emptyConfig
	}
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}

	conn := tls.Client(rawConn, config)

	if timeout == 0 {
		err = conn.Handshake()
	} else {
		go func() {
			errChannel <- conn.Handshake()
		}()

		err = <-errChannel
	}

	if err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

func proxyDialer(dialer *net.Dialer, proxyURL *url.URL) proxy.Dialer {
	pdialer, err := proxy.FromURL(proxyURL, dialer)
	if err != nil {
		log.Printf("apns2: parse proxy url error %s", err.Error())
		return nil
	}
	return pdialer
}
