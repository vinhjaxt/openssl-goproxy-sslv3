package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/libp2p/go-openssl"
	"github.com/valyala/fasthttp"
)

var dialer = (&net.Dialer{
	DualStack: true,
	Timeout:   7 * time.Second,
}).Dial
var json = jsoniter.ConfigCompatibleWithStandardLibrary
var uncatchRecover = func() {
	if r := recover(); r != nil {
		log.Println("Uncatched error:", r, string(debug.Stack()))
	}
}

var sslVer = flag.Int(`ver`, 0x02, `SSL Version. SSLv3 = 2; TLSv1 = 3; TLSv1.1 = 4; TLSv1.2 = 5; AnyVer = 6`)
var noVerify = flag.Bool(`k`, false, `Don't verify SNI`)

func TlsDial(hostname string, addr string) (net.Conn, error) {
	conn, err := dialer("tcp", addr)
	if err != nil {
		return nil, err
	}
	ctx, err := openssl.NewCtxWithVersion(openssl.SSLVersion(*sslVer))
	if err != nil {
		conn.Close()
		return nil, err
	}
	tlsConn, err := openssl.Client(conn, ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	err = tlsConn.SetTlsExtHostName(hostname)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	err = tlsConn.Handshake()
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	if *noVerify == false {
		err = tlsConn.VerifyHostname(hostname)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}
	return tlsConn, err
}

func httpsHandler(ctx *fasthttp.RequestCtx, hostname string, remoteAddr string) error {
	var r net.Conn
	isMustProxify := mustProxify(hostname)

	if isMustProxify {
		var err error
		r, err = TlsDial(hostname, remoteAddr)
		if err != nil {
			return err
		}
	} else {
		var err error
		r, err = dialer("tcp", remoteAddr)
		if err != nil {
			return err
		}
	}
	if ctx.Hijacked() {
		return nil
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Keep-Alive", "timeout=120, max=5")
	ctx.Hijack(func(clientConn net.Conn) {
		var l net.Conn
		if isMustProxify {
			tlsConfig, err := TLSConfigFromCA(&GoproxyCa, hostname)
			if err != nil {
				log.Println("TLSConfigFromCA:", hostname, err)
				return
			}
			clientConnTLS := tls.Server(clientConn, tlsConfig)
			err = clientConnTLS.Handshake()
			if err != nil {
				log.Println("Client handshake", hostname, err)
				return
			}
			l = clientConnTLS
		} else {
			l = clientConn
		}
		go ioTransfer(r, l)
		ioTransfer(l, r)
	})
	return nil
}

func ioTransfer(destination io.WriteCloser, source io.ReadCloser) {
	defer func() {
		time.Sleep(time.Second)
		destination.Close()
		source.Close()
	}()
	_, err := io.Copy(destination, source)
	if err != nil {
		if err != io.EOF {
			// log.Println("ioTransfer", err)
		}
	}
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	defer uncatchRecover()
	// Some library must set header: Connection: keep-alive
	// ctx.Response.Header.Del("Connection")
	// ctx.Response.ConnectionClose() // ==> false

	// log.Println(string(ctx.Path()), string(ctx.Host()), ctx.String(), "\r\n\r\n", ctx.Request.String())

	host := string(ctx.Host())
	if len(host) < 1 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		log.Println("Reject: Empty host")
		return
	}

	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		if err1, ok := err.(*net.AddrError); ok && strings.Index(err1.Err, "missing port") != -1 {
			if bytes.Equal(ctx.Method(), []byte("CONNECT")) {
				port = "443"
			} else {
				port = "80"
			}
			hostname, _, err = net.SplitHostPort(host + ":80")
		}
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			log.Println("Reject: Invalid host", host, err)
			return
		}
	}

	// https connecttion
	if bytes.Equal(ctx.Method(), []byte("CONNECT")) {
		err = httpsHandler(ctx, hostname, `[`+hostname+`]:`+port)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			log.Println("httpsHandler:", host, err)
		}
		return
	}

	err = httpClient.DoTimeout(&ctx.Request, &ctx.Response, httpClientTimeout)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		log.Println("httpHandler:", host, err)
	}
}

// Domains
var domainList = flag.String("d", "domains.txt", "Domains List File")
var domainRegexList = flag.String("r", "domains-regex.txt", "Domains Regex List File")
var domainCertMapFile = flag.String("dcm", "domains-certs.json", "Domains Cert Map File")

type DomainAlias struct {
	Base  string
	Alias string
}

var domainProxiesCache = map[string]bool{}
var domainProxiesCacheLock sync.RWMutex
var domainsRegex []*regexp.Regexp
var lineRegex = regexp.MustCompile(`[\r\n]+`)
var domainsAlias []*DomainAlias

func parseDomains() bool {
	if len(*domainList) > 0 {
		c, err := ioutil.ReadFile(*domainList)
		if err == nil {
			lines := lineRegex.Split(string(c), -1)
			for _, line := range lines {
				line = strings.Trim(line, "\r\n\t ")
				if len(line) < 1 || line[0] == '#' {
					continue
				}
				domainProxiesCacheLock.Lock()
				domainProxiesCache[line] = true
				domainProxiesCacheLock.Unlock()
			}
		} else {
			log.Println(err)
		}
	}
	if len(*domainRegexList) > 0 {
		c, err := ioutil.ReadFile(*domainRegexList)
		if err == nil {
			lines := lineRegex.Split(string(c), -1)
			for _, line := range lines {
				line = strings.Trim(line, "\r\n\t ")
				if len(line) < 1 || line[0] == '#' {
					continue
				}
				domainsRegex = append(domainsRegex, regexp.MustCompile(line))
			}
		} else {
			log.Println(err)
		}
	}
	if len(*domainCertMapFile) > 0 {
		var certDomainAliasMap = map[string]string{}
		c, err := ioutil.ReadFile(*domainCertMapFile)
		if err == nil {
			err = json.Unmarshal(c, &certDomainAliasMap)
		}
		if err == nil {
			for k, v := range certDomainAliasMap {
				if len(k) > 1 && k[0] == '*' {
					domainsAlias = append(domainsAlias, &DomainAlias{
						Base:  k[1:],
						Alias: v,
					})
				} else {
					cacheVerifyMapLock.Lock()
					cacheVerifyMap[k] = v
					cacheVerifyMapLock.Unlock()
				}
			}
		} else {
			log.Println(err)
		}
	}
	if len(domainsRegex) < 1 && len(domainProxiesCache) < 1 {
		log.Println("No domains to proxy? Please specify a domain name in", *domainList, "or", *domainRegexList)
		return false
	}
	return true
}

// OK, no lock need here
func mustProxify(hostname string) bool {
	domainProxiesCacheLock.RLock()
	b, ok := domainProxiesCache[hostname]
	domainProxiesCacheLock.RUnlock()
	if ok {
		return b
	}
	b = false
	for _, re := range domainsRegex {
		b = re.MatchString(hostname)
		if b {
			break
		}
	}
	domainProxiesCacheLock.Lock()
	domainProxiesCache[hostname] = b
	domainProxiesCacheLock.Unlock()
	log.Println("Proxify:", hostname, b)
	return b
}

var listen = flag.String(`listen`, `:8081`, `Listen address. Eg: :8443; unix:/tmp/proxy.sock`)

func main() {
	flag.Parse()

	if parseDomains() == false {
		return
	}

	// Server
	var err error
	var ln net.Listener
	if strings.HasPrefix(*listen, `unix:`) {
		unixFile := (*listen)[5:]
		os.Remove(unixFile)
		ln, err = net.Listen(`unix`, unixFile)
		os.Chmod(unixFile, os.ModePerm)
		log.Println(`Listening:`, unixFile)
	} else {
		ln, err = net.Listen(`tcp`, *listen)
		log.Println(`Listening:`, ln.Addr().String())
	}
	if err != nil {
		log.Panicln(err)
	}
	srv := &fasthttp.Server{
		// ErrorHandler: nil,
		Handler:               requestHandler,
		NoDefaultServerHeader: true, // Don't send Server: fasthttp
		// Name: "nginx",  // Send Server header
		ReadBufferSize:                2 * 4096, // Make sure these are big enough.
		WriteBufferSize:               4096,
		ReadTimeout:                   5 * time.Second,
		WriteTimeout:                  time.Second,
		IdleTimeout:                   time.Minute, // This can be long for keep-alive connections.
		DisableHeaderNamesNormalizing: false,       // If you're not going to look at headers or know the casing you can set this.
		// NoDefaultContentType: true, // Don't send Content-Type: text/plain if no Content-Type is set manually.
		MaxRequestBodySize: 200 * 1024 * 1024, // 200MB
		DisableKeepalive:   false,
		KeepHijackedConns:  false,
		// NoDefaultDate: len(*staticDir) == 0,
		ReduceMemoryUsage: true,
		TCPKeepalive:      true,
		// TCPKeepalivePeriod: 10 * time.Second,
		// MaxRequestsPerConn: 1000,
		// MaxConnsPerIP: 20,
	}
	log.Panicln(srv.Serve(ln))
}
