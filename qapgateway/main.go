
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

type Config struct {
	NatsUrl            string
	NatsToken          string
	NatsQueueQAP       string
	NatsQueueAnalytics string
	EndpointCheck      string
}

type RequestObject struct {
	Type       string              `json:"type"`
	Path       string              `json:"path"`
	Method     string              `json:"method"`
	HttpStatus int                 `json:"http_status"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
}

type ResponseObject struct {
	Type       string              `json:"type"`
	Path       string              `json:"path"`
	Method     string              `json:"method"`
	HttpStatus int                 `json:"http_status"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
}

type Nats struct {
	Conn               *nats.Conn
	NatsUrl            string
	NatsToken          string
	NatsQueueQAP       string
	NatsQueueAnalytics string
}

var endpointMap = map[string]string{
	"/csscolornames/colors": "/css/cores",
}

func NewNats(natsUrl, natsToken, natsQueueQAP, natsQueueAnalytics string) *Nats {
	return &Nats{
		NatsUrl:            natsUrl,
		NatsToken:          natsToken,
		NatsQueueQAP:       natsQueueQAP,
		NatsQueueAnalytics: natsQueueAnalytics,
	}
}

var pluginName = "qap-krakend-plugin"
var ClientRegisterer = registerer(pluginName)

type registerer string

func (r registerer) RegisterClients(f func(
	name string,
	handler func(context.Context, map[string]interface{}) (http.Handler, error),
)) {
	f(string(r), r.registerClients)
}

func (r registerer) registerClients(_ context.Context, extra map[string]interface{}) (http.Handler, error) {
	config := GetConfig()
	nats := NewNats(config.NatsUrl, config.NatsToken, config.NatsQueueQAP, config.NatsQueueAnalytics)
	nats.StartConn()

	gatewayName := "unknown-gateway"
	if val, ok := extra["gateway_name"].(string); ok {
		gatewayName = val
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		krakendPath := req.URL.Path
		if ep, ok := extra["endpoint"].(string); ok && ep != "" {
			krakendPath = ep
		}
		if val, ok := endpointMap[krakendPath]; ok {
			krakendPath = val
		}

		originalBody, err := io.ReadAll(req.Body)
		if err != nil {
			logger.Error("Failed to read request body:", err)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewBuffer(originalBody))

		requestObject := RequestObject{
			Type:       "request",
			Path:       req.URL.Path,
			Method:     req.Method,
			HttpStatus: 0,
			Headers:    req.Header,
			Body:       string(originalBody),
		}

		if requestMsg, err := json.Marshal(requestObject); err == nil {
			nats.PublishQAP(requestMsg)
			nats.PublishAnalytics(requestMsg)
		} else {
			logger.Error("Failed to marshal request:", err)
		}

		if strings.TrimSpace(config.EndpointCheck) != "" {
			valid, err := AccessCheck(config.EndpointCheck, req.Header)
			if err != nil {
				logger.Error("Checking service unavailable:", err)
				http.Error(w, "Checking service unavailable", http.StatusInternalServerError)
				return
			}
			if !valid {
				http.Error(w, "Access Denied", http.StatusForbidden)
				return
			}
		}

		forwardReq, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), bytes.NewReader(originalBody))
		if err != nil {
			http.Error(w, "Failed to create forward request", http.StatusInternalServerError)
			return
		}
		forwardReq.Header = req.Header.Clone()

		resp, err := http.DefaultClient.Do(forwardReq)
		if err != nil {
			http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Failed to read response", http.StatusInternalServerError)
			return
		}

		userEmail := req.Header.Get("X-User-Email")
		authToken := req.Header.Get("Authorization") // ✅ Captura o token

		mergedHeaders := map[string][]string{}
		for k, v := range resp.Header {
			mergedHeaders[k] = v
		}
		mergedHeaders["X-API-Path"] = []string{krakendPath}
		mergedHeaders["X-Status"] = []string{fmt.Sprintf("%d", resp.StatusCode)}
		mergedHeaders["X-Api-Key"] = []string{gatewayName}
		if userEmail != "" {
			mergedHeaders["X-User-Email"] = []string{userEmail}
		}
		if authToken != "" {
			mergedHeaders["X-Authorization"] = []string{authToken}
		}

		responseObject := ResponseObject{
			Type:       "response",
			Path:       req.URL.Path,
			Method:     req.Method,
			HttpStatus: resp.StatusCode,
			Headers:    mergedHeaders,
			Body:       string(respBody),
		}

		if respMsg, err := json.Marshal(responseObject); err == nil {
			nats.PublishQAP(respMsg)
			nats.PublishAnalytics(respMsg)
		} else {
			logger.Error("Failed to marshal response:", err)
		}

		for k, hs := range resp.Header {
			for _, h := range hs {
				w.Header().Add(k, h)
			}
		}

		w.Header().Set("X-API-Path", krakendPath)
		w.Header().Set("X-Status", fmt.Sprintf("%d", resp.StatusCode))
		w.Header().Set("X-Api-Key", gatewayName)
		if userEmail != "" {
			w.Header().Set("X-User-Email", userEmail)
		}
		if authToken != "" {
			w.Header().Set("X-Authorization", authToken)
		}

		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
	}), nil
}

func GetConfig() *Config {
	return &Config{
		NatsUrl:            os.Getenv("NATS_URL"),
		NatsToken:          os.Getenv("NATS_TOKEN"),
		NatsQueueQAP:       os.Getenv("NATS_QUEUE_QAP"),
		NatsQueueAnalytics: os.Getenv("NATS_QUEUE_ANALYTICS"),
		EndpointCheck:      os.Getenv("ENDPOINT_CHECK"),
	}
}

func (n *Nats) StartConn() {
	conn, err := nats.Connect(
		n.NatsUrl,
		nats.Token(n.NatsToken),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(10*time.Second),
		nats.DisconnectHandler(func(_ *nats.Conn) {
			logger.Error("Disconnected from NATS")
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			logger.Debug("Reconnected to NATS")
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			logger.Error("Connection to NATS closed")
		}),
	)
	if err != nil {
		logger.Error("Failed to connect to NATS:", err)
		return
	}
	n.Conn = conn
}

func (n *Nats) PublishQAP(message []byte) {
	if n.Conn == nil || !n.Conn.IsConnected() {
		logger.Error("Cannot publish QAP: NATS connection not established")
		return
	}
	if err := n.Conn.Publish(n.NatsQueueQAP, message); err != nil {
		logger.Error("Failed to publish QAP message:", err)
	}
}

func (n *Nats) PublishAnalytics(message []byte) {
	if n.Conn == nil || !n.Conn.IsConnected() {
		logger.Error("Cannot publish Analytics: NATS connection not established")
		return
	}
	if err := n.Conn.Publish(n.NatsQueueAnalytics, message); err != nil {
		logger.Error("Failed to publish Analytics message:", err)
	}
}

func AccessCheck(endpoint string, header http.Header) (bool, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return false, err
	}

	req.Header = header.Clone()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("❌ endpoint: %v - return: %v - %v", endpoint, resp.StatusCode, string(body))
	}
	return true, nil
}

func main() {}

var logger Logger = nil

func (registerer) RegisterLogger(v interface{}) {
	if l, ok := v.(Logger); ok {
		logger = l
		logger.Debug(fmt.Sprintf("[PLUGIN: %s] 🎫 Client-Plugin: Registered", ClientRegisterer))
	}
}

type Logger interface {
	Debug(v ...interface{})
	Info(v ...interface{})
	Warning(v ...interface{})
	Error(v ...interface{})
	Critical(v ...interface{})
	Fatal(v ...interface{})
}
