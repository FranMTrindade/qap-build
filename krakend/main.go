package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var pluginName = "qap-auth-injector"
var ClientRegisterer = registerer(pluginName)

type registerer string

func (r registerer) RegisterClients(f func(string, func(context.Context, map[string]interface{}) (http.Handler, error))) {
	f(string(r), r.registerClients)
}

func (r registerer) registerClients(_ context.Context, _ map[string]interface{}) (http.Handler, error) {
	token, err := fetchToken()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch token: %w", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.Header.Set("Authorization", "Bearer " + token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "Upstream request failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for k, v := range resp.Header {
			for _, h := range v {
				w.Header().Add(k, h)
			}
		}

		w.WriteHeader(resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		w.Write(body)
	}), nil
}

func fetchToken() (string, error) {
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "qap-front")
	form.Add("client_secret", "tIk6IvluTeOS2o23C4nffL48j2fyF50H")
	form.Add("username", "admin@konneqt.io")
	form.Add("password", "LZNK1kguf_KI")

	req, err := http.NewRequest("POST", "https://idp.konneqt.cloud/realms/qap-dev/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var resBody struct {
		AccessToken string `json:"access_token"`
	}
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &resBody)

	if resBody.AccessToken == "" {
		return "", fmt.Errorf("token not found in response")
	}
	return resBody.AccessToken, nil
}
