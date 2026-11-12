package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type config struct {
	Listen, BaseURL, DataDir                                   string
	AdminToken, JellyfinURL, JellyfinKey                       string
	AuthentikURL, AuthentikToken, AuthentikPath                string
	AuthentikGroups                                            []string
	OIDCIssuer, OIDCClientID, OIDCClientSecret, OIDCAdminGroup string
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func secret(key string) (string, error) {
	if file := os.Getenv(key + "_FILE"); file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read %s_FILE: %w", key, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return os.Getenv(key), nil
}

func loadConfig() (config, error) {
	c := config{
		Listen:         env("LISTEN_ADDR", "127.0.0.1:8080"),
		BaseURL:        strings.TrimRight(os.Getenv("BASE_URL"), "/"),
		DataDir:        env("DATA_DIR", "./data"),
		JellyfinURL:    strings.TrimRight(os.Getenv("JELLYFIN_URL"), "/"),
		AuthentikURL:   strings.TrimRight(os.Getenv("AUTHENTIK_URL"), "/"),
		AuthentikPath:  env("AUTHENTIK_USER_PATH", "users/media"),
		OIDCIssuer:     os.Getenv("AUTHENTIK_OIDC_ISSUER"),
		OIDCClientID:   os.Getenv("AUTHENTIK_OIDC_CLIENT_ID"),
		OIDCAdminGroup: env("AUTHENTIK_ADMIN_GROUP", "media-admins"),
	}
	for key, dest := range map[string]*string{
		"ADMIN_TOKEN": &c.AdminToken, "JELLYFIN_API_KEY": &c.JellyfinKey, "AUTHENTIK_TOKEN": &c.AuthentikToken,
		"AUTHENTIK_OIDC_CLIENT_SECRET": &c.OIDCClientSecret,
	} {
		value, err := secret(key)
		if err != nil {
			return c, err
		}
		if value == "" {
			return c, fmt.Errorf("%s or %s_FILE is required", key, key)
		}
		*dest = value
	}
	if len(c.AdminToken) < 32 {
		return c, fmt.Errorf("ADMIN_TOKEN must contain at least 32 characters")
	}
	if c.OIDCClientID == "" {
		return c, fmt.Errorf("AUTHENTIK_OIDC_CLIENT_ID is required")
	}
	for key, value := range map[string]string{"BASE_URL": c.BaseURL, "JELLYFIN_URL": c.JellyfinURL, "AUTHENTIK_URL": c.AuthentikURL, "AUTHENTIK_OIDC_ISSUER": c.OIDCIssuer} {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return c, fmt.Errorf("%s must be an absolute HTTP(S) URL without credentials, query, or fragment", key)
		}
		if key == "BASE_URL" && u.Path != "" {
			return c, fmt.Errorf("BASE_URL must not contain a path; serve at the domain root")
		}
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return c, fmt.Errorf("LISTEN_ADDR: %w", err)
	}
	for _, group := range strings.Split(os.Getenv("AUTHENTIK_GROUPS"), ",") {
		if group = strings.TrimSpace(group); group != "" {
			c.AuthentikGroups = append(c.AuthentikGroups, group)
		}
	}
	return c, nil
}
