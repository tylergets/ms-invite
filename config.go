package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type config struct {
	JellyfinEnabled, AuthentikEnabled                          bool
	JellyfinLibraryIDs                                         []string
	JellyfinLiveTV                                             bool
	JellyfinPublicURL                                          string
	SiteName                                                   string
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
		SiteName:          env("SITE_NAME", "Media library"),
		Listen:            env("LISTEN_ADDR", "127.0.0.1:8080"),
		BaseURL:           strings.TrimRight(os.Getenv("BASE_URL"), "/"),
		DataDir:           env("DATA_DIR", "./data"),
		JellyfinURL:       strings.TrimRight(os.Getenv("JELLYFIN_URL"), "/"),
		JellyfinPublicURL: strings.TrimRight(os.Getenv("JELLYFIN_PUBLIC_URL"), "/"),
		AuthentikURL:      strings.TrimRight(os.Getenv("AUTHENTIK_URL"), "/"),
		AuthentikPath:     env("AUTHENTIK_USER_PATH", "users/media"),
		OIDCIssuer:        os.Getenv("AUTHENTIK_OIDC_ISSUER"),
		OIDCClientID:      os.Getenv("AUTHENTIK_OIDC_CLIENT_ID"),
		OIDCAdminGroup:    env("AUTHENTIK_ADMIN_GROUP", "media-admins"),
	}
	for key, dest := range map[string]*bool{"JELLYFIN_ENABLED": &c.JellyfinEnabled, "AUTHENTIK_ENABLED": &c.AuthentikEnabled} {
		value, err := strconv.ParseBool(env(key, "true"))
		if err != nil {
			return c, fmt.Errorf("%s must be true or false", key)
		}
		*dest = value
	}
	if !c.JellyfinEnabled && !c.AuthentikEnabled {
		return c, fmt.Errorf("enable at least one account provisioning service")
	}
	secrets := map[string]*string{
		"ADMIN_TOKEN":                  &c.AdminToken,
		"AUTHENTIK_OIDC_CLIENT_SECRET": &c.OIDCClientSecret,
	}
	urls := map[string]string{"BASE_URL": c.BaseURL, "AUTHENTIK_OIDC_ISSUER": c.OIDCIssuer}
	if c.JellyfinEnabled {
		secrets["JELLYFIN_API_KEY"] = &c.JellyfinKey
		urls["JELLYFIN_URL"] = c.JellyfinURL
		if c.JellyfinPublicURL != "" {
			urls["JELLYFIN_PUBLIC_URL"] = c.JellyfinPublicURL
		}
		if err := json.Unmarshal([]byte(env("JELLYFIN_ALLOWED_LIBRARY_IDS", "null")), &c.JellyfinLibraryIDs); err != nil {
			return c, fmt.Errorf("JELLYFIN_ALLOWED_LIBRARY_IDS must be a JSON array of library IDs or null")
		}
		for _, id := range c.JellyfinLibraryIDs {
			if strings.TrimSpace(id) == "" {
				return c, fmt.Errorf("JELLYFIN_ALLOWED_LIBRARY_IDS cannot contain empty IDs")
			}
		}
		liveTV, err := strconv.ParseBool(env("JELLYFIN_ALLOW_LIVE_TV", "false"))
		if err != nil {
			return c, fmt.Errorf("JELLYFIN_ALLOW_LIVE_TV must be true or false")
		}
		c.JellyfinLiveTV = liveTV
	}
	if c.AuthentikEnabled {
		secrets["AUTHENTIK_TOKEN"] = &c.AuthentikToken
		urls["AUTHENTIK_URL"] = c.AuthentikURL
	}
	for key, dest := range secrets {
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
	for key, value := range urls {
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

func (c config) services() []string {
	services := []string{}
	if c.AuthentikEnabled {
		services = append(services, "authentik")
	}
	if c.JellyfinEnabled {
		services = append(services, "jellyfin")
	}
	return services
}
