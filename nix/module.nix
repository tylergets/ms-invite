{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.services.ms-invite;
in
{
  options.services.ms-invite = {
    enable = mkEnableOption "the Jellyfin and Authentik invite service";

    package = mkOption {
      type = types.package;
      description = "The ms-invite package. Set automatically by the flake module.";
    };

    publicUrl = mkOption {
      type = types.str;
      example = "https://invite.example.com";
      description = "Public origin, without a path or trailing slash. Used for links and CSRF protection.";
    };

    listenAddress = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "Listen address; IPv6 addresses must be enclosed in brackets.";
    };

    port = mkOption {
      type = types.port;
      default = 8080;
      description = "HTTP listen port.";
    };

    adminTokenFile = mkOption {
      type = types.str;
      example = "/run/secrets/ms-invite-admin-token";
      description = "Absolute runtime path to the API token and session signing key (at least 32 characters). Loaded with systemd credentials.";
    };

    jellyfin = {
      url = mkOption {
        type = types.str;
        example = "http://127.0.0.1:8096";
        description = "Jellyfin API base URL, including any configured base path.";
      };
      apiKeyFile = mkOption {
        type = types.str;
        description = "Absolute runtime path to the Jellyfin API key.";
      };
    };

    authentik = {
      url = mkOption {
        type = types.str;
        example = "https://auth.example.com";
        description = "Authentik base URL, without /api/v3.";
      };
      tokenFile = mkOption {
        type = types.str;
        description = "Absolute runtime path to an Authentik API token.";
      };
      groups = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Authentik group UUIDs assigned to new users.";
      };
      userPath = mkOption {
        type = types.str;
        default = "users/media";
        description = "Authentik path for provisioned users.";
      };
      oidc = {
        issuer = mkOption {
          type = types.str;
          example = "https://auth.example.com/application/o/ms-invite/";
          description = "OIDC issuer for the admin application, including the trailing slash.";
        };
        clientId = mkOption {
          type = types.str;
          description = "Authentik OAuth2 confidential client ID.";
        };
        clientSecretFile = mkOption {
          type = types.str;
          description = "Absolute runtime path to the OIDC client secret.";
        };
        adminGroup = mkOption {
          type = types.str;
          default = "media-admins";
          description = "Group NAME required in the verified ID token to administer invites. Never assign this group to invitees.";
        };
      };
    };

    nginx = {
      enable = mkEnableOption "an nginx reverse proxy with ACME TLS";
      hostName = mkOption {
        type = types.str;
        default = "";
        example = "invite.example.com";
        description = "Public hostname; must match publicUrl. Configure security.acme separately.";
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.all (file: lib.hasPrefix "/" file && !(lib.hasPrefix "/nix/store/" file)) [
          cfg.adminTokenFile
          cfg.jellyfin.apiKeyFile
          cfg.authentik.tokenFile
          cfg.authentik.oidc.clientSecretFile
        ];
        message = "ms-invite secrets must use absolute runtime paths outside the Nix store.";
      }
      {
        assertion =
          !cfg.nginx.enable || (cfg.nginx.hostName != "" && cfg.publicUrl == "https://${cfg.nginx.hostName}");
        message = "ms-invite nginx.hostName must be set and publicUrl must be https:// followed by that hostname.";
      }
      {
        assertion =
          !cfg.nginx.enable
          || lib.elem cfg.listenAddress [
            "127.0.0.1"
            "[::1]"
          ];
        message = "ms-invite's built-in nginx proxy requires a loopback listenAddress.";
      }
    ];

    systemd.services.ms-invite = {
      description = "Media server invitations";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      environment = {
        LISTEN_ADDR = "${cfg.listenAddress}:${toString cfg.port}";
        BASE_URL = cfg.publicUrl;
        DATA_DIR = "/var/lib/ms-invite";
        ADMIN_TOKEN_FILE = "%d/admin-token";
        JELLYFIN_URL = cfg.jellyfin.url;
        JELLYFIN_API_KEY_FILE = "%d/jellyfin-api-key";
        AUTHENTIK_URL = cfg.authentik.url;
        AUTHENTIK_TOKEN_FILE = "%d/authentik-token";
        AUTHENTIK_GROUPS = lib.concatStringsSep "," cfg.authentik.groups;
        AUTHENTIK_USER_PATH = cfg.authentik.userPath;
        AUTHENTIK_OIDC_ISSUER = cfg.authentik.oidc.issuer;
        AUTHENTIK_OIDC_CLIENT_ID = cfg.authentik.oidc.clientId;
        AUTHENTIK_OIDC_CLIENT_SECRET_FILE = "%d/oidc-client-secret";
        AUTHENTIK_ADMIN_GROUP = cfg.authentik.oidc.adminGroup;
      };
      serviceConfig = {
        ExecStart = lib.getExe cfg.package;
        DynamicUser = true;
        StateDirectory = "ms-invite";
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/ms-invite";
        UMask = "0077";
        LoadCredential = [
          "admin-token:${cfg.adminTokenFile}"
          "jellyfin-api-key:${cfg.jellyfin.apiKeyFile}"
          "authentik-token:${cfg.authentik.tokenFile}"
          "oidc-client-secret:${cfg.authentik.oidc.clientSecretFile}"
        ];
        Restart = "on-failure";
        RestartSec = 5;
        TimeoutStopSec = 110;
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectProc = "invisible";
        RestrictSUIDSGID = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        CapabilityBoundingSet = "";
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        SystemCallArchitectures = "native";
      };
    };

    services.nginx = mkIf cfg.nginx.enable {
      enable = true;
      recommendedProxySettings = true;
      recommendedTlsSettings = true;
      virtualHosts.${cfg.nginx.hostName} = {
        enableACME = true;
        forceSSL = true;
        # Invite URLs are bearer credentials; avoid writing them to access logs.
        extraConfig = "access_log off;";
        locations."/" = {
          proxyPass = "http://${cfg.listenAddress}:${toString cfg.port}";
          extraConfig = ''
            proxy_read_timeout 120s;
            client_max_body_size 8k;
          '';
        };
      };
    };

    networking.firewall.allowedTCPPorts = mkIf cfg.nginx.enable [
      80
      443
    ];
  };
}
