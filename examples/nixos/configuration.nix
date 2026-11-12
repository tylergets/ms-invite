{ ... }:
{
  services.ms-invite = {
    enable = true;
    publicUrl = "https://invite.example.com";
    adminTokenFile = "/run/secrets/ms-invite-admin-token";

    jellyfin = {
      url = "http://127.0.0.1:8096";
      apiKeyFile = "/run/secrets/jellyfin-api-key";
    };

    authentik = {
      url = "https://auth.example.com";
      tokenFile = "/run/secrets/authentik-api-token";
      # UUIDs, not group names. Use a non-administrator media-users group.
      groups = [ "00000000-0000-0000-0000-000000000000" ];
      userPath = "users/media";
      oidc = {
        issuer = "https://auth.example.com/application/o/ms-invite/";
        clientId = "replace-with-authentik-client-id";
        clientSecretFile = "/run/secrets/ms-invite-oidc-secret";
        adminGroup = "media-admins";
      };
    };

    nginx = {
      enable = true;
      hostName = "invite.example.com";
    };
  };

  security.acme = {
    acceptTerms = true;
    defaults.email = "you@example.com";
  };
}
