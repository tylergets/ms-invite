# ms-invite

A tiny service for inviting people to a media server. Create a single-use link;
the recipient chooses a username, email, and password, and gets an account in
**Jellyfin and Authentik**.

- Admin login through **Authentik OIDC**, restricted to an admin group.
- Expiring invitations, labels, status tracking, and revocation.
- Server-rendered pages; no JavaScript or frontend build.
- One Go binary, embedded assets, and a small persistent JSON ledger.
- Nix flake, NixOS module, systemd credentials, and optional nginx/ACME TLS.

Both accounts initially receive the same password. This service provisions local
accounts; it does not configure Jellyfin SSO or synchronize later password changes.

## Authentik setup

### Admin login

Create an **OAuth2/OpenID Connect provider** and an application with slug
`ms-invite`:

1. Choose a **confidential** client and the authorization-code grant.
2. Set a **strict** redirect URI: `https://invite.example.com/auth/callback`.
   For local development, also allow `http://localhost:8080/auth/callback`.
3. Select an **RSA signing key** (RS256), and leave token encryption disabled.
4. Use the default **per-provider issuer**:
   `https://auth.example.com/application/o/ms-invite/` (including the trailing slash).
5. Include the standard `openid`, `profile`, and `email` scope mappings. Enable
   **Include claims in ID token**; the `profile` mapping must supply a `groups`
   array containing group names.
6. Create a `media-admins` group and add your administrator account. Set
   `authentik.oidc.adminGroup` if you use a different name. You can also restrict
   the Authentik application itself to this group.

The service verifies the ID token's signature, issuer, audience, expiry, nonce,
and admin group. Login uses state and PKCE. Admin sessions expire after at most
one hour, or at the ID token's expiry if sooner. Group changes take effect on the
next login/session expiry. “Sign out” clears this application's session; it does
not sign you out of Authentik. Rotating `ADMIN_TOKEN` invalidates all local sessions.

### User provisioning

Create a dedicated service account and API token. Give it permissions to:

- List/view and add users (`authentik_core.view_user`, `authentik_core.add_user`).
- Change users (`authentik_core.change_user`).
- Set passwords (`authentik_core.reset_user_password`).
- View the groups you assign (`authentik_core.view_group`).

Configure `authentik.groups` with the **UUIDs** of ordinary media-user groups.
The admin-login group setting is a **name**, whereas signup groups are **UUIDs**.
Do not assign the admin-login group, superuser groups, or groups inheriting those
permissions to invitees. Application access remains controlled by your existing
Authentik policies and group bindings.

The email address is recorded in Authentik; this service does not verify ownership
or send invitation emails. Share invite links yourself.

## Jellyfin setup

Create an API key in **Dashboard → API Keys**. New users are non-administrators,
hidden from the public login screen, and allowed remote playback of all libraries.
Content deletion and downloading are disabled. Other Jellyfin default policy
settings are preserved. You can adjust an individual user's library access in
Jellyfin after signup.

## Deploy on NixOS

Add this project as an input to your existing system flake:

```nix
inputs.ms-invite.url = "github:tylergets/ms-invite";
inputs.ms-invite.inputs.nixpkgs.follows = "nixpkgs";
```

Import `ms-invite.nixosModules.default` into your host's modules and configure:

```nix
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
    groups = [ "your-media-users-group-uuid" ];
    oidc = {
      issuer = "https://auth.example.com/application/o/ms-invite/";
      clientId = "your-client-id";
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
```

The host must already run Jellyfin and have network access to Authentik. Point DNS
at the host; the nginx option opens ports 80/443 and obtains a certificate.
The application listens on `127.0.0.1:8080` by default. With your own proxy, leave
`nginx.enable` disabled, forward the original host, and allow a 120-second upstream
timeout. `publicUrl` must exactly match the browser origin and have no path.

Provision the four secret files with your preferred secret manager, or place
root-readable files at persistent runtime paths such as `/var/lib/secrets/`:

| Secret | Contents |
| --- | --- |
| `adminTokenFile` | Random API/session key, at least 32 characters (`openssl rand -hex 32`) |
| `jellyfin.apiKeyFile` | Jellyfin API key |
| `authentik.tokenFile` | Authentik provisioning API token |
| `authentik.oidc.clientSecretFile` | Authentik OAuth2 client secret |

Use quoted **string paths**, not Nix path literals or inline secrets. systemd
loads them via `LoadCredential`; secrets do not enter the Nix store. Restart the
service after rotating secret contents. The module uses a dynamic user, a hardened
systemd service, and `/var/lib/ms-invite` for state.

An example deployment flake is in [`examples/nixos/`](examples/nixos/). Merge its
configuration with your host's existing hardware and system configuration, replace
the example domains/group UUID, and rebuild:

```sh
sudo nixos-rebuild switch --flake /path/to/your/system-flake#media
systemctl status ms-invite
journalctl -u ms-invite
```

Visit **`https://invite.example.com/admin`**, sign in through Authentik, and create
an invitation. The complete invite URL is shown **once**; only its SHA-256 digest
is persisted. If you lose the link, revoke the invite and create another.

## Run locally

Requires Go 1.26+ on Linux, or Nix:

```sh
nix develop
cp .env.example .env
# Edit .env and create the referenced secret files.
set -a
. ./.env
set +a
CGO_ENABLED=0 go run .
```

Then open `http://localhost:8080/admin`. Configure that exact callback origin in
Authentik. HTTP is intended for local development; use HTTPS for deployment.

Alternatively, `nix build` produces `result/bin/ms-invite`. Environment variables
are listed in [`.env.example`](.env.example). Each secret also supports its direct
environment-variable form without `_FILE`; a configured file takes precedence.
`AUTHENTIK_GROUPS` is comma-separated and optional. `DATA_DIR` defaults to `./data`.

## Automation API

The browser uses Authentik sessions. The JSON API uses `ADMIN_TOKEN` as a bearer
credential:

```sh
curl --fail-with-body https://invite.example.com/api/invites \
  -H "Authorization: Bearer $(cat /path/to/admin-token)" \
  -H 'Content-Type: application/json' \
  -d '{"label":"Alex","expires_in_hours":168}'
```

Returns HTTP 201 with `{"invite": {...}, "url": "https://.../invite/..."}`.
Expiry defaults to seven days; accepted values are 1–8760 hours.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/invites` | List invite IDs, statuses, and provisioning details |
| `POST` | `/api/invites` | Create an invite; return its link once |
| `POST` | `/api/invites/{id}/revoke` | Prevent further use of an invite |
| `GET` | `/healthz` | Process liveness; does not probe upstream services |

Browser mutations require a matching `Origin`; bearer API requests can omit it.

## Failures and persistence

Account creation spans two independent services, so there is no shared database
transaction. The service records each step before continuing:

- Authentik users start inactive. Jellyfin users start with an unknown random
  bootstrap password. Both are configured before signup finishes.
- If a later operation fails, the recipient can retry the **same invite, username,
  and email** before expiry. Known account IDs are reused; both passwords are set
  again. Passwords are never stored by this service.
- If an account-creation response is lost, or the process stops during creation,
  the invite shows **needs attention**. It will not guess ownership of an existing
  username or automatically repeat an uncertain create operation.
- For an invite needing attention, review the recorded IDs and upstream accounts.
  Authentik users carry an `ms_invite_id` attribute. Remove only confirmed partial
  accounts, revoke the invite, then issue a replacement. The same cleanup applies
  to abandoned or expired partial signups.
- Revocation prevents further signup; it does not disable or delete provisioned
  accounts. A failure during final activation may leave one account active. Check
  both services when cleaning up a partial signup.

This is designed for a small, single-instance service. A filesystem lock prevents
two instances from sharing the same ledger; signup operations are serialized. A
second simultaneous signup receives a retry response. Updates use atomic rename
and filesystem synchronization. Back up `/var/lib/ms-invite/invites.json` along
with the upstream services. The ledger contains usernames and email addresses.

Invite links are bearer credentials. The supplied nginx virtual host disables
access logging; apply equivalent URL redaction/access controls to any other proxy
logs. The app does not log request URLs, passwords, tokens, or upstream bodies.

## Checks

```sh
nix develop -c go test -race ./...
nix develop -c go vet ./...
nix build
nix flake check --no-build
```

Tests use mock Jellyfin/Authentik HTTP servers and a signed mock OIDC provider.
They cover single-use/expired/revoked invites, persistent partial-signup recovery,
ambiguous creates, existing-account protection, admin authorization, CSRF, PKCE,
OIDC claim/signature checks, and session tampering.
