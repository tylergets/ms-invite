{
  description = "A tiny invite service for Jellyfin and Authentik";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = self.packages.${system}.ms-invite;
          ms-invite = pkgs.buildGoModule {
            pname = "ms-invite";
            version = "0.1.0";
            src = nixpkgs.lib.cleanSourceWith {
              src = ./.;
              filter =
                path: type:
                let
                  relative = nixpkgs.lib.removePrefix "${toString ./.}/" (toString path);
                in
                relative == "web"
                || nixpkgs.lib.hasPrefix "web/" relative
                || builtins.match "[^/]+\\.go" relative != null
                || builtins.elem relative [
                  "go.mod"
                  "go.sum"
                ];
            };
            vendorHash = "sha256-2m/dfVcwPqb+Hi2lSTHKqpoooYSROfEciGDoTle/MLs=";
            env.CGO_ENABLED = 0;
            ldflags = [
              "-s"
              "-w"
            ];
            meta = {
              description = "Single-use and reusable invitations for Jellyfin and Authentik";
              mainProgram = "ms-invite";
              platforms = systems;
            };
          };
        }
      );

      nixosModules.default = self.nixosModules.ms-invite;
      nixosModules.ms-invite = { pkgs, lib, ... }: {
        imports = [ ./nix/module.nix ];
        services.ms-invite.package =
          lib.mkDefault
            self.packages.${pkgs.stdenv.hostPlatform.system}.ms-invite;
      };

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.go
              pkgs.gopls
              pkgs.nixfmt
            ];
          };
        }
      );

      checks = forAllSystems (system: {
        package = self.packages.${system}.ms-invite;
        module =
          (nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [
              self.nixosModules.default
              ({ ... }: {
                boot.isContainer = true;
                system.stateVersion = "26.05";
                services.ms-invite = {
                  enable = true;
                  publicUrl = "https://invite.example.com";
                  adminTokenFile = "/run/secrets/invite-admin";
                  jellyfin = {
                    url = "http://127.0.0.1:8096";
                    apiKeyFile = "/run/secrets/jellyfin-key";
                  };
                  authentik = {
                    url = "https://auth.example.com";
                    tokenFile = "/run/secrets/authentik-token";
                    oidc = {
                      issuer = "https://auth.example.com/application/o/ms-invite/";
                      clientId = "ms-invite";
                      clientSecretFile = "/run/secrets/oidc-client-secret";
                    };
                  };
                  nginx = {
                    enable = true;
                    hostName = "invite.example.com";
                  };
                };
                security.acme = {
                  acceptTerms = true;
                  defaults.email = "admin@example.com";
                };
              })
            ];
          }).config.system.build.toplevel;
      });
    };
}
