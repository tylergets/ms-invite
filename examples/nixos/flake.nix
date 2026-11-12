{
  description = "Example media-server NixOS deployment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    ms-invite.url = "github:tylergets/ms-invite";
    ms-invite.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, ms-invite, ... }: {
    nixosConfigurations.media = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        # Add your host's hardware-configuration.nix and existing configuration.
        ms-invite.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
