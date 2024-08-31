rec {
  description = "Blah Chat Server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      naersk,
    }:
    let
      inherit (nixpkgs) lib;
      eachSystem = lib.genAttrs lib.systems.flakeExposed;

      rev = self.rev or (lib.warn "Git changes are not committed" (self.dirtyRev or "dirty"));
    in
    {
      packages = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          naersk' = pkgs.callPackage naersk { };
        in
        rec {
          default = blahd;
          blahd = pkgs.callPackage (
            {
              pkg-config,
              openssl,
              sqlite,
            }:
            naersk'.buildPackage rec {
              pname = "blahd";
              src = ./.;
              version = "git-${rev}";
              CFG_RELEASE = version;

              nativeBuildInputs = [
                pkg-config
              ];
              buildInputs = [
                openssl
                sqlite
              ];

              cargoBuildOptions = opts: opts ++ [
                "--package=blahd"
                "--package=blahctl"
              ];

              postInstall = ''
                mkdir -p $out/etc/systemd/system
                substitute ./blahd/blahd.example.service $out/etc/systemd/system/blahd.service \
                  --replace-fail '/usr/bin/blahd' "$out/bin/blahd"
              '';

              meta = {
                inherit description;
                homepage = "https://github.com/Blah-IM/blahrs";
              };
            }
          ) { };
        }
      );

      nixosModules = rec {
        default = blahd;
        blahd = import ./nix/module.nix {
          inherit self;
        };
      };
    };
}