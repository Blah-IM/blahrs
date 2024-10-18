rec {
  description = "Blah Chat Server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      naersk,
      rust-overlay,
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
          rustBin = rust-overlay.lib.mkRustBin { } pkgs;
          toolchain = rustBin.fromRustupToolchainFile ./rust-toolchain.toml;
          naersk' = pkgs.callPackage naersk {
            cargo = toolchain;
            rustc = toolchain;
          };

          mkPkg =
            {
              pkg-config,
              openssl,
              sqlite,
            }:
            naersk'.buildPackage {
              pname = "blahd";
              src = ./.;
              version = "0-unstable";

              nativeBuildInputs = [
                pkg-config
              ];
              buildInputs = [
                openssl
                sqlite
              ];

              cargoBuildOptions =
                opts:
                opts
                ++ [
                  "--package=blahd"
                  "--package=blahctl"
                ];

              # Intentionally omit the socket unit. It is trivial but
              # highly configuration-specific. Users who want to use it almost
              # always need customization.
              postInstall = ''
                mkdir -p $out/etc/systemd/system
                substitute ./contrib/blahd.example.service $out/etc/systemd/system/blahd.service \
                  --replace-fail '/usr/bin/blahd' "$out/bin/blahd"
              '';

              meta = {
                inherit description;
                homepage = "https://github.com/Blah-IM/blahrs";
              };
            };
        in
        rec {
          default = blahd;
          blahd = (pkgs.callPackage mkPkg { }).overrideAttrs {
            # Only set this for the main derivation, not for deps.
            CFG_RELEASE = "git-${rev}";
            CFG_SRC_URL = "https://github.com/Blah-IM/blahrs/archive/${rev}.tar.gz";
          };
        }
      );

      devShells = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.default ];
            nativeBuildInputs = [
              pkgs.buildPackages.sqlite-interactive
              pkgs.cargo-llvm-cov
            ];

            env.RUST_LOG = "blahd=debug,blahctl=debug";
          };

          without-rust = self.devShells.${system}.default.overrideAttrs (old: {
            nativeBuildInputs = lib.filter (drv: drv.pname != "rust-default") old.nativeBuildInputs;
          });
        }
      );

      nixosModules = rec {
        default = blahd;
        blahd = import ./contrib/module.nix {
          inherit self;
        };
      };
    };
}
