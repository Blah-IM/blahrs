{ self }:
{
  lib,
  config,
  pkgs,
  ...
}:
let
  inherit (lib)
    literalMD
    mdDoc
    mkEnableOption
    mkIf
    mkOption
    types
    ;

  cfg = config.services.blahd;

  toml = pkgs.formats.toml { };
  mkConfigFile =
    name: config:
    (toml.generate name config).overrideAttrs (old: {
      buildCommand =
        old.buildCommand
        + ''
          ${lib.getBin cfg.package}/bin/blahd validate --config $out
        '';
    });

  settingsType = types.submodule {
    freeformType = toml.type;

    # TODO: Auto-generate these options?
    options = { };
  };

in
{
  options.services.blahd = {
    enable = mkEnableOption "Blah Chat Server";

    package = mkOption {
      description = mdDoc "The blahd package to use.";
      type = types.package;
      default = self.packages.${pkgs.system}.blahd;
      defaultText = literalMD "blahd package from its flake output";
    };

    listen = mkOption {
      description = mdDoc ''
        The address:port or an absolute UNIX socket path to listen on.

        If not null, it sets {option}`services.blahd.settings.listen.systemd`
        to `true`, and systemd socket activation is configured.
      '';
      type = types.nullOr types.str;
      default = "/run/blahd/blahd.sock";
    };

    settings = mkOption {
      description = ''
        blahd configuration.
        Will be ignored if `settingsFile` is non-null.
      '';
      type = settingsType;
    };

    settingsFile = mkOption {
      description = ''
        blahd configuration file path.
        If non-null, this will be used and `settings` will be ignored.
      '';
      type = types.nullOr types.path;
      defaultText = literalMD "generated from `settings`";
      default = mkConfigFile "blahd.toml" cfg.settings;
    };
  };

  config = mkIf cfg.enable {
    systemd.packages = [ cfg.package ];
    environment.systemPackages = [ cfg.package ];

    systemd.sockets."blahd" = lib.mkIf (cfg.listen != null) {
      wantedBy = [ "sockets.target" ];
      listenStreams = [ cfg.listen ];
    };

    systemd.services."blahd" = lib.mkDefault {
      overrideStrategy = "asDropin";

      restartIfChanged = true; # We support graceful shutdown.
      stopIfChanged = false;
    };

    environment.etc."blahd/blahd.toml".source = cfg.settingsFile;

    services.blahd.settings = lib.mkIf (cfg.listen != null) {
      listen.systemd = true;
    };
  };
}
