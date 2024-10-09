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

    systemd.services."blahd" = {
      overrideStrategy = "asDropin";

      wantedBy = [ "multi-user.target" ];
      restartIfChanged = false;
      stopIfChanged = false;
    };

    environment.etc."blahd/blahd.toml".source = cfg.settingsFile;
  };
}
