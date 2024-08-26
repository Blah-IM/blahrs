with import <nixpkgs> { };
mkShell {
  nativeBuildInputs = [ pkg-config sqlite-interactive ];
  buildInputs = [ openssl.dev sqlite.dev ];

  env.RUST_LOG = "debug";
}
