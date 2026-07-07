{ stdenvNoCC, pkgsStatic }:
let
  framevmctlSrc = builtins.path {
    name = "framevmctl-src";
    path = ./../src;
  };
in stdenvNoCC.mkDerivation {
  name = "framevmctl";
  nativeBuildInputs = [ pkgsStatic.stdenv.cc ];
  buildCommand = ''
    mkdir -p $out/bin
    $CC -O2 -Wall -Werror -static \
      ${framevmctlSrc}/framevmctl/framevmctl.c \
      -o $out/bin/framevmctl
  '';
}
