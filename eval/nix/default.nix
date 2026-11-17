{
  system ? builtins.currentSystem,
}:
let
  pkgs = import ../../distro/nixpkgs.nix {
    config = { };
    overlays = [ ];
    inherit system;
    crossSystem.config = "x86_64-unknown-linux-gnu";
  };
  sources = builtins.fromJSON (builtins.readFile ../configs/payload-sources.json);
  lmbench = (pkgs.callPackage ../../test/initramfs/nix/benchmark/lmbench.nix { }).overrideAttrs (old: {
    patches = (old.patches or [ ]) ++ [ ../patches/lmbench-timing-rusage.patch ];
    preBuild = ''
      makeFlagsArray+=(CPPFLAGS="-std=gnu89 -DRUSAGE -I${pkgs.libtirpc.dev}/include/tirpc -Wno-error=format-security")
    '';
  });
  will-it-scale = pkgs.callPackage ./will-it-scale.nix { inherit sources; };
  busybox = pkgs.pkgsStatic.busybox;
  stress-ng = pkgs.stress-ng;
  guest-runner = pkgs.stdenv.mkDerivation {
    pname = "eval-guest-bins";
    version = "0.1.0";
    src = ../guest;
    dontConfigure = true;
    buildPhase = ''
      runHook preBuild
      CC=${pkgs.stdenv.cc.targetPrefix}cc
      $CC -O2 -Wall -Wextra -Werror -pthread -o eval_guest_runner eval_guest_runner.c
      $CC -O2 -Wall -Wextra -Werror -o vdso_selfcheck vdso_selfcheck.c
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      mkdir -p $out/bin
      cp eval_guest_runner vdso_selfcheck $out/bin/
      runHook postInstall
    '';
  };
  all_pkgs = [
    busybox
    lmbench
    will-it-scale
    stress-ng
    guest-runner
  ];
in
pkgs.stdenvNoCC.mkDerivation {
  name = "eval-payload.cpio";
  nativeBuildInputs = [ pkgs.pkgsBuildBuild.cpio ];
  buildCommand = ''
    work=$(mktemp -d)
    mkdir -p "$work"/{bin,dev,etc,proc,sys,tmp,nix/store}
    mkdir -p "$work"/benchmark/bin/{lmbench,will-it-scale}
    chmod 1777 "$work/tmp"

    cp -r ${busybox}/bin/* "$work/bin/"
    cp -r ${lmbench}/bin/* "$work/benchmark/bin/lmbench/"
    cp -r ${will-it-scale}/bin/* "$work/benchmark/bin/will-it-scale/"
    cp ${stress-ng}/bin/stress-ng "$work/benchmark/bin/stress-ng"

    cp ${guest-runner}/bin/eval_guest_runner "$work/bin/eval_guest_runner"
    cp ${guest-runner}/bin/vdso_selfcheck "$work/bin/vdso_selfcheck"
    ln -sf /bin/eval_guest_runner "$work/init"

    pkg_path=${pkgs.lib.strings.concatStringsSep ":" all_pkgs}
    while IFS= read -r dep_path; do
      if [[ "$pkg_path" == *"$dep_path"* ]]; then
        continue
      fi
      cp -r "$dep_path" "$work/nix/store/"
    done < ${pkgs.writeClosure all_pkgs}

    (cd "$work" && find . -print0 | LC_ALL=C sort -z | cpio -o -H newc --null > "$out")
  '';
}
