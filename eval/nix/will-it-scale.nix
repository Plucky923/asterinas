{
  stdenv,
  fetchurl,
  hwloc,
  sources ? builtins.fromJSON (builtins.readFile ../configs/payload-sources.json),
}:
let
  spec = sources."will-it-scale";
in
stdenv.mkDerivation rec {
  pname = "will-it-scale";
  version = builtins.substring 0 8 spec.version;

  src = fetchurl {
    url = spec.url;
    sha256 = spec.sha256;
  };

  buildInputs = [ hwloc ];
  dontConfigure = true;

  buildPhase = ''
    runHook preBuild
    mkdir -p bin
    CC=${stdenv.cc.targetPrefix}cc
    TESTS="getppid1 open1 dup1 pipe1 page_fault1 page_fault2 page_fault3 mmap1 mmap2 brk1 malloc1"
    for t in $TESTS; do
      $CC -O2 -Wall -pthread -I. tests/$t.c main.c -lhwloc -o bin/${t}_processes
    done
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin
    cp bin/*_processes $out/bin/
    runHook postInstall
  '';
}
