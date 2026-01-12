{ target ? "x86_64", enableBenchmarkTest ? false, enableConformanceTest ? false
, enableRegressionTest ? false, conformanceTestSuite ? "ltp"
, conformanceTestWorkDir ? "/tmp", regressionTestPlatform ? "asterinas"
, dnsServer ? "none", smp ? 1, initramfsCompressed ? true
, enableNestedQemu ? false
, framevmObjPath ? ""
, framevmInstallPath ? "/framevm/framevm.o"
, memCompareWorksetBytes ? "536870912", memCompareRuns ? "5"
, memCompareSeed ? "12345", memCompareDoStore ? "0", memPageRandRuns ? "5"
, memPageRandSeed ? "12345", memPageRandDoStore ? "0" }:
let
  crossSystem.config = if target == "x86_64" then
    "x86_64-unknown-linux-gnu"
  else if target == "riscv64" then
    "riscv64-unknown-linux-gnu"
  else
    throw "Target arch ${target} not yet supported.";

  # Prefer the preinstalled nixpkgs channel inside the dev container to avoid
  # unnecessary network fetches during normal builds. Fall back to the pinned
  # tarball when no local channel is available.
  nixpkgsPath = if builtins.pathExists
  /nix/var/nix/profiles/per-user/root/channels/nixpkgs then
    /nix/var/nix/profiles/per-user/root/channels/nixpkgs
  else if builtins.getEnv "NIX_PATH" != "" then
    <nixpkgs>
  else
    fetchTarball {
      url =
        "https://github.com/NixOS/nixpkgs/archive/c0bebd16e69e631ac6e52d6eb439daba28ac50cd.tar.gz";
      sha256 = "1fbhkqm8cnsxszw4d4g0402vwsi75yazxkpfx3rdvln4n6s68saf";
    };
  pkgs = import nixpkgsPath {
    config = { };
    overlays = [ ];
    inherit crossSystem;
  };
in rec {
  # Packages needed by initramfs
  busybox = pkgs.busybox;
  benchmark = pkgs.callPackage ./benchmark { };
  conformance = pkgs.callPackage ./conformance {
    inherit smp;
    testSuite = conformanceTestSuite;
    workDir = conformanceTestWorkDir;
  };
  regression =
    pkgs.callPackage ./regression { testPlatform = regressionTestPlatform; };
  nestedQemu =
    if enableNestedQemu && target == "x86_64" then pkgs.qemu else null;

  initramfs = pkgs.callPackage ./initramfs.nix {
    inherit busybox;
    benchmark = if enableBenchmarkTest then benchmark else null;
    conformance = if enableConformanceTest then conformance else null;
    regression = if enableRegressionTest then regression else null;
    nestedQemu = nestedQemu;
    dnsServer = dnsServer;
    framevmObjPath = framevmObjPath;
    framevmInstallPath = framevmInstallPath;
  };
  initramfs-image = pkgs.callPackage ./initramfs-image.nix {
    inherit initramfs;
    compressed = initramfsCompressed;
  };

  # Packages needed by host
  apacheHttpd = pkgs.apacheHttpd;
  iperf3 = pkgs.iperf3;
  libmemcached = pkgs.libmemcached.overrideAttrs (_: {
    configureFlags = [ "--enable-memaslap" ];
    LDFLAGS = "-lpthread";
    CPPFLAGS = "-fcommon -fpermissive";
  });
  lmbench = pkgs.callPackage ./benchmark/lmbench.nix { };
  redis = (pkgs.redis.overrideAttrs (_: { doCheck = false; })).override {
    withSystemd = false;
  };
}
