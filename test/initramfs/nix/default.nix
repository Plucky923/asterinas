{ target ? "x86_64", enableBenchmarkTest ? false, enableConformanceTest ? false
, enableRegressionTest ? false, conformanceTestSuite ? "ltp"
, conformanceTestWorkDir ? "/tmp", regressionTestPlatform ? "asterinas"
, dnsServer ? "none", smp ? 1, initramfsCompressed ? true
, framevmObjPath ? ""
, framevmInstallPath ? "/framevm/framevm.o" }:
let
  crossSystem.config = if target == "x86_64" then
    "x86_64-unknown-linux-gnu"
  else if target == "riscv64" then
    "riscv64-unknown-linux-gnu"
  else
    throw "Target arch ${target} not yet supported.";

  # Pinned nixpkgs. The corresponding cache has been built into the Docker
  # image. So Nix does not need to build the packages from scratch.
  nixpkgs = fetchTarball {
    url =
      "https://github.com/NixOS/nixpkgs/archive/c0bebd16e69e631ac6e52d6eb439daba28ac50cd.tar.gz";
    sha256 = "1fbhkqm8cnsxszw4d4g0402vwsi75yazxkpfx3rdvln4n6s68saf";
  };
  pkgs = import nixpkgs {
    config = { };
    overlays = [ ];
    inherit crossSystem;
  };
in rec {
  # Packages needed by initramfs
  busybox = pkgs.busybox;
  framevm-rootfs-image = pkgs.callPackage ./framevm-rootfs-image.nix {
    busybox = pkgs.pkgsStatic.busybox;
  };
  benchmark = pkgs.callPackage ./benchmark { };
  conformance = pkgs.callPackage ./conformance {
    inherit smp;
    testSuite = conformanceTestSuite;
    workDir = conformanceTestWorkDir;
  };
  regression =
    pkgs.callPackage ./regression { testPlatform = regressionTestPlatform; };

  initramfs = pkgs.callPackage ./initramfs.nix {
    inherit busybox;
    benchmark = if enableBenchmarkTest then benchmark else null;
    conformance = if enableConformanceTest then conformance else null;
    regression = if enableRegressionTest then regression else null;
    dnsServer = dnsServer;
    framevmObjPath = framevmObjPath;
    framevmInstallPath = framevmInstallPath;
    framevmRootfs = framevm-rootfs-image;
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
