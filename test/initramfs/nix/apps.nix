{ lib, stdenv, hostPlatform, glibc, libnl, callPackage, testPlatform
, memCompareWorksetBytes ? "536870912", memCompareRuns ? "5"
, memCompareSeed ? "12345", memCompareDoStore ? "0", memPageRandRuns ? "5"
, memPageRandSeed ? "12345", memPageRandDoStore ? "0" }: rec {

  intelTdxEnabled = hostPlatform.system == "x86_64-linux"
    && builtins.getEnv "INTEL_TDX" == "1";

  tdxAttest = callPackage ./apps/tdx-attest.nix { };

  package = stdenv.mkDerivation ({
    pname = "apps";
    version = "0.1.0";
    src = lib.fileset.toSource {
      root = ./../src;
      fileset = ./../src/apps;
    };

    INTEL_TDX = builtins.getEnv "INTEL_TDX";

    HOST_PLATFORM = "${hostPlatform.system}";
    CC = "${stdenv.cc.targetPrefix}cc";
    C_FLAGS = "-I${libnl.dev}/include/libnl3"
      + (if testPlatform == "asterinas" then " -D__asterinas__" else "");
    # FIXME: Excluding `glibc` allows the build to succeed, but causes some tests to fail.
    buildInputs = [ glibc glibc.static libnl ];
    buildCommand = ''
      BUILD_DIR=$(mktemp -d)
      mkdir -p $BUILD_DIR
      cp -r $src/apps $BUILD_DIR/

      pushd $BUILD_DIR
      make --no-print-directory -C apps \
        MEM_COMPARE_WORKSET_BYTES=${memCompareWorksetBytes} \
        MEM_COMPARE_RUNS=${memCompareRuns} \
        MEM_COMPARE_SEED=${memCompareSeed} \
        MEM_COMPARE_DO_STORE=${memCompareDoStore} \
        MEM_PAGE_RAND_RUNS=${memPageRandRuns} \
        MEM_PAGE_RAND_SEED=${memPageRandSeed} \
        MEM_PAGE_RAND_DO_STORE=${memPageRandDoStore}
      popd

      mkdir -p $out
      mv build/initramfs/test/* $out/
    '';
  } // lib.optionalAttrs intelTdxEnabled {
    TDX_ATTEST_DIR = "${tdxAttest}/QuoteGeneration";
  });
}
