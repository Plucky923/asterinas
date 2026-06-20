{ lib, pkgs, stdenvNoCC, fetchFromGitHub, hostPlatform, writeClosure, busybox
, benchmark, conformance, regression, dnsServer
, framevmObjPath ? ""
, framevmInstallPath ? "/framevm/framevm.o"
, framevmRootfs ? null }:
let
  boot_hello = builtins.path { path = ./../src/boot_hello.sh; };
  framevm_start = builtins.path { path = ./../src/framevm_start.sh; };
  framevm_shell = builtins.path { path = ./../src/framevm_shell.sh; };
  framevm_foreground_smoke = builtins.path { path = ./../src/framevm_foreground_smoke.sh; };
  framevm_share_test = builtins.path { path = ./../src/framevm_share_test.sh; };
  framevm_busybox_smoke = builtins.path { path = ./../src/framevm_busybox_smoke.sh; };
  init = builtins.path { path = ./../src/init; };
  etc = lib.fileset.toSource {
    root = ./../etc;
    fileset = ./../etc;
  };
  gvisor_libs = if conformance != null && conformance.testSuite == "gvisor" then
    builtins.path {
      name = "gvisor-libs";
      path = "/lib/x86_64-linux-gnu";
    }
  else
    null;
  resolv_conf = pkgs.callPackage ./resolv_conf.nix { dnsServer = dnsServer; };
  # Whether the initramfs should include evtest, a common tool to debug input devices (`/dev/input/eventX`)
  is_evtest_included = false;
  framevmObj =
    if framevmObjPath == "" then null else builtins.path {
      name = "framevm-object";
      path = framevmObjPath;
    };
  all_pkgs = [ busybox etc resolv_conf ]
    ++ lib.optionals (benchmark != null) [ benchmark.package ]
    ++ lib.optionals (conformance != null) [ conformance.package ]
    ++ lib.optionals (regression != null) [ regression.package ]
    ++ lib.optionals is_evtest_included [ pkgs.evtest ];
in stdenvNoCC.mkDerivation {
  name = "initramfs";
  buildCommand = ''
    mkdir -p $out/{dev,etc,root,usr,opt,tmp,var,proc,sys}
    mkdir -p $out/{benchmark,test,ext2,exfat}
    mkdir -p $out/usr/{bin,sbin,lib,lib64,local}
    ln -sfn usr/bin $out/bin
    ln -sfn usr/sbin $out/sbin
    ln -sfn usr/lib $out/lib
    ln -sfn usr/lib64 $out/lib64
    cp -r ${busybox}/bin/* $out/bin/
    ${lib.optionalString is_evtest_included ''
      cp -r ${pkgs.evtest}/bin/* $out/bin/
    ''}

    cp ${boot_hello} $out/test/boot_hello.sh
    cp ${framevm_start} $out/test/framevm_start.sh
    chmod +x $out/test/framevm_start.sh
    cp ${framevm_shell} $out/test/framevm_shell.sh
    chmod +x $out/test/framevm_shell.sh
    cp ${framevm_foreground_smoke} $out/test/framevm_foreground_smoke.sh
    chmod +x $out/test/framevm_foreground_smoke.sh
    cp ${framevm_share_test} $out/test/framevm_share_test.sh
    chmod +x $out/test/framevm_share_test.sh
    cp ${framevm_busybox_smoke} $out/test/framevm_busybox_smoke.sh
    chmod +x $out/test/framevm_busybox_smoke.sh
    cp ${init} $out/init

    cp -r ${etc}/* $out/etc/

    cp ${resolv_conf}/resolv.conf $out/etc/

    ${lib.optionalString (regression != null) ''
      cp -r ${regression.package}/* $out/test/
    ''}

    ${lib.optionalString (benchmark != null) ''
      cp -r "${benchmark.package}"/* $out/benchmark/
    ''}

    ${lib.optionalString (conformance != null) ''
      cp -r "${conformance.package}"/* $out/
    ''}

    ${lib.optionalString
    (conformance != null && conformance.testSuite == "gvisor") ''
      # FIXME: Build gvisor syscall test with nix to avoid manual library copying.
      mkdir -p $out/lib/x86_64-linux-gnu
      cp -L ${gvisor_libs}/ld-linux-x86-64.so.2 $out/lib64/ld-linux-x86-64.so.2
      cp -L ${gvisor_libs}/libstdc++.so.6 $out/lib/x86_64-linux-gnu/libstdc++.so.6
      cp -L ${gvisor_libs}/libgcc_s.so.1 $out/lib/x86_64-linux-gnu/libgcc_s.so.1
      cp -L ${gvisor_libs}/libc.so.6 $out/lib/x86_64-linux-gnu/libc.so.6
      cp -L ${gvisor_libs}/libm.so.6 $out/lib/x86_64-linux-gnu/libm.so.6
    ''}

    ${lib.optionalString (framevmObj != null) ''
      install -Dm644 ${framevmObj} $out${framevmInstallPath}
    ''}

    ${lib.optionalString (framevmRootfs != null) ''
      install -Dm644 ${framevmRootfs} $out/framevm/rootfs.cpio.gz
    ''}

    # Use `writeClosure` to retrieve all dependencies of the specified packages.
    # This will generate a text file containing the complete closure of the packages,
    # including the packages themselves.
    # The output of `writeClosure` is equivalent to `nix-store -q --requisites`.
    mkdir -p $out/nix/store
    pkg_path=${lib.strings.concatStringsSep ":" all_pkgs}
    while IFS= read -r dep_path; do
      if [[ "$pkg_path" == *"$dep_path"* ]]; then
        continue
      fi
      cp -r $dep_path $out/nix/store/
    done < ${writeClosure all_pkgs}
  '';
}
