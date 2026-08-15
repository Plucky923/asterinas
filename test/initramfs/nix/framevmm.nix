{ lib, rustPlatform }:
let
  source = lib.cleanSourceWith {
    src = ../../..;
    filter = path: type:
      let name = baseNameOf path;
      in !(type == "directory" && (name == "target" || name == "build"
        || lib.hasPrefix ".framevm-build" name));
  };
in rustPlatform.buildRustPackage {
  pname = "framevmm";
  version = "0.1.0";
  src = source;
  buildAndTestSubdir = "tools/framevmm";
  cargoRoot = "tools/framevmm";
  cargoLock = {
    lockFile = "${source}/tools/framevmm/Cargo.lock";
    outputHashes."smoltcp-0.11.0" =
      "sha256-ayK6vDcvOnIhZEjYL/chm2R6jTs6hWXUkk53CxUixmY=";
  };

  meta = {
    description = "FrameVM userspace manager";
    license = lib.licenses.mpl20;
    mainProgram = "framevmm";
  };
}
