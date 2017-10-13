{ nixpkgs ? import <nixpkgs> {}, compiler ? "ghc821" }:

let

  inherit (nixpkgs) pkgs;

  mk-boringssl-crypto = { stdenv, fetchgit, cmake, perl, go }:
    stdenv.mkDerivation rec {
      name = "boringssl-crypto-${version}";
      version = "2017-10-13";

      src = fetchgit {
        url    = "https://boringssl.googlesource.com/boringssl";
        rev    = "fdb7a3580fa1b5564eed043f2e6471cc1abb0756";
        sha256 = "0kpr8fwkxpsyw7lcjpg9pwzcsccbsivih1dm1i4rqzqpflslbwxl";
      };

      buildInputs = [ cmake perl go ];
      enableParallelBuilding = true;
      NIX_CFLAGS_COMPILE = "-Wno-error";

      cmakeFlags = [ "-DBUILD_SHARED_LIBS=true" ];

      buildFlags = [ "crypto" ];

      installPhase = ''
        mkdir -p $out/include $out/lib

        cp -v crypto/libcrypto.so $out/lib
        cp -rv ../include/openssl $out/include
      '';
    };

  boringssl-crypto = nixpkgs.callPackage mk-boringssl-crypto {};

  f = { mkDerivation, base, conduit, inline-c, bytestring, mtl, containers, resourcet, tagged, safe-exceptions, tasty, QuickCheck, tasty-quickcheck, stdenv, boringssl }:
      mkDerivation {
        pname = "boring-crypto";
        version = "0.1.0.0";
        src = ./.;
        libraryHaskellDepends = [ base conduit inline-c bytestring mtl containers resourcet tagged safe-exceptions tasty QuickCheck tasty-quickcheck ];
        librarySystemDepends = [ boringssl-crypto ];
        license = stdenv.lib.licenses.mit;

        shellHook = ''
          export LD_LIBRARY_PATH=${boringssl-crypto}/lib:$LD_LIBRARY_PATH
          export CPATH=${boringssl-crypto}/include:$CPATH
        '';
      };

  haskellPackages = pkgs.haskell.packages.${compiler}.override {
    overrides = self: super: {
      inline-c = super.inline-c_0_6_0_5;
    };
  };

  drv = haskellPackages.callPackage f {};

in

  if pkgs.lib.inNixShell then drv.env else drv
