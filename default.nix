{ nixpkgs ? import <nixpkgs> {}, compiler ? "ghc821" }:

let

  inherit (nixpkgs) pkgs;

  f = { mkDerivation, base, conduit, inline-c, bytestring, mtl, containers, resourcet, tagged, safe-exceptions, tasty, QuickCheck, tasty-quickcheck, megaparsec, path, path-io, tasty-hunit, stdenv }:
      mkDerivation {
        pname = "boring-crypto";
        version = "0.1.0.0";
        src = ./.;
        libraryHaskellDepends = [ base conduit inline-c bytestring mtl containers resourcet tagged safe-exceptions tasty QuickCheck tasty-quickcheck megaparsec path path-io tasty-hunit ];
        license = stdenv.lib.licenses.mit;
      };

  haskellPackages = pkgs.haskell.packages.${compiler}.override {
    overrides = self: super: {
      inline-c = super.inline-c_0_6_0_5;
      directory = super.directory_1_3_1_4;
      megaparsec = super.megaparsec_6_2_0;
    };
  };

  drv = haskellPackages.callPackage f {};

in

  if pkgs.lib.inNixShell then drv.env else drv
