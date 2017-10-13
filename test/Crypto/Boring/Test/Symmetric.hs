{-# OPTIONS_GHC -fno-warn-orphans #-}

module Crypto.Boring.Test.Symmetric
  ( symmetricTests
  ) where

import Control.Monad
import Data.Proxy
import Data.Tagged
import qualified Data.ByteString as BS
import Test.QuickCheck
import Test.Tasty
import Test.Tasty.QuickCheck
import Data.Conduit
import qualified Data.Conduit.List as CL

import Crypto.Boring.Symmetric

allEnum :: (Enum a, Bounded a) => [ a ]
allEnum = [minBound..maxBound]

instance IsCipher cipher => Arbitrary (Key cipher) where
  arbitrary = 
    fmap (Key . BS.pack) $ replicateM (cipherKeyLength (untag (reflectCipher @cipher))) arbitrary

instance IsCipher cipher => Arbitrary (IV cipher) where
  arbitrary = 
    fmap (IV . BS.pack) $ replicateM (cipherBlockSize (untag (reflectCipher @cipher))) arbitrary

roundTrip :: forall cipher. IsCipher cipher => Proxy cipher -> BlockCipherMode -> PaddingMode -> Key cipher -> IV cipher -> Property
roundTrip _ blockCipherMode paddingMode key iv =
  forAll genChunks $ \chunks ->
    let
      roundTripChunks = runConduitPure (CL.sourceList chunks .| encrypt conf .| decrypt conf .| CL.consume)
    in BS.concat chunks === BS.concat roundTripChunks
  where
    conf = CipherConfig
      { ccCipherMode = blockCipherMode
      , ccPaddingMode = paddingMode
      , ccKey = key
      , ccIV = iv
      }
    genChunk = BS.pack <$> arbitrary
    genChunksUnpadded = listOf genChunk
    genChunks = case paddingMode of
      DisablePadding -> do
        chunks <- genChunksUnpadded
        let blockSize = cipherBlockSize $ untag (reflectCipher @cipher)
        let totalSize = sum $ map BS.length chunks
        extraChunk <- BS.pack <$> replicateM (blockSize - (totalSize `mod` blockSize)) arbitrary
        return (chunks ++ [ extraChunk ])
      EnablePadding -> genChunksUnpadded

symmetricTests :: TestTree
symmetricTests = testGroup "Symmetric" $ do
  cipher <- allEnum
  blockCipherMode <- allEnum
  paddingMode <- allEnum

  let propertyName =
        show cipher ++ " - " ++ show blockCipherMode ++ " - " ++ show paddingMode ++ " round trips"

  reifyCipher cipher $ \cipherProxy ->
    return $ testProperty propertyName $ roundTrip cipherProxy blockCipherMode paddingMode