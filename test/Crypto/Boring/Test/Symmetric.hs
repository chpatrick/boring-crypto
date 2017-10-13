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

roundTrip :: forall cipher. IsCipher cipher => Proxy cipher -> BlockCipherMode -> PaddingMode -> Key cipher -> IV cipher -> Gen Property
roundTrip _ blockCipherMode paddingMode key iv = do
  let conf = CipherConfig
        { ccCipherMode = blockCipherMode
        , ccPaddingMode = paddingMode
        , ccKey = key
        , ccIV = iv
        }
  let genChunk = case paddingMode of
        DisablePadding -> do
          let blockSize = cipherBlockSize $ untag (reflectCipher @cipher)
          fmap BS.pack $ replicateM blockSize arbitrary
        EnablePadding -> BS.pack <$> arbitrary 
  chunks <- listOf genChunk
  roundTripChunks <- CL.sourceList chunks $= encrypt conf $= decrypt conf $$ CL.consume
  return (BS.concat chunks === BS.concat roundTripChunks)

symmetricTests :: TestTree
symmetricTests = testGroup "Symmetric" $ do
  cipher <- allEnum
  blockCipherMode <- allEnum
  paddingMode <- allEnum

  let propertyName =
        show cipher ++ " - " ++ show blockCipherMode ++ " - " ++ show paddingMode ++ " round trips"

  reifyCipher cipher $ \cipherProxy ->
    return $ testProperty propertyName $ roundTrip cipherProxy blockCipherMode paddingMode