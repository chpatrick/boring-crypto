{-# OPTIONS_GHC -fno-warn-orphans #-}

module Crypto.Boring.Test.Symmetric
  ( mkSymmetricTests
  ) where

import Control.Monad
import Data.Proxy
import Data.Tagged
import qualified Data.ByteString as BS
import Test.QuickCheck
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.HUnit
import Data.Conduit
import Path
import qualified Data.Conduit.List as CL

import Crypto.Boring.Symmetric

import Crypto.Boring.Test.TestVectors

allEnum :: (Enum a, Bounded a) => [ a ]
allEnum = [minBound..maxBound]

instance IsCipher cipher => Arbitrary (Key cipher) where
  arbitrary =
    fmap (mkKey . BS.pack) $ replicateM (cipherKeyLength (untag (reflectCipher @cipher))) arbitrary

roundTrip :: forall cipher mode. (IsCipher cipher, IsMode mode) => Proxy cipher -> Proxy mode -> PaddingMode -> Key cipher -> Gen Property
roundTrip _ _ paddingMode key = do
  let genChunk = BS.pack <$> arbitrary
  let genChunksUnpadded = listOf genChunk
  let genChunks = case paddingMode of
        DisablePadding -> do
          chunks <- genChunksUnpadded
          let blockSize = cipherBlockSize $ untag (reflectCipher @cipher)
          let totalSize = sum $ map BS.length chunks
          extraChunk <- BS.pack <$> replicateM (blockSize - (totalSize `mod` blockSize)) arbitrary
          return (chunks ++ [ extraChunk ])
        EnablePadding -> genChunksUnpadded
  let genIV = case ivSize (Proxy @cipher) (Proxy @mode) of
        Nothing -> return $ mkIV (Proxy @cipher) (Proxy @mode) Nothing
        Just size -> fmap (mkIV (Proxy @cipher) (Proxy @mode) . Just . BS.pack) $ replicateM size arbitrary

  iv <- genIV
  let conf = CipherConfig
        { ccPaddingMode = paddingMode
        , ccKey = key
        , ccIV = iv
        } :: CipherConfig cipher mode
  chunks <- genChunks
  let roundTripChunks = runConduitPure (CL.sourceList chunks .| encrypt conf .| decrypt conf .| CL.consume)
  return (BS.concat chunks === BS.concat roundTripChunks)

mkSymmetricTests :: IO TestTree
mkSymmetricTests = fmap (testGroup "Symmetric") $ sequence $ do
  cipher <- allEnum
  reifyCipher cipher $ \(cipherProxy :: Proxy cipher) ->
    return $ fmap (testGroup (show cipher)) $ sequence $ do
      blockCipherMode <- allEnum

      reifyMode blockCipherMode $ \(modeProxy :: Proxy mode) -> do
        let mkAesTests keySize = do
              let testNames = [ "GFSbox", "KeySbox", "MMT", "VarKey", "VarTxt" ]

              return $ fmap (testGroup "Test vectors") $ sequence $ do
                testName <- testNames

                return $ do
                  let modeString = case blockCipherMode of
                        ECB -> "ECB"
                        CBC -> "CBC"
                        OFB -> "OFB"

                  vecPath <- parseRelFile ("ciphers/AES/" ++ modeString ++ "/" ++ modeString ++ testName ++ show (keySize :: Int) ++ ".rsp")
                  vectors <- getTestVectors cipherVectors vecPath
                  return $ testGroup testName $ do
                    vec <- vectors
                    let conf = CipherConfig
                          { ccKey = mkKey (cvKey vec)
                          , ccIV = mkIV cipherProxy modeProxy (cvIv vec)
                          , ccPaddingMode = DisablePadding
                          } :: CipherConfig cipher mode
                    let cryptFunc = case cvDirection vec of
                          CDEncrypt -> encrypt
                          CDDecrypt -> decrypt
                    let actualOutput = BS.concat $ runConduitPure (yield (cvInput vec) .| cryptFunc conf .| CL.consume)
                    return $ testCase (vectorString (cvInput vec) (cvOutput vec)) $
                      unless (actualOutput == cvOutput vec) $
                        assertFailure ("got " ++ toHex actualOutput)

        let roundTripTests = testGroup "Round-trip" $ do
              paddingMode <- allEnum
              return $ testProperty (show paddingMode) $ roundTrip cipherProxy modeProxy paddingMode

        let mkCipherTests = case cipher of
              AES128 -> mkAesTests 128
              AES256 -> mkAesTests 256

        return $ fmap (testGroup (show blockCipherMode)) $ sequence
            (pure roundTripTests : mkCipherTests)