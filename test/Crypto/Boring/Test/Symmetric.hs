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

mkSymmetricTests :: IO TestTree
mkSymmetricTests = fmap (testGroup "Symmetric") $ sequence $ do
  cipher <- allEnum
  reifyCipher cipher $ \(cipherProxy :: Proxy cipher) ->
    return $ fmap (testGroup (show cipher)) $ sequence $ do
      blockCipherMode <- allEnum

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
                        { ccKey = Key (cvKey vec)
                        , ccIV = IV (maybe BS.empty id (cvIv vec))
                        , ccCipherMode = blockCipherMode
                        , ccPaddingMode = DisablePadding
                        } :: CipherConfig cipher
                  let cryptFunc = case cvDirection vec of
                        CDEncrypt -> encrypt
                        CDDecrypt -> decrypt
                  let actualOutput = BS.concat $ runConduitPure (yield (cvInput vec) .| cryptFunc conf .| CL.consume)
                  return $ testCase (vectorString (cvInput vec) (cvOutput vec)) $
                    unless (actualOutput == cvOutput vec) $
                      assertFailure ("got " ++ toHex actualOutput)

      let roundTripTests = testGroup "Round-trip" $ do
            paddingMode <- allEnum
            return $ testProperty (show paddingMode) $ roundTrip cipherProxy blockCipherMode paddingMode

      let mkCipherTests = case cipher of
            AES128 -> mkAesTests 128
            AES256 -> mkAesTests 256

      return $ fmap (testGroup (show blockCipherMode)) $ sequence
          (pure roundTripTests : mkCipherTests)