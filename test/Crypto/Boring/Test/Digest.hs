module Crypto.Boring.Test.Digest
  ( mkDigestTests
  ) where

import Control.Monad
import Data.Proxy
import Path
import Test.Tasty
import Test.Tasty.HUnit
import Data.Conduit
import qualified Data.Conduit.List as CL

import Crypto.Boring.Digest

import Crypto.Boring.Test.TestVectors

mkTests :: forall algo. HashAlgorithm algo => String -> Proxy algo -> Path Rel File -> IO TestTree
mkTests name _ vecPath = do
  vectors <- getTestVectors cavsVectors vecPath
  return $ testGroup name $ do
    vec@( msg, expectedMd ) <- vectors
    let Digest actualMd = runConduitPure (yield msg .| hash @algo)
    return $ testCase (vectorString vec) $
      unless (actualMd == expectedMd) $
        assertFailure ("got " ++ toHex actualMd)

mkMonteTest :: forall algo. HashAlgorithm algo => String -> Proxy algo -> Path Rel File -> IO TestTree
mkMonteTest name _ vecPath = do
  ( seed, digests ) <- getTestVectors monteCarloVectors vecPath
  return $ testCase name $ do
    zipWithM_ (@?=) (map Digest digests) (monteCarloExpected (Digest @algo seed))

-- see https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/shs/shavs.pdf 6.4
monteCarloExpected :: forall algo. HashAlgorithm algo => Digest algo -> [ Digest algo ]
monteCarloExpected = take 100 . tail . iterate checkPoint
  where
    checkPoint seed = go (1 :: Int) [ seed, seed, seed ]
    go i msgs
      | i == 1000 = md
      | otherwise = go (i + 1) (tail msgs ++ [ md ])
      where
        md = runConduitPure (CL.sourceList (map unDigest msgs) .| hash @algo)

mkShaTests :: forall algo. HashAlgorithm algo => String -> String -> Proxy algo -> IO TestTree
mkShaTests category name _ = fmap (testGroup name) $ sequence
  [ testFile "ShortMsg" >>= mkTests "Short messages" (Proxy @algo)
  , testFile "LongMsg" >>= mkTests "Long messages" (Proxy @algo)
  , testFile "Monte" >>= mkMonteTest "Monte Carlo" (Proxy @algo)
  ]
    where
      testFile suff = parseRelFile ("hashes/" ++ category ++ "/" ++ name ++ suff ++ ".rsp") 

mkDigestTests :: IO TestTree
mkDigestTests =
  fmap (testGroup "Digest") $
    sequence
      [ mkTests "MD5" (Proxy @MD5) $(mkRelFile "hashes/MD5/rfc-1321.txt")
      , mkShaTests "SHA1" "SHA1" (Proxy @SHA1) 
      , mkShaTests "SHA2" "SHA256" (Proxy @SHA256) 
      , mkShaTests "SHA2" "SHA384" (Proxy @SHA384) 
      , mkShaTests "SHA2" "SHA512" (Proxy @SHA512) 
      ]