module Crypto.Boring.Test.Digest
  ( mkDigestTests
  ) where

import Control.Monad
import Data.Proxy
import Path
import Numeric
import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString as BS
import Data.Conduit
import qualified Data.Conduit.List as CL

import Crypto.Boring.Digest

import Crypto.Boring.Test.TestVectors

toHex :: BS.ByteString -> String
toHex bs = flip concatMap (BS.unpack bs) $ \d -> case showHex d "" of
      [ l ] -> [ '0', l ]
      hl -> hl

vectorString :: BS.ByteString -> BS.ByteString -> String
vectorString input output = trimmedInput ++ " -> " ++ toHex output
  where
    inputHex = toHex input
    trimmedInput
      | length inputHex > 50 = take 50 inputHex ++ "..."
      | otherwise = inputHex

mkTests :: forall algo. HashAlgorithm algo => String -> Proxy algo -> Path Rel File -> IO TestTree
mkTests name _ vecPath = do
  vectors <- getTestVectors hashVectors vecPath
  return $ testGroup name $ do
    vec <- vectors
    let Digest actualMd = runConduitPure (yield (hvInput vec) .| hash @algo)
    return $ testCase (vectorString (hvInput vec) (hvDigest vec)) $
      unless (actualMd == hvDigest vec) $
        assertFailure ("got " ++ toHex actualMd)

mkMonteTest :: forall algo. HashAlgorithm algo => String -> Proxy algo -> Path Rel File -> IO TestTree
mkMonteTest name algo vecPath = do
  monteVecs <- getTestVectors monteCarloVectors vecPath
  return $ testCase name $ do
    zipWithM_ (@?=) (map Digest (mcvIterations monteVecs)) (monteCarloExpected algo (Digest (mcvSeed monteVecs)))

mkHmacTests :: forall algo. HashAlgorithm algo => String -> Proxy algo -> Path Rel File -> IO TestTree
mkHmacTests name _ vecPath = do
  vectors <- getTestVectors macVectors vecPath
  return $ testGroup name $ do
    vec <- vectors
    let Hmac actualMd = runConduitPure (yield (mvInput vec) .| hmac @algo (HmacKey (mvKey vec)))
    return $ testCase (vectorString (mvInput vec) (mvDigest vec)) $
      unless (actualMd == mvDigest vec) $
        assertFailure ("got " ++ toHex actualMd)

-- see https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/shs/shavs.pdf 6.4
monteCarloExpected :: forall algo. HashAlgorithm algo => Proxy algo -> Digest algo -> [ Digest algo ]
monteCarloExpected _ initSeed = take 100 $ tail $ iterate checkPoint initSeed
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
  testGroup "Digest" <$> sequence
    [ testGroup "Hashes" <$> sequence
      [ mkTests "MD5" (Proxy @MD5) $(mkRelFile "hashes/MD5/rfc-1321.txt")
      , mkShaTests "SHA1" "SHA1" (Proxy @SHA1) 
      , mkShaTests "SHA2" "SHA256" (Proxy @SHA256) 
      , mkShaTests "SHA2" "SHA384" (Proxy @SHA384) 
      , mkShaTests "SHA2" "SHA512" (Proxy @SHA512) 
      ]
    , testGroup "HMAC" <$> sequence
      [ mkHmacTests "HMAC-MD5" (Proxy @MD5) $(mkRelFile "HMAC/rfc-2202-md5.txt")
      , mkHmacTests "HMAC-SHA1" (Proxy @SHA1) $(mkRelFile "HMAC/rfc-2202-sha1.txt")
      , mkHmacTests "HMAC-SHA224" (Proxy @SHA224) $(mkRelFile "HMAC/rfc-4231-sha224.txt")
      , mkHmacTests "HMAC-SHA256" (Proxy @SHA256) $(mkRelFile "HMAC/rfc-4231-sha256.txt")
      , mkHmacTests "HMAC-SHA384" (Proxy @SHA384) $(mkRelFile "HMAC/rfc-4231-sha384.txt")
      , mkHmacTests "HMAC-SHA512" (Proxy @SHA512) $(mkRelFile "HMAC/rfc-4231-sha512.txt")
      ]
    ]
