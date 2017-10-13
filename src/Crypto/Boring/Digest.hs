{-# LANGUAGE NoImplicitPrelude #-}

module Crypto.Boring.Digest
  ( Digest(..)
  , HashAlgorithm()
  , MD4
  , MD5
  , SHA1
  , SHA224
  , SHA256
  , SHA384
  , SHA512
  , hash
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import Data.Conduit
import qualified Language.C.Inline as C
import Foreign

import Crypto.Boring.Internal.Context
import Crypto.Boring.Internal.Prelude
import Crypto.Boring.Internal.Util

C.context cryptoCtx

C.include "<openssl/evp.h>"

class HashAlgorithm algo where
  hashAlgorithmMD :: Tagged algo (IO (Ptr EVP_MD))

data MD4
instance HashAlgorithm MD4 where
  hashAlgorithmMD = Tagged [C.exp| const EVP_MD* { EVP_md4() } |]

data MD5
instance HashAlgorithm MD5 where
  hashAlgorithmMD = Tagged [C.exp| const EVP_MD* { EVP_md5() } |]

data SHA1
instance HashAlgorithm SHA1 where
  hashAlgorithmMD = Tagged [C.exp| const EVP_MD* { EVP_sha1() } |]

data SHA224
instance HashAlgorithm SHA224 where
  hashAlgorithmMD = Tagged [C.exp| const EVP_MD* { EVP_sha224() } |]

data SHA256
instance HashAlgorithm SHA256 where
  hashAlgorithmMD = Tagged [C.exp| const EVP_MD* { EVP_sha256() } |]

data SHA384
instance HashAlgorithm SHA384 where
  hashAlgorithmMD = Tagged [C.exp| const EVP_MD* { EVP_sha384() } |]

data SHA512
instance HashAlgorithm SHA512 where
  hashAlgorithmMD = Tagged [C.exp| const EVP_MD* { EVP_sha512() } |]

newtype Digest algo = Digest BS.ByteString
  deriving (Eq, Ord, Show)

foreign import ccall "&EVP_MD_CTX_free" _EVP_MD_CTX_free :: FunPtr (Ptr EVP_MD_CTX -> IO ())

hash :: forall algo m. (HashAlgorithm algo, Monad m) => Sink BS.ByteString m (Digest algo)
hash = unsafeGeneralizeIO $ do
  ctx <- liftIO $ mask_ $ do
    ctxPtr <- [C.exp| EVP_MD_CTX* { EVP_MD_CTX_new() } |]
    newForeignPtr _EVP_MD_CTX_free ctxPtr
  algoMD <- liftIO $ untag (hashAlgorithmMD @algo)
  () <- liftIO $ checkRes "EVP_DigestInit_ex" [C.exp| int { EVP_DigestInit_ex($fptr-ptr:(EVP_MD_CTX* ctx), $(EVP_MD* algoMD), NULL) } |]
  awaitForever $ \block -> do
    liftIO $ checkRes "EVP_DigestUpdate" [C.exp| int { EVP_DigestUpdate($fptr-ptr:(EVP_MD_CTX* ctx), $bs-ptr:block, $bs-len:block) } |]
  liftIO $ do
    digestSize <- [C.exp| int { EVP_MD_size($(EVP_MD* algoMD)) } |] 
    fmap Digest $ BS.create (fromIntegral digestSize) $ \hashPtr -> do
      checkRes "EVP_DigestFinal_ex" [C.exp| int { EVP_DigestFinal_ex($fptr-ptr:(EVP_MD_CTX* ctx), $(uint8_t* hashPtr), NULL) } |]
