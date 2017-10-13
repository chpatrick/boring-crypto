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
  , HmacKey(..)
  , Hmac(..)
  , hmac
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import Data.Conduit
import qualified Language.C.Inline as C
import Foreign

import Crypto.Boring.Exception
import Crypto.Boring.Internal.Context
import Crypto.Boring.Internal.Prelude
import Crypto.Boring.Internal.Util

C.context cryptoCtx

C.include "<openssl/evp.h>"
C.include "<openssl/hmac.h>"

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

newtype HmacKey = HmacKey BS.ByteString
  deriving (Eq, Ord, Show)

newtype Hmac algo = Hmac BS.ByteString
  deriving (Eq, Ord, Show)

foreign import ccall "&HMAC_CTX_free" _HMAC_CTX_free :: FunPtr (Ptr HMAC_CTX -> IO ())

hmac :: forall algo m. (HashAlgorithm algo, Monad m) => HmacKey -> Sink BS.ByteString m (Hmac algo)
hmac (HmacKey key) = unsafeGeneralizeIO $ do
  ctx <- liftIO $ mask_ $ do
    ctxPtr <- [C.exp| HMAC_CTX* { HMAC_CTX_new() } |]
    when (ctxPtr == nullPtr) $
      throw (CryptoException "HMAC_CTX_new() failed!")
    algoMD <- untag (hashAlgorithmMD @algo)
    ctx <- newForeignPtr _HMAC_CTX_free ctxPtr
    checkRes "HMAC_Init_ex" [C.exp| int {
      HMAC_Init_ex(
        $(HMAC_CTX* ctxPtr),
        $bs-ptr:key,
        $bs-len:key,
        $(EVP_MD* algoMD),
        NULL
      ) } |]
    return ctx
  awaitForever $ \input ->
    liftIO $ checkRes "HMAC_Update" [C.exp| int { HMAC_Update($fptr-ptr:(HMAC_CTX* ctx), $bs-ptr:input, $bs-len:input) } |]
  liftIO $ do
    maxSize <- [C.exp| size_t { EVP_MAX_MD_SIZE } |]
    fmap Hmac $ BS.createAndTrim (fromIntegral maxSize) $ \resPtr -> do
      outLen <- C.withPtr_ $ \outLenPtr ->
        checkRes "HMAC_Final"
          [C.exp| int {
            HMAC_Final(
              $fptr-ptr:(HMAC_CTX* ctx),
              $(uint8_t* resPtr),
              $(unsigned int* outLenPtr)
            ) } |]
      return (fromIntegral outLen)