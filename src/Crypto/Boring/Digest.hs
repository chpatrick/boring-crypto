{-# LANGUAGE NoImplicitPrelude #-}

module Crypto.Boring.Digest
  ( hash
  , Digest(..)
  , HmacKey(..)
  , Hmac(..)
  , hmac
  , HashAlgorithm()
  , MD4
  , MD5
  , SHA1
  , SHA224
  , SHA256
  , SHA384
  , SHA512
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

C.include "<openssl/err.h>"
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

newtype Digest algo = Digest { unDigest :: BS.ByteString }
  deriving (Eq, Ord, Show)

foreign import ccall "&EVP_MD_CTX_free" _EVP_MD_CTX_free :: FunPtr (Ptr EVP_MD_CTX -> IO ())

-- | Compute a hash of input data using a given algorithm.
hash :: forall algo m. (HashAlgorithm algo, Monad m) => Sink BS.ByteString m (Digest algo)
hash = unsafeGeneralizeIO $ do
  let update ctx block =
        [checkExp|
          EVP_DigestUpdate(
            $fptr-ptr:(EVP_MD_CTX* ctx),
            $bs-ptr:block,
            $bs-len:block
          ) |]

  -- we have to be careful not to create the ctx as the first operation here,
  -- because then GHC can helpfully let-float it out and all invocations will share the ctx
  mbFirst <- await
  ( ctx, algoMD ) <- liftIO $ do
    ctx <- mask_ $ do
      ctxPtr <- $(checkPtrExp "EVP_MD_CTX" "EVP_MD_CTX_new()")
      newForeignPtr _EVP_MD_CTX_free ctxPtr
    algoMD <- untag (hashAlgorithmMD @algo)
    [checkExp|
      EVP_DigestInit_ex(
        $fptr-ptr:(EVP_MD_CTX* ctx),
        $(EVP_MD* algoMD),
        NULL // pick default implementation
      ) |]
    traverse_ (update ctx) mbFirst
    return ( ctx, algoMD )
  awaitForever (liftIO . update ctx)
  liftIO $ do
    digestSize <- [C.exp| int { EVP_MD_size($(EVP_MD* algoMD)) } |]
    fmap Digest $ BS.create (fromIntegral digestSize) $ \hashPtr -> do
      [checkExp|
        EVP_DigestFinal_ex(
          $fptr-ptr:(EVP_MD_CTX* ctx),
          $(uint8_t* hashPtr),
          NULL // we don't need to know the digest size
        ) |]
{-# NOINLINE hash #-}

newtype HmacKey = HmacKey { unHmacKey :: BS.ByteString }
  deriving (Eq, Ord, Show)

newtype Hmac algo = Hmac { unHmac :: BS.ByteString }
  deriving (Eq, Ord, Show)

foreign import ccall "&HMAC_CTX_free" _HMAC_CTX_free :: FunPtr (Ptr HMAC_CTX -> IO ())

-- | Compute an HMAC of input data using a given underlying algorithm.
hmac :: forall algo m. (HashAlgorithm algo, Monad m) => HmacKey -> Sink BS.ByteString m (Hmac algo)
hmac (HmacKey key) = unsafeGeneralizeIO $ do
  ctx <- liftIO $ do
    ctx <- mask_ $ do
      ctxPtr <- $(checkPtrExp "HMAC_CTX" "HMAC_CTX_new()")
      newForeignPtr _HMAC_CTX_free ctxPtr
    algoMD <- untag (hashAlgorithmMD @algo)
    [checkExp|
      HMAC_Init_ex(
        $fptr-ptr:(HMAC_CTX* ctx),
        $bs-ptr:key,
        $bs-len:key,
        $(EVP_MD* algoMD),
        NULL // use the default implementation
      ) |]
    return ctx
  awaitForever $ \input ->
    liftIO [checkExp|
      HMAC_Update(
        $fptr-ptr:(HMAC_CTX* ctx),
        $bs-ptr:input,
        $bs-len:input
      ) |]
  liftIO $ do
    maxSize <- [C.exp| size_t { EVP_MAX_MD_SIZE } |]
    fmap Hmac $ BS.createAndTrim (fromIntegral maxSize) $ \resPtr -> do
      outLen <- C.withPtr_ $ \outLenPtr ->
        [checkExp|
          HMAC_Final(
            $fptr-ptr:(HMAC_CTX* ctx),
            $(uint8_t* resPtr),
            $(unsigned int* outLenPtr)
          ) |]
      return (fromIntegral outLen)
{-# NOINLINE hmac #-}