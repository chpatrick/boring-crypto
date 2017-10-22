{-# LANGUAGE NoImplicitPrelude #-}

module Crypto.Boring.Symmetric
  ( encrypt
  , decrypt
  , Cipher(..)
  , IsCipher(..)
  , reifyCipher
  , cipherBlockSize
  , cipherKeyLength
  , PaddingMode(..)
  , BlockCipherMode(..)
  , CipherConfig(..)
  , IV(..)
  , Key(..)
  ) where

import Foreign
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS (createAndTrim)
import Data.Conduit
import qualified Language.C.Inline as C
import System.IO.Unsafe

import Crypto.Boring.Exception
import Crypto.Boring.Internal.Context
import Crypto.Boring.Internal.Prelude
import Crypto.Boring.Internal.Util

C.context cryptoCtx

C.include "<openssl/evp.h>"

newtype IV (cipher :: Cipher) = IV BS.ByteString
  deriving (Eq, Ord, Show)
newtype Key (cipher :: Cipher) = Key BS.ByteString
  deriving (Eq, Ord, Show)

data BlockCipherMode
  = CBC
  | ECB
  | OFB
    deriving (Eq, Ord, Show, Enum, Bounded)

data Cipher
  = AES128
  | AES256
    deriving (Eq, Ord, Show, Enum, Bounded)

class IsCipher (cipher :: Cipher) where
  reflectCipher :: Tagged cipher Cipher

instance IsCipher 'AES128 where
  reflectCipher = Tagged AES128

instance IsCipher 'AES256 where
  reflectCipher = Tagged AES256

reifyCipher :: Cipher -> (forall cipher. IsCipher cipher => Proxy cipher -> a) -> a
reifyCipher c f = case c of
  AES128 -> f (Proxy @'AES128)
  AES256 -> f (Proxy @'AES256)

-- | The block size of a given `Cipher` in bytes.
cipherBlockSize :: Cipher -> Int
cipherBlockSize cipher = unsafePerformIO $ do
  c'cipher <- getCipher cipher CBC
  fromIntegral <$> [C.exp| int { EVP_CIPHER_block_size($(EVP_CIPHER* c'cipher)) } |]
{-# NOINLINE cipherBlockSize #-}

-- | The key size of a given `Cipher` in bytes.
cipherKeyLength :: Cipher -> Int
cipherKeyLength cipher = unsafePerformIO $ do
  c'cipher <- getCipher cipher CBC
  fromIntegral <$> [C.exp| int { EVP_CIPHER_key_length($(EVP_CIPHER* c'cipher)) } |]
{-# NOINLINE cipherKeyLength #-}

-- | Whether to enable padding. If disabled, encryption and decryption operations
-- must be given a multiple of `cipherBlockSize` bytes of data.
data PaddingMode
  = EnablePadding
  | DisablePadding
    deriving (Eq, Ord, Show, Enum, Bounded)

data CipherConfig cipher = CipherConfig
  { ccPaddingMode :: PaddingMode
  , ccCipherMode :: BlockCipherMode
  , ccKey :: Key cipher
  , ccIV :: IV cipher
  }

ccCipher :: forall cipher. IsCipher cipher => CipherConfig cipher -> Cipher
ccCipher _ = untag (reflectCipher @cipher)

foreign import ccall "&EVP_CIPHER_CTX_free" _EVP_CIPHER_CTX_free :: FunPtr (Ptr EVP_CIPHER_CTX -> IO ())

getCipher :: Cipher -> BlockCipherMode -> IO (Ptr EVP_CIPHER)
getCipher cipher mode = case cipher of
  AES128 -> case mode of
    CBC -> [C.exp| const EVP_CIPHER* { EVP_aes_128_cbc() } |]
    ECB -> [C.exp| const EVP_CIPHER* { EVP_aes_128_ecb() } |]
    OFB -> [C.exp| const EVP_CIPHER* { EVP_aes_128_ofb() } |]

  AES256 -> case mode of
    CBC -> [C.exp| const EVP_CIPHER* { EVP_aes_256_cbc() } |]
    ECB -> [C.exp| const EVP_CIPHER* { EVP_aes_256_ecb() } |]
    OFB -> [C.exp| const EVP_CIPHER* { EVP_aes_256_ofb() } |]

crypt
  :: (Monad m, IsCipher cipher)
  => (ForeignPtr EVP_CIPHER_CTX -> Ptr EVP_CIPHER -> Key cipher -> IV cipher -> IO ()) -- init context
  -> (ForeignPtr EVP_CIPHER_CTX -> Ptr Word8 -> Ptr C.CInt -> BS.ByteString -> IO ()) -- update
  -> (ForeignPtr EVP_CIPHER_CTX -> Ptr Word8 -> Ptr C.CInt -> IO ()) -- final
  -> CipherConfig cipher
  -> Conduit BS.ByteString m BS.ByteString
crypt initCtx update final conf = unsafeGeneralizeIO $ do
  ctx <- liftIO $ do
    ctx <- mask_ $ do
      ctxPtr <- [C.exp| EVP_CIPHER_CTX* { EVP_CIPHER_CTX_new() } |]
      when (ctxPtr == nullPtr) $
        throwM $ CryptoException "EVP_CIPHER_CTX_new failed"
      newForeignPtr _EVP_CIPHER_CTX_free ctxPtr
    cipher <- getCipher (ccCipher conf) (ccCipherMode conf)
    -- TODO: check key length
    initCtx ctx cipher (ccKey conf) (ccIV conf)
    let padding = case ccPaddingMode conf of
          DisablePadding -> 0
          EnablePadding -> 1
    checkRes "EVP_CIPHER_CTX_set_padding" [C.exp| int { EVP_CIPHER_CTX_set_padding($fptr-ptr:(EVP_CIPHER_CTX* ctx), $(int padding)) } |]
    return ctx

  let blockSize = cipherBlockSize (ccCipher conf)

  let yieldBlock maxSize f = do
        outBuf <- liftIO $
          BS.createAndTrim maxSize $ \outPtr -> do
            outLen <- C.withPtr_ $ \outLenPtr -> 
              f outPtr outLenPtr
            return (fromIntegral outLen)
        unless (BS.null outBuf) $ yield outBuf

  awaitForever $ \input -> do
    yieldBlock (BS.length input + blockSize) $ \outPtr outLenPtr ->
      update ctx outPtr outLenPtr input

  yieldBlock blockSize $ \outPtr outLenPtr ->
    final ctx outPtr outLenPtr

-- | Encrypt data using a given cipher.
encrypt :: (Monad m, IsCipher cipher) => CipherConfig cipher -> Conduit BS.ByteString m BS.ByteString
encrypt =
  crypt
    (\ctx cipher (Key key) (IV iv) -> 
      checkRes "EVP_EncryptInit_ex"
        [C.exp| int {
          EVP_EncryptInit_ex(
            $fptr-ptr:(EVP_CIPHER_CTX* ctx),
            $(EVP_CIPHER* cipher),
            NULL, // pick default impl
            $bs-ptr:key, $bs-ptr:iv) 
        } |])
    (\ctx outPtr outLenPtr plain ->
      checkRes "EVP_EncryptUpdate" [C.exp| int {
        EVP_EncryptUpdate(
          $fptr-ptr:(EVP_CIPHER_CTX* ctx),
          $(uint8_t* outPtr),
          $(int* outLenPtr),
          $bs-ptr:plain,
          $bs-len:plain
        ) } |])
    (\ctx outPtr outLenPtr -> 
      checkRes "EVP_EncryptFinal_ex" [C.exp| int {
        EVP_EncryptFinal_ex(
          $fptr-ptr:(EVP_CIPHER_CTX* ctx),
          $(uint8_t* outPtr),
          $(int* outLenPtr)
        ) } |])

-- | Decrypt data using a given cipher.
decrypt :: (Monad m, IsCipher cipher) => CipherConfig cipher -> Conduit BS.ByteString m BS.ByteString
decrypt =
  crypt
    (\ctx cipher (Key key) (IV iv) -> 
      checkRes "EVP_DecryptInit_ex"
        [C.exp| int {
          EVP_DecryptInit_ex(
            $fptr-ptr:(EVP_CIPHER_CTX* ctx),
            $(EVP_CIPHER* cipher),
            NULL, // pick default impl
            $bs-ptr:key, $bs-ptr:iv) 
        } |])
    (\ctx outPtr outLenPtr plain ->
      checkRes "EVP_DecryptUpdate" [C.exp| int {
        EVP_DecryptUpdate(
          $fptr-ptr:(EVP_CIPHER_CTX* ctx),
          $(uint8_t* outPtr),
          $(int* outLenPtr),
          $bs-ptr:plain,
          $bs-len:plain
        ) } |])
    (\ctx outPtr outLenPtr -> 
      checkRes "EVP_DecryptFinal_ex" [C.exp| int {
        EVP_DecryptFinal_ex(
          $fptr-ptr:(EVP_CIPHER_CTX* ctx),
          $(uint8_t* outPtr),
          $(int* outLenPtr)
        ) } |])
