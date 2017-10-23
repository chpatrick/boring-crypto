{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TypeFamilies #-}

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
  , IsMode(reflectMode, IV, mkIV, ivSize)
  , reifyMode
  , CipherConfig(..)
  , Key
  , mkKey
  , Block
  , mkBlock
  ) where

import Foreign
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS (createAndTrim)
import Data.Conduit
import qualified Language.C.Inline as C
import System.IO.Unsafe

import Crypto.Boring.Internal.Context
import Crypto.Boring.Internal.Prelude
import Crypto.Boring.Internal.Util

C.context cryptoCtx

C.include "<openssl/err.h>"
C.include "<openssl/evp.h>"

newtype Key (cipher :: Cipher) = Key BS.ByteString
  deriving (Eq, Ord, Show)

mkKey :: forall cipher. (IsCipher cipher, HasCallStack) => BS.ByteString -> Key cipher
mkKey bs
  | actualLength == expectedLength = Key bs
  | otherwise = error ("Invalid key length, expected " ++ show expectedLength ++ ", got " ++ show actualLength)
    where
      expectedLength = cipherKeyLength (untag (reflectCipher @cipher))
      actualLength = BS.length bs

newtype Block (cipher :: Cipher) = Block BS.ByteString
  deriving (Eq, Ord, Show)

mkBlock :: forall cipher. (IsCipher cipher, HasCallStack) => BS.ByteString -> Block cipher
mkBlock bs
  | actualLength == expectedLength = Block bs
  | otherwise = error ("Invalid block length, expected " ++ show expectedLength ++ ", got " ++ show actualLength)
    where
      expectedLength = cipherBlockSize (untag (reflectCipher @cipher))
      actualLength = BS.length bs

data NoIV = NoIV
  deriving (Eq, Ord, Show)

data BlockCipherMode
  = CBC
  | ECB
  | OFB
    deriving (Eq, Ord, Show, Enum, Bounded)

class IsMode (mode :: BlockCipherMode) where
  type IV (cipher :: Cipher) mode :: *
  reflectMode :: Tagged mode BlockCipherMode
  getIV :: Proxy cipher -> Proxy mode -> IV cipher mode -> BS.ByteString
  mkIV :: (HasCallStack, IsCipher cipher) => Proxy cipher -> Proxy mode -> Maybe BS.ByteString -> IV cipher mode
  ivSize :: (IsCipher cipher) => Proxy cipher -> Proxy mode -> Maybe Int

instance IsMode 'CBC where
  type IV cipher 'CBC = Block cipher
  reflectMode = Tagged CBC
  getIV _ _ (Block iv) = iv
  mkIV _ _ = maybe (error "Expected an IV for CBC") mkBlock
  ivSize (_ :: Proxy cipher) _ = Just $ cipherBlockSize $ untag (reflectCipher @cipher)

instance IsMode 'ECB where
  type IV cipher 'ECB = NoIV
  reflectMode = Tagged ECB
  getIV _ _ NoIV = BS.empty
  mkIV _ _ = maybe NoIV (\_ -> error "Expected no IV for ECB")
  ivSize _ _ = Nothing

instance IsMode 'OFB where
  type IV cipher 'OFB = Block cipher
  reflectMode = Tagged OFB
  getIV _ _ (Block iv) = iv
  mkIV _ _ = maybe (error "Expected an IV for OFB") mkBlock
  ivSize (_ :: Proxy cipher) _ = Just $ cipherBlockSize $ untag (reflectCipher @cipher)

reifyMode :: BlockCipherMode -> (forall mode. IsMode mode => Proxy mode -> a) -> a
reifyMode m f = case m of
  CBC -> f (Proxy @'CBC)
  ECB -> f (Proxy @'ECB)
  OFB -> f (Proxy @'OFB)

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
  c'cipher <- getCipher cipher ECB
  fromIntegral <$> [C.exp| int { EVP_CIPHER_block_size($(EVP_CIPHER* c'cipher)) } |]
{-# NOINLINE cipherBlockSize #-}

-- | The key size of a given `Cipher` in bytes.
cipherKeyLength :: Cipher -> Int
cipherKeyLength cipher = unsafePerformIO $ do
  c'cipher <- getCipher cipher ECB
  fromIntegral <$> [C.exp| int { EVP_CIPHER_key_length($(EVP_CIPHER* c'cipher)) } |]
{-# NOINLINE cipherKeyLength #-}

-- | Whether to enable padding. If disabled, encryption and decryption operations
-- must be given a multiple of `cipherBlockSize` bytes of data.
data PaddingMode
  = EnablePadding
  | DisablePadding
    deriving (Eq, Ord, Show, Enum, Bounded)

data CipherConfig cipher mode = CipherConfig
  { ccPaddingMode :: PaddingMode
  , ccKey :: Key cipher
  , ccIV :: IV cipher mode
  }

ccCipher :: forall cipher mode. IsCipher cipher => CipherConfig cipher mode -> Cipher
ccCipher _ = untag (reflectCipher @cipher)

ccCipherMode :: forall cipher mode. IsMode mode => CipherConfig cipher mode -> BlockCipherMode
ccCipherMode _ = untag (reflectMode @mode)

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
  :: forall m cipher mode. (Monad m, IsCipher cipher, IsMode mode)
  => (ForeignPtr EVP_CIPHER_CTX -> Ptr EVP_CIPHER -> Key cipher -> BS.ByteString -> IO ()) -- init context
  -> (ForeignPtr EVP_CIPHER_CTX -> Ptr Word8 -> Ptr C.CInt -> BS.ByteString -> IO ()) -- update
  -> (ForeignPtr EVP_CIPHER_CTX -> Ptr Word8 -> Ptr C.CInt -> IO ()) -- final
  -> CipherConfig cipher mode
  -> Conduit BS.ByteString m BS.ByteString
crypt initCtx update final conf = unsafeGeneralizeIO $ do
  ctx <- liftIO $ do
    ctx <- mask_ $ do
      ctxPtr <- $(checkPtrExp "EVP_CIPHER_CTX" "EVP_CIPHER_CTX_new()")
      newForeignPtr _EVP_CIPHER_CTX_free ctxPtr

    cipher <- getCipher (ccCipher conf) (ccCipherMode conf)
    -- TODO: check key length
    initCtx ctx cipher (ccKey conf) (getIV (Proxy @cipher) (Proxy @mode) (ccIV conf))
    let padding = case ccPaddingMode conf of
          DisablePadding -> 0
          EnablePadding -> 1
    [checkExp|
      EVP_CIPHER_CTX_set_padding(
        $fptr-ptr:(EVP_CIPHER_CTX* ctx),
        $(int padding)
      ) |]
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
{-# NOINLINE crypt #-}

-- | Encrypt data using a given cipher.
encrypt :: (Monad m, IsCipher cipher, IsMode mode) => CipherConfig cipher mode -> Conduit BS.ByteString m BS.ByteString
encrypt =
  crypt
    (\ctx cipher (Key key) iv ->
      [checkExp|
        EVP_EncryptInit_ex(
          $fptr-ptr:(EVP_CIPHER_CTX* ctx),
          $(EVP_CIPHER* cipher),
          NULL, // pick default impl
          (const uint8_t*) $bs-ptr:key,
          (const uint8_t*) $bs-ptr:iv
      ) |])
    (\ctx outPtr outLenPtr plain ->
      [checkExp|
        EVP_EncryptUpdate(
          $fptr-ptr:(EVP_CIPHER_CTX* ctx),
          $(uint8_t* outPtr),
          $(int* outLenPtr),
          (const uint8_t*) $bs-ptr:plain,
          $bs-len:plain
        ) |])
    (\ctx outPtr outLenPtr ->
      [checkExp|
        EVP_EncryptFinal_ex(
          $fptr-ptr:(EVP_CIPHER_CTX* ctx),
          $(uint8_t* outPtr),
          $(int* outLenPtr)
        ) |])

-- | Decrypt data using a given cipher.
decrypt :: (Monad m, IsCipher cipher, IsMode mode) => CipherConfig cipher mode -> Conduit BS.ByteString m BS.ByteString
decrypt =
  crypt
    (\ctx cipher (Key key) iv ->
      [checkExp|
        EVP_DecryptInit_ex(
          $fptr-ptr:(EVP_CIPHER_CTX* ctx),
          $(EVP_CIPHER* cipher),
          NULL, // pick default impl
          (const uint8_t*) $bs-ptr:key,
          (const uint8_t*) $bs-ptr:iv
      ) |])
    (\ctx outPtr outLenPtr plain ->
      [checkExp|
        EVP_DecryptUpdate(
          $fptr-ptr:(EVP_CIPHER_CTX* ctx),
          $(uint8_t* outPtr),
          $(int* outLenPtr),
          (const uint8_t*) $bs-ptr:plain,
          $bs-len:plain
        ) |])
    (\ctx outPtr outLenPtr ->
      [checkExp|
        EVP_DecryptFinal_ex(
          $fptr-ptr:(EVP_CIPHER_CTX* ctx),
          $(uint8_t* outPtr),
          $(int* outLenPtr)
        ) |])
