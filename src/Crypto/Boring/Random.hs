{-# LANGUAGE NoImplicitPrelude #-}

module Crypto.Boring.Random
  ( randomBytes
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import qualified Language.C.Inline as C
import Foreign

import Crypto.Boring.Internal.Prelude
import Crypto.Boring.Internal.Util

C.include "<openssl/err.h>"
C.include "<openssl/rand.h>"

-- | Generate @n@ bytes of cryptographically random data.
randomBytes :: MonadIO m => Int -> m BS.ByteString
randomBytes len = liftIO $ do
  let c'len = fromIntegral len
  BS.create len $ \bufPtr -> do
    [checkExp|
      RAND_bytes(
        $(uint8_t* bufPtr),
        $(size_t c'len)
      ) |]
