{-# LANGUAGE NoImplicitPrelude #-}

module Crypto.Boring.Random
  ( randomBytes
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import qualified Language.C.Inline as C
import Foreign

import Crypto.Boring.Internal.Prelude
import Crypto.Boring.Exception

C.include "<openssl/rand.h>"

randomBytes :: MonadIO m => Int -> m BS.ByteString
randomBytes len = liftIO $ do
  let c'len = fromIntegral len
  BS.create len $ \bufPtr -> do
    success <- [C.exp| int {
      RAND_bytes($(uint8_t* bufPtr), $(size_t c'len))
      } |]

    unless (toBool success) $
      throwM $ CryptoException "Random number generation failed!"