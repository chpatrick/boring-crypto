{-# LANGUAGE NoImplicitPrelude #-}

module Crypto.Boring.Random
  ( genRandom
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import qualified Language.C.Inline as C
import Foreign

import Crypto.Boring.Internal.Prelude
import Crypto.Boring.Exception

C.include "<sys/random.h>"
C.include "<stdint.h>"

-- TODO: support other platforms

genRandom :: Int -> IO BS.ByteString
genRandom len = do
  let c'len = fromIntegral len
  BS.create len $ \bufPtr -> do
    success <- [C.block| int {
      const size_t target = $(size_t c'len);
      uint8_t* buf = $(uint8_t* bufPtr);
      size_t totalRead = 0;

      while (totalRead < target) {
        // getrandom can be interrupted and return less than len bytes,
        // so loop until we've filled the buffer
        const ssize_t res = getrandom(buf + totalRead, target - totalRead, 0);

        if (res < 0) {
          return 0;
        }

        totalRead += res;
      }

      return 1;

      } |]

    unless (toBool success) $
      throwM $ CryptoException "Random number generation failed!"