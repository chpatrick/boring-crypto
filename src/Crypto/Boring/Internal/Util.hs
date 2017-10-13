module Crypto.Boring.Internal.Util
  ( checkRes
  , unsafeGeneralizeIO
  ) where

import Control.Monad.Morph
import Foreign.C
import Control.Exception.Safe

import Crypto.Boring.Exception

import System.IO.Unsafe

unsafeGeneralizeIO :: (MFunctor t, Monad m) => t IO a -> t m a
unsafeGeneralizeIO = hoist (return . unsafePerformIO)

checkRes :: MonadThrow m => String -> m CInt -> m ()
checkRes name m = do
  res <- m
  case res of
    1 -> return ()
    0 -> throw (CryptoException (name ++ " failed"))
    _ -> error "Unexpected return value."
