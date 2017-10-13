module Crypto.Boring.Internal.Util
  ( checkRes
  , unsafeGeneralizeIO
  ) where

import Data.Conduit
import Foreign.C
import Control.Exception.Safe

import Crypto.Boring.Exception

import System.IO.Unsafe

unsafeGeneralizeIO :: Monad m => ConduitM i o IO r -> ConduitM i o m r
unsafeGeneralizeIO = transPipe (return . unsafePerformIO)

checkRes :: MonadThrow m => String -> m CInt -> m ()
checkRes name m = do
  res <- m
  case res of
    1 -> return ()
    0 -> throw (CryptoException (name ++ " failed"))
    _ -> error "Unexpected return value."
