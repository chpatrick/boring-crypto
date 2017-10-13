module Crypto.Boring.Exception
  ( CryptoException(..)
  ) where

import Control.Exception

newtype CryptoException = CryptoException String
  deriving Show

instance Exception CryptoException