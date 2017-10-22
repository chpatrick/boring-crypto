module Crypto.Boring.Exception
  ( BoringSslError(..)
  , CryptoException(..)
  ) where

import Control.Exception

data BoringSslError = BoringSslError
  { beErrorCode :: Int
  , beLibrary :: String
  , beFile :: FilePath
  , beLineNumber :: Int
  , beReasonString :: String
  , beExtraStrings :: String
  } deriving (Eq, Ord, Show)

newtype CryptoException = CryptoException [ BoringSslError ]
  deriving Show

instance Exception CryptoException