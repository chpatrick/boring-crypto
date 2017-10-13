{-# LANGUAGE NoImplicitPrelude #-}

module Crypto.Boring.Internal.Context
  ( EVP_CIPHER_CTX
  , EVP_CIPHER
  , EVP_MD_CTX
  , EVP_MD
  , HMAC_CTX
  , cryptoCtx
  ) where

import qualified Data.Map as M
import qualified Language.C.Inline as C
import qualified Language.C.Inline.Context as C
import qualified Language.C.Types as C

import Crypto.Boring.Internal.Prelude

data EVP_MD_CTX
data EVP_MD
data EVP_CIPHER_CTX
data EVP_CIPHER

data HMAC_CTX

cryptoCtx :: C.Context
cryptoCtx = C.baseCtx <> C.bsCtx <> C.fptrCtx <> mempty
  { C.ctxTypesTable = M.fromList
      [ ( C.TypeName "EVP_MD_CTX", [t|EVP_MD_CTX|] )
      , ( C.TypeName "EVP_MD", [t|EVP_MD|] )

      , ( C.TypeName "EVP_CIPHER_CTX", [t|EVP_CIPHER_CTX|] )
      , ( C.TypeName "EVP_CIPHER", [t|EVP_CIPHER|] )

      , ( C.TypeName "HMAC_CTX", [t|HMAC_CTX|] )
      ]
  }