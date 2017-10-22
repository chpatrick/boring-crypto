module Crypto.Boring.Internal.Util
  ( checkRes
  , unsafeGeneralizeIO
  , checkExp
  , checkPtrExp
  ) where

import Data.Conduit
import Data.IORef
import Data.List
import Data.Monoid
import Foreign
import Foreign.C
import Numeric
import Control.Exception.Safe
import Language.C.Inline as C
import Language.Haskell.TH.Quote
import Language.Haskell.TH

import Crypto.Boring.Exception
import Crypto.Boring.Internal.Context

import System.IO.Unsafe

C.context cryptoCtx

C.include "<openssl/err.h>"

unsafeGeneralizeIO :: Monad m => ConduitM i o IO r -> ConduitM i o m r
unsafeGeneralizeIO = transPipe (return . unsafePerformIO)
{-# NOINLINE unsafeGeneralizeIO #-}

checkRes :: (FunPtr ErrorCallback -> IO CInt) -> IO ()
checkRes cont = do
  errorsRef <- newIORef mempty

  let errorCb errPtr errLen _ = do
        errString <- peekCStringLen ( errPtr, fromIntegral errLen )
        let splitError str = case break (==':') str of
              ( x, ":" ) -> [ x ]
              ( x, ':' : rest ) -> x : splitError rest
              _ -> []

        print (splitError errString)

        err <- case splitError errString of
          _ : "error" : codeHex : libName : "OPENSSL_internal" : reasonString : file : lineStr : extraStrings
            | [ ( code, "" ) ] <- readHex codeHex
            , [ ( lineNo, "" ) ] <- reads lineStr ->
            return BoringSslError
              { beLibrary = libName
              , beErrorCode = code
              , beReasonString = reasonString
              , beFile = file
              , beLineNumber = lineNo
              , beExtraStrings = intercalate ":" extraStrings
              }

          _ -> fail "Could not parse BoringSSL error!"

        modifyIORef' errorsRef (<> Endo (err:))
        return 1
  errorCbPtr <- $(C.mkFunPtr [t|ErrorCallback|]) errorCb
  res <- cont errorCbPtr
  case res of
    1 -> return ()
    0 -> do
      errorsEndo <- readIORef errorsRef
      throwIO (CryptoException (appEndo errorsEndo []))
    _ -> error "Unexpected return value."

checkExp :: QuasiQuoter
checkExp = QuasiQuoter
  { quoteExp = \expStr -> do
      errorCb <- newName "errorCb"
      let inlineCStr = unlines
            [ "int {"
            , "  int res = " ++ expStr ++ ";"
            , "  if (res == 0) {"
            , "    ERR_print_errors_cb($(int (*" ++ nameBase errorCb ++ ")(const char*, size_t, void*)), NULL);"
            , "  }"
            , "  return res;"
            , "}"
            ]
      [e| checkRes $ \ $(varP errorCb) -> $(quoteExp C.block inlineCStr) |]

  , quotePat = unsupported
  , quoteType = unsupported
  , quoteDec = unsupported
  } where
    unsupported _ = fail "Unsupported quasiquotation."

checkPtrExp :: String -> String -> ExpQ
checkPtrExp ptrType expStr = do
  errorCb <- newName "errorCb"
  resPtrPtr <- newName "resPtrPtr"
  let inlineCStr = unlines
        [ "int {"
        , "  " ++ ptrType ++ "* res = " ++ expStr ++ ";"
        , "  if (res == NULL) {"
        , "    ERR_print_errors_cb($(int (*" ++ nameBase errorCb ++ ")(const char*, size_t, void*)), NULL);"
        , "    return 0;"
        , "  }"
        , "  *$(" ++ ptrType ++ "** " ++ nameBase resPtrPtr ++ ") = res;"
        , "  return 1;"
        , "}"
        ]
  [e| C.withPtr_ $ \ $(varP resPtrPtr) -> checkRes $ \ $(varP errorCb) -> $(quoteExp C.block inlineCStr) |]