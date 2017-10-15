{-# LANGUAGE NoMonomorphismRestriction #-}

module Crypto.Boring.Test.TestVectors
  ( getTestVectors
  , cavsVectors
  , monteCarloVectors
  , vectorString
  , toHex
  ) where

import Control.Applicative
import Control.Exception (throwIO)
import Control.Monad
import Numeric
import Text.Megaparsec
import Text.Megaparsec.ByteString
import qualified Text.Megaparsec.Lexer as MPL
import qualified Data.ByteString as BS
import Path

type TestVectors = [ ( BS.ByteString, BS.ByteString ) ]
type MonteCarloVectors = ( BS.ByteString, [ BS.ByteString ] )

hexString :: Parser BS.ByteString
hexString = fmap BS.pack $ some $ do
  nibbles <- replicateM 2 hexDigitChar
  case readHex nibbles of
    [ ( val, "" ) ] -> return val
    _ -> fail "hexadecimal byte"

skipSpace :: Parser ()
skipSpace = MPL.space
  (void spaceChar)
  (MPL.skipLineComment "#")
  empty

lexeme :: Parser a -> Parser a
lexeme = MPL.lexeme skipSpace

param :: String -> Parser a -> Parser a
param name value = do
  _ <- lexeme $ string name
  _ <- lexeme $ char '='
  lexeme value

cavsVectors :: Parser TestVectors
cavsVectors = do
  let vector mbMdLen = do
        len <- param "Len" MPL.integer
        msg <- param "Msg" hexString
        md <- param "MD" hexString
        realMsg <-
          if
            | maybe False (/= BS.length md) mbMdLen -> fail "invalid Md length" 
            | len == 0 && msg == BS.singleton 0 -> return BS.empty
            | BS.length msg * 8 /= fromIntegral len -> fail "invalid Msg length"
            | otherwise -> return msg 
        return ( realMsg, md )

  skipSpace
  
  mbMdLen <- optional $ do
    void $ lexeme $ string "[L"
    void $ lexeme $ char '='
    mdLen <- lexeme MPL.integer
    void $ lexeme $ char ']'
    skipSpace
    return (fromIntegral mdLen)

  vecs <- many (vector mbMdLen <* skipSpace)
  eof
  return vecs

monteCarloVectors :: Parser MonteCarloVectors
monteCarloVectors = do
  skipSpace
  
  mbMdLen <- optional $ do
    void $ lexeme $ string "[L"
    void $ lexeme $ char '='
    mdLen <- lexeme MPL.integer
    void $ lexeme $ char ']'
    skipSpace
    return (fromIntegral mdLen)

  let vectors curCount = do
        vecCount <- param "COUNT" MPL.integer
        unless (vecCount == curCount) $ fail "Invalid COUNT"
        md <- param "MD" hexString
        when (maybe False (/= BS.length md) mbMdLen) $
          fail "invalid Md length" 

        mds <- option [] $ vectors (curCount + 1)
        return (md : mds)

  seed <- param "Seed" hexString
  vecs <- vectors 0 
  eof
  return ( seed, vecs )

getTestVectors :: Parser a -> Path Rel File -> IO a
getTestVectors parser path = do
  let basePath = $(mkRelDir "third_party/python-cryptography/vectors/cryptography_vectors")
  vecString <- BS.readFile $ toFilePath (basePath </> path)
  case runParser parser (toFilePath path) vecString of
    Left err -> throwIO err
    Right vectors -> return vectors

toHex :: BS.ByteString -> String
toHex bs = flip concatMap (BS.unpack bs) $ \d -> case showHex d "" of
      [ l ] -> [ '0', l ]
      hl -> hl

vectorString :: ( BS.ByteString, BS.ByteString ) -> String
vectorString ( input, output ) = trimmedInput ++ " -> " ++ toHex output
  where
    inputHex = toHex input
    trimmedInput
      | length inputHex > 50 = take 50 inputHex ++ "..."
      | otherwise = inputHex
