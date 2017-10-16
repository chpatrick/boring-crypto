{-# LANGUAGE NoMonomorphismRestriction #-}

module Crypto.Boring.Test.TestVectors
  ( getTestVectors
  , HashVector(..)
  , hashVectors
  , MonteCarloVectors(..)
  , monteCarloVectors
  , MacVector(..)
  , macVectors
  ) where

import Control.Applicative
import Control.Exception (throwIO)
import Control.Monad
import Data.Void
import Numeric
import Text.Megaparsec
import Text.Megaparsec.Char
import qualified Text.Megaparsec.Char.Lexer as L
import qualified Data.ByteString as BS
import Path

data HashVector = HashVector
  { hvInput :: BS.ByteString
  , hvDigest :: BS.ByteString
  }

data MonteCarloVectors = MonteCarloVectors
  { mcvSeed :: BS.ByteString
  , mcvIterations :: [ BS.ByteString ]
  }

data MacVector = MacVector
  { mvKey :: BS.ByteString
  , mvInput :: BS.ByteString
  , mvDigest :: BS.ByteString
  }

type Parser = Parsec Void String

hexString :: Parser BS.ByteString
hexString = fmap BS.pack $ some $ do
  nibbles <- replicateM 2 hexDigitChar
  case readHex nibbles of
    [ ( val, "" ) ] -> return val
    _ -> fail "hexadecimal byte"

skipSpace :: Parser ()
skipSpace = L.space
  (void spaceChar)
  (L.skipLineComment "#")
  empty

lexeme :: Parser a -> Parser a
lexeme = L.lexeme skipSpace

param :: String -> Parser a -> Parser a
param name value = do
  _ <- lexeme $ string name
  _ <- lexeme $ char '='
  lexeme value

hashVectors :: Parser [ HashVector ]
hashVectors = do
  skipSpace
  
  mbMdLen <- optional $ do
    void $ lexeme $ string "[L"
    void $ lexeme $ char '='
    mdLen <- lexeme L.decimal
    void $ lexeme $ char ']'
    skipSpace
    return mdLen

  let vector = do
        len <- param "Len" L.decimal
        msg <- param "Msg" hexString
        md <- param "MD" hexString
        realMsg <-
          if
            | maybe False (/= BS.length md) mbMdLen -> fail "invalid Md length" 
            | len == 0 && msg == BS.singleton 0 -> return BS.empty
            | BS.length msg * 8 /= len -> fail "invalid Msg length"
            | otherwise -> return msg 
        return HashVector
          { hvInput = realMsg
          , hvDigest = md
          }

  vecs <- many (vector <* skipSpace)
  eof
  return vecs

monteCarloVectors :: Parser MonteCarloVectors
monteCarloVectors = do
  skipSpace
  
  mbMdLen <- optional $ do
    void $ lexeme $ string "[L"
    void $ lexeme $ char '='
    mdLen <- lexeme L.decimal
    void $ lexeme $ char ']'
    skipSpace
    return mdLen

  let vectors curCount = do
        vecCount <- param "COUNT" L.decimal
        unless (vecCount == curCount) $ fail "Invalid COUNT"
        md <- param "MD" hexString
        when (maybe False (/= BS.length md) mbMdLen) $
          fail "invalid Md length" 

        mds <- option [] $ vectors (curCount + 1)
        return (md : mds)

  seed <- param "Seed" hexString
  vecs <- vectors (0 :: Int)
  eof
  return $ MonteCarloVectors
    { mcvSeed = seed
    , mcvIterations = vecs
    }

macVectors :: Parser [ MacVector ]
macVectors = do
  skipSpace

  mbMdLen <- optional $ do
    void $ lexeme $ string "[L"
    void $ lexeme $ char '='
    mdLen <- lexeme L.decimal
    void $ lexeme $ char ']'
    skipSpace
    return mdLen

  let vector = do
        len <- param "Len" L.decimal
        key <- param "Key" hexString
        msg <- param "Msg" hexString
        md <- param "MD" hexString
        realMsg <-
          if
            | maybe False (/= BS.length md) mbMdLen -> fail "invalid Md length"
            | len == 0 && msg == BS.singleton 0 -> return BS.empty
            | BS.length msg * 8 /= len -> fail "invalid Msg length"
            | otherwise -> return msg
        return MacVector
          { mvKey = key
          , mvInput = realMsg
          , mvDigest = md
          }

  vecs <- many (vector <* skipSpace)
  eof
  return vecs

getTestVectors :: Parser a -> Path Rel File -> IO a
getTestVectors parser path = do
  let basePath = $(mkRelDir "third_party/python-cryptography/vectors/cryptography_vectors")
  vecString <- readFile $ toFilePath (basePath </> path)
  case runParser parser (toFilePath path) vecString of
    Left err -> throwIO err
    Right vectors -> return vectors
