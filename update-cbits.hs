{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE TypeFamilies #-}

import Control.Applicative
import Control.Exception
import Control.Monad
import qualified Data.ByteString as BS
import Data.Char
import Data.List
import Data.Foldable
import Path
import Path.IO
import System.Directory (createDirectoryLink)
import System.Process
import Text.Megaparsec
import Text.Megaparsec.ByteString
import Text.Megaparsec.Char
import qualified Text.Megaparsec.Lexer as L

parseBazel :: Parser [ ( String, [ Path Rel File ] ) ] 
parseBazel = do
  let skipSpace =
        L.space
          (void spaceChar)
          (L.skipLineComment "#")
          empty

  let lexeme = L.lexeme skipSpace
  let symbol = L.symbol skipSpace

  skipSpace

  fileLists <- many $ do
    listName <- lexeme (some $ satisfy (not . isSpace))
    symbol "="
    let file = do
          path <- lexeme (char '"' *> manyTill L.charLiteral (char '"'))
          case parseRelFile path of
            Nothing -> fail "Expected relative file path."
            Just path -> return path
    files <-
      between (symbol "[") (symbol "]")
        $ sepEndBy
          file
          (symbol ",")
    return ( listName, files )

  eof

  return fileLists


main :: IO ()
main = do
  let cbitsRel = $(mkRelDir "cbits")
  cbitsDir <- makeAbsolute cbitsRel
  removeDirRecur cbitsDir
  createDir cbitsDir

  withSystemTempDir "boring-ssl-unpack" $ \tmpDir -> do
    boringSslDir <- resolveDir' "third_party/boringssl"
    let srcDirLink = tmpDir </> $(mkRelFile "src")
    createDirectoryLink (toFilePath boringSslDir) (toFilePath srcDirLink)
    _ <- readCreateProcess (proc "python2" [ "src/util/generate_build_files.py", "bazel" ])
      { cwd = Just (toFilePath tmpDir)
      } ""
    let bazelFile = toFilePath (tmpDir </> $(mkRelFile "BUILD.generated.bzl"))
    bazelStr <- BS.readFile bazelFile
    fileLists <- case parse parseBazel bazelFile bazelStr of
      Left err -> throwIO err
      Right lists -> return lists
    
    for_ fileLists $ \( listName, files ) -> do
      when ("crypto_" `isPrefixOf` listName || listName == "fips_fragments") $
        for_ files $ \file -> do
          let srcAbs = tmpDir </> file
          let dstAbs = cbitsDir </> file
          ensureDir (parent dstAbs)
          copyFile srcAbs dstAbs

    let licenseRel = $(mkRelFile "LICENSE")
    copyFile
      (boringSslDir </> licenseRel)
      (cbitsDir </> licenseRel)

    let sourceFiles listName = case lookup listName fileLists of
          Nothing -> error "Invalid list name."
          Just files -> map (\fileRel -> toFilePath (cbitsRel </> fileRel)) files

    let extraSourceHosts =
          [ ( "linux", "linux", [ "aarch64", "arm", "ppc64le", "x86", "x86_64" ] )
          , ( "mac", "darwin", [ "x86", "x86_64" ] )
          , ( "win", "windows", [ "x86", "x86_64" ] )
          ]

    putStrLn $ unlines
      ([ "c-sources:"
      ] ++ map ("  " ++) (sourceFiles "crypto_sources")
        ++ do
          ( boringName, cabalName, arches ) <- extraSourceHosts
          arch <- arches
          [ "if os(" ++ cabalName ++ ") && arch(" ++ arch ++ ")"
            , "  c-sources:"
            ] ++ map ("    " ++) (sourceFiles ("crypto_sources_" ++ boringName ++ "_" ++ arch))
      )