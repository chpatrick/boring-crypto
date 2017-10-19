{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE TypeFamilies #-}

-- This tool builds and tests BoringSSL in third_party/boringssl, and if
-- they pass, copies the source files to cbits and generates the cabal fo rit.

-- It requires CMake, Go, Perl and Ninja to run.

import Control.Applicative
import Control.Exception
import Control.Monad
import Data.Char
import Data.List
import Data.Foldable
import Path
import Path.IO
import System.Exit
import System.Process
import System.Posix.Files (createSymbolicLink)
import Text.Megaparsec
import Text.Megaparsec.Char
import qualified Text.Megaparsec.Char.Lexer as L
import Data.Void

parseBazel :: Parsec Void String [ ( String, [ Path Rel File ] ) ]
parseBazel = do
  let skipSpace =
        L.space
          (void spaceChar)
          (L.skipLineComment "#")
          empty

  let lexeme = L.lexeme skipSpace
  let symbol sym = void $ L.symbol skipSpace sym

  skipSpace

  fileLists <- many $ do
    listName <- lexeme (some $ satisfy (not . isSpace))
    symbol "="
    let file = do
          path <- lexeme (char '"' *> manyTill L.charLiteral (char '"'))
          case parseRelFile path of
            Nothing -> fail "Expected relative file path."
            Just relPath -> return relPath
    files <-
      between (symbol "[") (symbol "]")
        $ sepEndBy
          file
          (symbol ",")
    return ( listName, files )

  eof

  return fileLists

exec :: String -> [ String ] -> Path Abs Dir -> IO ()
exec cmd args procCwd = do
  let cp = (proc cmd args)
        { cwd = Just (toFilePath procCwd)
        }
  withCreateProcess cp $ \_ _ _ hnd -> do
    exit <- waitForProcess hnd
    case exit of
      ExitSuccess -> return ()
      ExitFailure code -> fail (intercalate " " (cmd : args) ++ " failed with code " ++ show code)

main :: IO ()
main = do
  let cbitsRel = $(mkRelDir "cbits")
  cbitsDir <- makeAbsolute cbitsRel
  removeDirRecur cbitsDir
  createDir cbitsDir

  boringSslDir <- resolveDir' "third_party/boringssl"

  putStrLn "Running tests..."
  withSystemTempDir "boring-ssl-build" $ \buildDir -> do
    exec "cmake" [ "-GNinja", toFilePath boringSslDir ] buildDir
    exec "ninja" [ "run_tests" ] buildDir

  putStrLn "Copying source files..."
  withSystemTempDir "boring-ssl-unpack" $ \tmpDir -> do
    let srcDirLink = tmpDir </> $(mkRelFile "src")
    createSymbolicLink (toFilePath boringSslDir) (toFilePath srcDirLink)
    exec "python2" [ "src/util/generate_build_files.py", "bazel" ] tmpDir
    let bazelFile = toFilePath (tmpDir </> $(mkRelFile "BUILD.generated.bzl"))
    bazelStr <- readFile bazelFile
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