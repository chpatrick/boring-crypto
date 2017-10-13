module Crypto.Boring.Test.Random
  ( randomTests
  ) where

import Control.Monad.IO.Class
import qualified Data.ByteString as BS
import Test.QuickCheck
import Test.QuickCheck.Monadic
import Test.Tasty
import Test.Tasty.QuickCheck

import Crypto.Boring.Random

randomReturnsCorrectLength :: Property
randomReturnsCorrectLength = monadicIO $ do
  size <- pick (sized return)
  buf <- liftIO $ genRandom size
  return (BS.length buf === size)

randomTests :: TestTree
randomTests = testGroup "Random"
  [ testProperty "genRandom returns correct length" randomReturnsCorrectLength
  ]