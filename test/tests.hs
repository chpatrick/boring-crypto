import Test.Tasty
import Test.Tasty.Ingredients.Basic (consoleTestReporter)

import Crypto.Boring.Test.Symmetric
import Crypto.Boring.Test.Random

tests :: TestTree
tests = testGroup "Crypto.Boring"
  [ symmetricTests
  , randomTests
  ]

main :: IO ()
main = defaultMainWithIngredients [ consoleTestReporter ] tests