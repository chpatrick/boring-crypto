import Test.Tasty
import Test.Tasty.Ingredients.Basic

import Crypto.Boring.Test.Symmetric
import Crypto.Boring.Test.Random
import Crypto.Boring.Test.Digest

main :: IO ()
main = do
  tests <- testGroup "Crypto.Boring" <$> sequence
    [ pure symmetricTests
    , mkDigestTests
    , pure randomTests
    ]
  defaultMainWithIngredients [ consoleTestReporter ] tests