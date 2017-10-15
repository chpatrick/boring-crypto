import Test.Tasty
import Test.Tasty.Ingredients.Basic (consoleTestReporter)

import Crypto.Boring.Test.Symmetric
import Crypto.Boring.Test.Random
import Crypto.Boring.Test.Digest

main :: IO ()
main = do
  tests <- fmap (testGroup "Crypto.Boring") $ sequence
    [ pure symmetricTests
    , mkDigestTests
    , pure randomTests
    ]
  defaultMainWithIngredients [ consoleTestReporter ] tests