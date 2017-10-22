import Test.Tasty

import Crypto.Boring.Test.Symmetric
import Crypto.Boring.Test.Random
import Crypto.Boring.Test.Digest

main :: IO ()
main = do
  tests <- testGroup "Crypto.Boring" <$> sequence
    [ mkSymmetricTests
    , mkDigestTests
    , pure randomTests
    ]
  defaultMain tests