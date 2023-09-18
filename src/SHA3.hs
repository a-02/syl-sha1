{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}

module SHA3 where

import Control.Applicative (liftA2)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC8
import Data.Bits
import Data.BitVector as BV hiding (index)
import Data.List (unfoldr)
import Data.Word

x :: a
x = x
