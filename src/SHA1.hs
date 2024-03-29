{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}

module SHA1 where

import Control.Applicative (liftA2)
import Data.BitVector as BV hiding (index)
import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC8
import Data.List (unfoldr)
import Data.Word

-- 0.0.0 : 80 seconds, 99% work
-- 0.0.1 : 2 seconds, 95% work
main :: String
main = hashString $ Prelude.replicate 65536 'a'

-- User-facing functions.

hashString :: String -> String
hashString xs = makeNice (hash . parse . pad . fromString $ xs)

-- Implementation.

(<&&>) :: (Integral a) => (a -> Bool) -> (a -> Bool) -> a -> Bool
(<&&>) = liftA2 (&&)

sha1Function :: (Bits a) => Integer -> a -> a -> a -> a
sha1Function t x y z
  | (>= 0) <&&> (<= 19) $ t = ch x y z
  | (>= 20) <&&> (<= 39) $ t = parity x y z
  | (>= 40) <&&> (<= 59) $ t = maj x y z
  | (>= 60) <&&> (<= 79) $ t = parity x y z
  | otherwise = error "exceeded function bounds in SHA1 function"

sha1Constants :: (Num a) => Integer -> a
sha1Constants t
  | (>= 0) <&&> (<= 19) $ t = 0x5a827999
  | (>= 20) <&&> (<= 39) $ t = 0x6ed9eba1
  | (>= 40) <&&> (<= 59) $ t = 0x8f1bbcdc
  | (>= 60) <&&> (<= 79) $ t = 0xca62c1d6
  | otherwise = error "exceeded function bounds in SHA1 constants"

ch :: (Bits a) => a -> a -> a -> a
ch x y z = (x .&. y) `xor` (complement x .&. z)

parity :: (Bits a) => a -> a -> a -> a
parity x y z = x `xor` y `xor` z

maj :: (Bits a) => a -> a -> a -> a
maj x y z = (x .&. y) `xor` (x .&. z) `xor` (y .&. z)

-- SHA1 Preprocessing.

fromString :: String -> BV
fromString string = fromByteString (BSC8.pack string)

fromByteString :: BS.ByteString -> BV
fromByteString bs =
  let word8s = BS.unpack bs
   in (BV.join . fmap fromIntegral) word8s

pad :: BV -> BV
pad bv =
  let bvAppend1 = bv # bitVec 1 (1 :: Int)
   in bvAppend1
        # zeros ((448 - size bvAppend1) `mod` 512)
        #
        -- l + 1 + k = 448 mod 512
        -- k = (448 - (l + 1)) mod 512
        bitVec 64 (size bv)

parse :: BV -> [[BV]]
parse bv = group (32 :: Int) <$> group (512 :: Int) bv

type HashValue = (Word32, Word32, Word32, Word32, Word32)

h0 :: HashValue
h0 =
  ( 0x67452301
  , 0xefcdab89
  , 0x98badcfe
  , 0x10325476
  , 0xc3d2e1f0
  )

-- Hashing.

hash :: [[BV]] -> HashValue
hash = Prelude.foldl fullRound h0

-- `fullRound h0 (group 32 $ pad (fromString "abc"))` should
-- spit out:
-- ["0x42541b35","0x5738d5e1","0x21834873","0x681e6df6","0x0d8fdf6ad"]
fullRound :: HashValue -> [BV] -> HashValue
fullRound hashval block =
  add5tuple hashval $
    (fst . last) $
      unfoldr
        ( \hvt@(hv, t) ->
            let next (_, index) = (SHA1.round hv block index, index + 1)
                offset = 2 -- God himself told me to do this, I think.
             in if t == (79 + offset) -- How did I mess this up?
                  then Nothing
                  else Just (hvt, next hvt)
        )
        (hashval, 0)

round :: HashValue -> [BV] -> Integer -> HashValue
round (a, b, c, d, e) block t =
  let schedule = messageSchedule' block
      bigT = rotate a 5 + sha1Function t b c d + e + sha1Constants t + fromIntegral (schedule !! fromIntegral t)
   in (bigT, a, rotate b 30, c, d)

makeNice :: HashValue -> String
makeNice (a, b, c, d, e) = showHex . join $ fmap (bitVec 32) [a, b, c, d, e]

messageSchedule' :: [BV] -> [BV]
messageSchedule' block =
  (++) block . tail $
    scanWithHistory func nil [16 .. 79] block
 where
  func _ index blockHist =
    let b = blockHist
     in flip rotate 1 $
          foldl1
            xor
            [ b !! (index - 3)
            , b !! (index - 8)
            , b !! (index - 14)
            , b !! (index - 16)
            ]

-- This is a poor man's histomorphism.
scanWithHistory :: (a -> t -> [a] -> a) -> a -> [t] -> [a] -> [a]
scanWithHistory func start list hist =
  start
    : ( case list of
          [] -> []
          x : xs ->
            let next = func start x hist
             in scanWithHistory func next xs (hist ++ pure next)
      )

-- There's a generics way to do this probably.
add5tuple ::
  (Num a, Num b, Num c, Num d, Num e) =>
  (a, b, c, d, e) ->
  (a, b, c, d, e) ->
  (a, b, c, d, e)
add5tuple (a, b, c, d, e) (f, g, h, i, j) = (a + f, b + g, c + h, d + i, e + j)
