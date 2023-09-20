{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}

module SHA3 where

import Control.Applicative (liftA2)
import Control.Monad
import Control.Monad.ST
import Data.Bit
import Data.Bits (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC8
import qualified Data.Vector as V
import qualified Data.Vector.Unboxed as U
import qualified Data.Vector.Unboxed.Mutable as MU
import Data.Word

-- 2.2 Algorithm Parameters & Other Variables
--
-- A - state array
-- A[x,y,z] - bit @ (x,y,z) in array A
-- b - width of keccak-p perm in bits
-- c - sponge function capacity
-- d - length of a hash function
-- f - generic underlying function for sponge construction
-- ir - round index for keccak-p perm
-- J - RawSHAKE input string
-- l - for keccak-p, binary log of lane size (log2(w))
-- Lane(i,j) - for array A, a string of bits of the lane where (x,y) = (i,j)
-- M - input string for SHA3 (or, message)
-- N - input string for SPONGE[f,pad,r] or KECCAK[c]
-- nr - number of rounds for keccak-p
-- pad - generic padding rule for sponge construction
-- Plane(j) - for array A, string of bits of the plane whose y coordinate is j
-- r - rate of the sponge function
-- RC - for a keccak-p round, the "round constant"
-- w - lane size of a keccak-p permutation, aka b/25
--
-- 2.3 Basic Operations and Functions
--
-- 0s - for positive integer s, 0s is a string of consecutive 0's of length s
-- len(x) - length
-- X[i] - for string X and int i, 0 <= i < len(x), X[i] is x !! i, 0-indexed
-- Trunc(s)(X) - for +int s and string X, bits X[0] to X[s-1]
--   ex: Trunc(2)(10010) = 10
--
-- 2.4 Specified Functoins
--
-- theta, rho, pi, xi, iota - five step mappings that comprise a round
-- keccak[c] - keccak isntance with keccak-f[1600] as underlying perm with capacity c
-- keccak-f[b] - family of 7 perms as the underlying function for keccak.
--   the set values for the width b for perms is
--   {25,50,100,200,400,800,1600}
-- pad10*1 - multi-rate padding rule. 1, then 0s, then 1
-- rc - generates round constants
-- Rnd - round function for keccak-p
-- SPONGE[f,pad,r] - sponge function with function f, padding rule pad, rate r
--
-- 3 keccak-p permutations
--
-- permutations have 2 parameters.
--     1) the length of the strings that are permuted (the WIDTH)
--     2) the number of iteratoins of the internal transformation (the ROUND)
-- width is denoted by `b`. number of rounds is `n`.
-- keccak-p with n rounds and width b is keccakp[b,n]. defined for any
-- b in [25,50,100,200,400,800,1600], any +int n.
-- a round of keccak-p (called Rnd) is 5 transofrmations, called STEP MAPPINGs.
-- the permutatoin is defined in terms of an array of b bits that is updated
-- called the 'state". it gets repeatedly updated. you get it.
--
-- the keccak-p is comprised of b bits. w is b/25. l is log2(b/25)
-- input/output of permutations are b-bit strings.
-- '' of step mappings is 5 x 5 x w arrays.
-- theyre 0-indexed too, so a state array is all the bits ([0..4], [0..4], [0..w-1]
--
-- state  - any (x,y,z)
-- plane  - all values with the same Y
-- slice  - all values with the same Z
-- sheet  - all vlaues with the same X
-- row    - all values with the same Y, Z
-- column - all vlaues with the same X, Z
-- lane   - all values with the same X, Y
-- bit    - an (x,y,z)
--
-- arrays to strings
-- A[x,y,z] = S[w(5y+x)+z]
--
-- strings to arrays
-- Lane(i,j) = A[i,j,0] .. A[i,j,w-1]
--
-- Plane(j) = Lane(0,j) .. Lane(4,j)
--
-- S = Plane(0) .. Plane(4)
--
-- oh btw btw
--
-- xor on lists ziplists em
-- jsyk

data ArraySlice
  = Plane Int
  | Slice Int
  | Sheet Int
  | Row Int Int
  | Column Int Int
  | Lane Int Int
  | Point Int Int Int

arrayToString :: Int -> Int -> Int -> Int -> Int
arrayToString w x y z = w * (5 * y + x) + z

stringToArray :: Int -> Int -> (Int, Int, Int)
stringToArray w i =
  (,,)
    (((i - z) `div` w) `rem` 5)
    (((i - z) `div` w) `div` 5)
    z
 where
  z = i `mod` w

bySlice :: Int -> ArraySlice -> Vector Int
bySlice w as =
  U.fromList $
    let str x1 y1 z1 = (w * (5 * y1 + x1)) + z1
        xs = [0 .. 4]
        ys = [0 .. 4]
        zs = [0 .. (w - 1)]
     in case as of
          (Plane y) -> (\(x, z) -> str x y z) <$> liftA2 (,) xs zs
          (Slice z) -> (\(x, y) -> str x y z) <$> liftA2 (,) xs ys
          (Sheet x) -> uncurry (str x) <$> liftA2 (,) ys zs
          (Row y z) -> (\x -> str x y z) <$> xs
          (Column x z) -> (\y -> str x y z) <$> ys
          (Lane x y) -> str x y <$> zs
          (Point x y z) -> [str x y z]

-- step mapping 1: theta
--
-- step 1: generating C[x,z]
-- for all pairs (x,z)
-- C[x,z] = foldl1 xor $ A[x,0,z] .. A[x,4,z]
theta :: U.Vector Bit -> U.Vector Bit
theta array = runST $ do
  let w = U.length array `div` 25
      b = U.length array
      bigC x1 z1 = U.foldl1 xor ((array U.!) `U.map` bySlice w (Column x1 z1))
      bigD x2 z2 =
        xor
          (bigC (x2 - 1 `mod` 5) z2)
          (bigC (x2 + 1 `mod` 5) (z2 - 1 `mod` 5))
  newArray <- MU.generate b ((\(x, _, z) -> bigD x z) . stringToArray w)
  zipInPlace xor array newArray
  U.freeze newArray

rhoOffsets :: [Int]
rhoOffsets =
  [ 0
  , 1
  , 190
  , 28
  , 91
  , 36
  , 300
  , 6
  , 55
  , 276
  , 3
  , 10
  , 171
  , 153
  , 231
  , 105
  , 45
  , 15
  , 21
  , 136
  , 210
  , 66
  , 253
  , 120
  , 71
  ]

-- generates indexes for where the bits should be moved to
rhoBack :: Int -> U.Vector Int
rhoBack w =
  -- w copies of [0..24], each times w.
  -- [0,0,0...64,64,64...128,128,128... if w=64
  -- a & b are the same length; 25 * w = w * 25.
  let a = concatMap (fmap (* w) . replicate w) [0 .. 24]
      b =
        concat $
          zipWith
            -- add the offset to each number, then mod by w
            -- [0,1,2,3...1,2,3,4...190,191,192...
            (\x y -> fmap ((`mod` w) . (+ x)) y)
            -- how much are we offsetting each lane by, in order
            -- goes from (0,0) to (4,4)
            rhoOffsets
            -- 25 lists from 0 to w-1. think of these as blank lanes
            (replicate 25 [0 .. (w - 1)])
   in U.fromList $ zipWith (+) a b

rho :: U.Vector Bit -> U.Vector Bit
-- if i used a ring buffer, this would be O(1)!
rho array = let w = U.length array `div` 25 in U.backpermute array (rhoBack w)

{-

this was a lesson in hubris.

  cIndices <- U.thaw $ U.concat $ bySlice w . Plane <$> [0..4]
  -- C is ... ok. i got C wrong. but this is still a neat solution.
  c <- MU.replicate w (Bit False)
  MU.iforM_ cIndices $ \index bit -> do
    currentBit <- MU.read c (index `rem` w)
    MU.write c (index `rem` w) (currentBit `xor` array U.! bit)

-}

x :: a
x = x
