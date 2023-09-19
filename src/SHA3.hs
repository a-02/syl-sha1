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

x :: a
x = x
