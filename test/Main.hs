{-# language NamedFieldPuns #-}

import Cef
import Sample

import Control.Monad (when)

import qualified Data.Bytes as Bytes
import qualified Data.Primitive as PM

main :: IO ()
main = do
  putStrLn "Test A"
  case decode sampleA10_a of
    Nothing -> fail "Failed to parse"
    Just Event{fields=Fields{severity},extension} -> do
      let len = length extension
      when (severity /= 4) (fail "Incorrect severity, expected 4")
      when (len /= 13) (fail ("Extension, expected 13 pairs, got " ++ show len))
      case PM.indexSmallArray extension 0 of
        Pair{key,value} -> do
          when (key /= Bytes.fromAsciiString "externalId")
            (fail "Expected first key to be externalId")
          when (value /= Bytes.fromAsciiString "3461888970")
            (fail "Expected first value to be 3461888970")
      case PM.indexSmallArray extension 12 of
        Pair{key,value} -> do
          when (key /= Bytes.fromAsciiString "act")
            (fail "Expected last key to be act")
          when (value /= Bytes.fromAsciiString "ignore")
            (fail "Expected last value to be ignore")
  putStrLn "Test A Succeeded"
  putStrLn "Complete"
