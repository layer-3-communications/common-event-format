{-# language NamedFieldPuns #-}

import Cef
import Sample

import Control.Monad (when)

import qualified Data.Primitive as PM
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Text.Ascii as Ascii
import qualified Data.Bytes.Text.Latin1 as Latin1

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
          when (key /= Ascii.fromString "externalId")
            (fail "Expected first key to be externalId")
          when (value /= Ascii.fromString "3461888970")
            (fail "Expected first value to be 3461888970")
      case PM.indexSmallArray extension 12 of
        Pair{key,value} -> do
          when (key /= Ascii.fromString "act")
            (fail "Expected last key to be act")
          when (value /= Ascii.fromString "ignore")
            (fail "Expected last value to be ignore")
  putStrLn "Test A Succeeded"
  putStrLn "Test B"
  case decode sampleA10_b of
    Nothing -> fail "Failed to parse"
    Just _ -> pure ()
  putStrLn "Test B Succeeded"
  putStrLn "Test C"
  case decode sampleCrowdstrike_c of
    Nothing -> fail "Failed to parse"
    Just Event{fields=Fields{severity},extension} -> do
      let len = length extension
      when (severity /= 1) (fail "Incorrect severity, expected 1")
      when (len /= 2) (fail ("Extension, expected 2 pairs, got " ++ show len))
      case PM.indexSmallArray extension 1 of
        Pair{key,value} -> do
          when (key /= Ascii.fromString "reportFileReference")
            (fail "Expected last key to be reportFileReference")
          when (value /= Ascii.fromString "/report-executions-download/v1?ids=abcdefg") $ fail $
            "Expected last value to be (length 42) /report-executions-download/v1?ids=abcdefg but got (length "
            ++
            show (Bytes.length value)
            ++
            ") "
            ++
            Latin1.toString value
            ++
            "."
  putStrLn "Test C Succeeded"
  putStrLn "Complete"
