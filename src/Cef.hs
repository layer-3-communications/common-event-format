{-# language BangPatterns #-}
{-# language LambdaCase #-}
{-# language NamedFieldPuns #-}

module Cef
  ( Event(..)
  , Fields(..)
  , Pair(..)
  , decode
  ) where

import Data.Bytes.Types (Bytes(Bytes))
import Data.Bytes.Parser (Parser)
import Data.Word (Word8)
import Data.Primitive (SmallArray)
import Data.Chunks (Chunks)
import Data.Builder.ST (Builder)

import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe
import qualified Data.Builder.ST as Builder
import qualified Data.Chunks as Chunks

data Event = Event
  { fields :: !Fields
    -- ^ The seven prefix fields present in all CEF logs.
  , extension :: {-# UNPACK #-} !(SmallArray Pair)
    -- ^ A collection of key-value pairs.
  }

-- | Standard CEF fields
data Fields = Fields
  { version :: {-# UNPACK #-} !Word8
  , deviceVendor :: {-# UNPACK #-} !Bytes
  , deviceProduct :: {-# UNPACK #-} !Bytes
  , deviceVersion :: {-# UNPACK #-} !Bytes
  , signatureId :: {-# UNPACK #-} !Bytes
  , name :: {-# UNPACK #-} !Bytes
  , severity :: {-# UNPACK #-} !Word8
  }

-- | A key-value pair
data Pair = Pair
  { key :: {-# UNPACK #-} !Bytes
  , value :: {-# UNPACK #-} !Bytes
  }

decode :: Bytes -> Maybe Event
decode !b = Parser.parseBytesMaybe parser b

parser :: Parser () s Event
parser = do
  Latin.char4 () 'C' 'E' 'F' ':'
  version <- Latin.decWord8 ()
  Latin.char () '|'
  deviceVendor <- Parser.takeTrailedBy () 0x7C
  deviceProduct <- Parser.takeTrailedBy () 0x7C
  deviceVersion <- Parser.takeTrailedBy () 0x7C
  signatureId <- Parser.takeTrailedBy () 0x7C
  -- We do this nonsense because CEF logs from A10s are missing
  -- the name field sometimes. This makes the logs technically
  -- not compliant with CEF, but it is easier to hack about their
  -- infidelity to a spec than it is to get the appliance fixed.
  target <- Unsafe.cursor
  n <- Parser.any ()
  p <- Parser.any ()
  if p == 0x7C && n >= 0x30 && n <= 0x39 -- if it is a digit followed by pipe
    then do
      let severity = n - 0x30
      key0 <- Parser.takeTrailedBy () 0x3D
      bldr0 <- Parser.effect Builder.new
      extension' <- parserExtension bldr0 key0
      arr <- Unsafe.expose
      let !extension = Chunks.concat extension'
          !fields = Fields
            { version, deviceVendor, deviceProduct
            , deviceVersion, signatureId, severity
            , name = Bytes arr target 0
            }
      pure Event{fields,extension}
    else do
      Unsafe.jump target
      name <- Parser.takeTrailedBy () 0x7C
      severity <- Latin.decWord8 ()
      Latin.char () '|'
      key0 <- Parser.takeTrailedBy () 0x3D
      bldr0 <- Parser.effect Builder.new
      extension' <- parserExtension bldr0 key0
      let !extension = Chunks.concat extension'
          !fields = Fields
            { version, deviceVendor, deviceProduct
            , deviceVersion, signatureId, name, severity
            }
      pure Event{fields,extension}

parserExtension :: Builder s Pair -> Bytes -> Parser () s (Chunks Pair)
parserExtension !bldr0 !key0 = do
  start <- Unsafe.cursor
  b <- Parser.takeWhile (/=0x3D)
  Parser.isEndOfInput >>= \case
    True -> do
      end <- Unsafe.cursor
      arr <- Unsafe.expose
      let !val0 = Bytes arr start (end - start)
      let !pair = Pair{key=key0,value=val0}
      Parser.effect $ do
        bldr1 <- Builder.push pair bldr0
        Builder.freeze bldr1
    False -> do
      Latin.char () '='
      case Bytes.splitEnd1 0x20 b of
        Nothing -> Parser.fail () -- No space character between equal signs
        Just (val0,key1) -> do
          let !pair = Pair{key=key0,value=val0}
          bldr1 <- Parser.effect (Builder.push pair bldr0)
          parserExtension bldr1 key1
