{-# language BangPatterns #-}
{-# language LambdaCase #-}
{-# language NamedFieldPuns #-}

module Cef
  ( Event(..)
  , Fields(..)
  , Pair(..)
  , decode
  ) where

import Control.Monad.ST.Run (runByteArrayST)
import Data.Builder.ST (Builder)
import Data.Bytes.Parser (Parser)
import Data.Bytes.Types (Bytes(Bytes))
import Data.Chunks (Chunks)
import Data.Primitive (SmallArray)
import Data.Word (Word8)

import qualified Data.Bytes as Bytes
import qualified Data.Primitive as PM
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
      key0 <- Latin.takeTrailedBy () '='
      bldr0 <- Parser.effect Builder.new
      extension' <- parserExtension bldr0 key0
      let !extension = Chunks.concat extension'
          !fields = Fields
            { version, deviceVendor, deviceProduct
            , deviceVersion, signatureId, name, severity
            }
      pure Event{fields,extension}

-- | At the beginning of this function, a key and the equals sign
-- after it have already been parsed.
parserExtension :: Builder s Pair -> Bytes -> Parser () s (Chunks Pair)
parserExtension !bldr0 !key0 = do
  -- If the first character of the field is a double-quote character,
  -- then we use Palo Alto's non-standard extension of treating
  -- the value as though it has CSV-style escape sequences. Additionally,
  -- the equality operator does not need to be escaped if the field is
  -- quoted.
  Latin.trySatisfy (== '"') >>= \case
    True -> do
      val0 <- parserQuoted ()
      Latin.skipChar1 () ' '
      key1 <- Latin.takeTrailedBy () '='
      let !pair = Pair{key=key0,value=val0}
      bldr1 <- Parser.effect (Builder.push pair bldr0)
      parserExtension bldr1 key1
    False -> do
      start <- Unsafe.cursor
      b0 <- takeUntilUnescapedEquals start
      let !b = case Bytes.any (==0x5C) b0 of
                True -> unescape b0
                False -> b0
      Parser.isEndOfInput >>= \case
        True -> do
          let !pair = Pair{key=key0,value=b}
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

takeUntilUnescapedEquals :: Int -> Parser () s Bytes
takeUntilUnescapedEquals !initialCursor = do
  b <- Parser.takeWhile (/=0x3D)
  pos <- Unsafe.cursor
  arr <- Unsafe.expose
  let w = PM.indexByteArray arr (pos - 1) :: Word8
  case w of
    0x5C -> do
      _ <- Parser.any ()
      takeUntilUnescapedEquals initialCursor
    _ -> do
      let !val0 = Bytes arr initialCursor (pos - initialCursor)
      pure val0

unescape :: Bytes -> Bytes
unescape (Bytes src srcOff0 srcLen0) =
  let output = runByteArrayST $ do
        dst <- PM.newByteArray srcLen0
        let go !srcIx !dstIx !len = case len of
              0 -> do
                PM.shrinkMutableByteArray dst dstIx
                PM.unsafeFreezeByteArray dst
              _ -> case PM.indexByteArray src srcIx :: Word8 of
                0x5C -> do
                  PM.writeByteArray dst dstIx (PM.indexByteArray src (srcIx + 1) :: Word8)
                  go (srcIx + 2) (dstIx + 1) (len - 2)
                w -> do
                  PM.writeByteArray dst dstIx w
                  go (srcIx + 1) (dstIx + 1) (len - 1)
        go srcOff0 0 srcLen0
   in Bytes output 0 (PM.sizeofByteArray output)

-- Precondition: the cursor is right after the opening double quote.
-- TODO: Surely there are some kind of escape sequences that can show
-- up in here. I do not yet have any examples though.
parserQuoted :: e -> Parser e s Bytes
parserQuoted e = Latin.takeTrailedBy e '"'
