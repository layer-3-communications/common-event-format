module Sample
  ( sampleA10_a
  ) where

import Data.Bytes (Bytes)
import qualified Data.Bytes as Bytes

sampleA10_a :: Bytes
sampleA10_a = Bytes.fromAsciiString
  "CEF:0|A10|TH4225 TPS|3.1.2-TPS-P1|DDOS|Well known port \
  \check|4|externalId=3461888970 cs1=EX-HOSTING traffic-type \
  \UDP cs1Label=obj-info msg=DDoS packet from well-known UDP \
  \source port detected timestamp=Wed Oct 12 15:58:09 2020 \
  \cs3=UDP_Basic cs3Label=template cnt=1366 src=192.0.2.105 \
  \spt=999 dst=192.0.2.11 dpt=1001 act=ignore"
