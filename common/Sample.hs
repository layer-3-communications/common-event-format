module Sample
  ( sampleA10_a
  , sampleA10_b
  , sampleCrowdstrike_c
  , samplePan_a
  ) where

import Data.Bytes (Bytes)
import qualified Data.Bytes.Text.Ascii as Ascii
import qualified Data.Bytes as Bytes

sampleA10_a :: Bytes
sampleA10_a = Ascii.fromString
  "CEF:0|A10|TH4225 TPS|3.1.2-TPS-P1|DDOS|Well known port \
  \check|4|externalId=3461888970 cs1=EX-HOSTING traffic-type \
  \UDP cs1Label=obj-info msg=DDoS packet from well-known UDP \
  \source port detected timestamp=Wed Oct 12 15:58:09 2020 \
  \cs3=UDP_Basic cs3Label=template cnt=1366 src=192.0.2.105 \
  \spt=999 dst=192.0.2.11 dpt=1001 act=ignore"

sampleA10_b :: Bytes
sampleA10_b = Ascii.fromString
  "CEF:0|A10|TH4415 TPS|3.6.8-TPS-P3|DDOS|4|externalId=3511768169 \
  \cs1=EX-HOSTING traffic-type ICMP cs1Label=obj-info \
  \cs3=ICMP_BASIC_GENERAL cs3Label=template cnt=3327 \
  \src=192.0.2.33 dst=192.0.2.5 act=drop"

sampleCrowdstrike_c :: Bytes
sampleCrowdstrike_c = Ascii.fromString
  "CEF:0|CrowdStrike|FalconHost|1.0|ScheduledReportNotificationEvent|\
  \Scheduled Report Notification Event|1|cat=\
  \ScheduledReportNotificationEvent\
  \ reportFileReference=/report-executions-download/v1?ids\\=abcdefg"

samplePan_a :: Bytes
samplePan_a = Ascii.fromString
  "CEF:0|Palo Alto Networks|PAN-OS|10.0|VPN|GLOBALPROTECT|1|rt=2023/05/24 15:25:04 \
  \PanOSDeviceSN=004251758665 PanOSLogTimeStamp=2023/05/24 15:25:04 \
  \PanOSVirtualSystem=vsys1 PanOSEventID=gateway-config-release \
  \PanOSStage=configuration PanOSAuthMethod= PanOSTunnelType= \
  \PanOSSourceUserName=bob@example.com PanOSSourceRegion=US \
  \PanOSEndpointDeviceName=bob-iphone-2 PanOSPublicIPv4=192.0.2.20 \
  \PanOSPublicIPv6=0.0.0.0 PanOSPrivateIPv4=192.0.2.10 \
  \PanOSPrivateIPv6=0.0.0.0 PanOSHostID=de:ad:be:ef:01:23 \
  \PanOSDeviceSN=ABCD123456 PanOSGlobalProtectClientVersion=1.0.0 \
  \PanOSEndpointOSType=Mac PanOSEndpointOSVersion=\"Apple Mac OS X 1.2.3\" \
  \PanOSCountOfRepeats=1 PanOSQuarantineReason= PanOSConnectionError= \
  \PanOSDescription=\"\" PanOSEventStatus=success"
