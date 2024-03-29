module Sample
  ( sampleA10_a
  , sampleA10_b
  , sampleCrowdstrike_c
  , samplePan_a
  , samplePan_b
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

samplePan_b :: Bytes
samplePan_b = Ascii.fromString
  "CEF:0|Palo Alto Networks|PAN-OS|9.1.14|url|THREAT|1|rt=Aug 09 2023 15:29:29 \
  \GMT deviceExternalId=551871312974 src=192.0.2.111 dst=192.0.2.112 \
  \sourceTranslatedAddress=0.0.0.0 destinationTranslatedAddress=0.0.0.0 \
  \cs1Label=Rule cs1=In-to-Out suser=org\\admin duser= app=web-browsing \
  \cs3Label=Virtual System cs3=vsys1 cs4Label=Source Zone \
  \cs4=Private cs5Label=Destination Zone cs5=Out \
  \deviceInboundInterface=ethernet2/5.255 deviceOutboundInterface=ethernet1/3.2401 \
  \cs6Label=LogProfile cs6=Global-Forward-Logs cn1Label=SessionID cn1=121071 \
  \cnt=1 spt=56007 dpt=80 sourceTranslatedPort=0 destinationTranslatedPort=0 \
  \flexString1Label=Flags flexString1=0x3000 proto=tcp act=alert \
  \request=\"example.com/foo.web?s=xyz;resource=123;element=55;w=1232;h=924;q=8;format=6;1234\" \
  \cs2Label=URL Category cs2=computer-and-internet-info flexString2Label=Direction \
  \flexString2=client-to-server PanOSActionFlags=0xa000000000000000 externalId=825210825 \
  \requestContext=image/jpeg cat=(9999) fileId=0 requestMethod=get \
  \requestClientApplication=\"Mozilla/5.0 (Macintosh; Intel Mac OS X 1_2_3) \
  \AppleWebKit/500.00 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/500.00\" \
  \PanOSXForwarderfor= PanOSReferer=\"http://exmaple.com/login\" \
  \PanOSDGl1=240 PanOSDGl2=134 PanOSDGl3=0 PanOSDGl4=0 PanOSVsysName=Production \
  \dvchost=Palo-1 PanOSSrcUUID= PanOSDstUUID= PanOSTunnelID=0 PanOSMonitorTag= \
  \PanOSParentSessionID=0 PanOSParentStartTime= PanOSTunnelType=N/A \
  \PanOSThreatCategory=unknown PanOSContentVer=AppThreat-0-0 PanOSAssocID=0 \
  \PanOSPPID=4294967295 PanOSHTTPHeader=\"http://example.com/login\" \
  \PanOSRuleUUID=c9c1db77-1e75-4d47-b1ef-4a5ac6bb59c0 \
  \PanOSURLCatList=\"computer-and-internet-info,low-risk\" \
  \PanOSHTTP2Con=0 PanDynamicUsrgrp="
