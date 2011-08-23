module Network.Pcap.Enumerator 
       ( enumPcap
       ) where

import Data.ByteString (ByteString)
import Data.ByteString.Char8 ()
import Data.Enumerator hiding (map, filter)
import Network.Pcap

enumPcap :: FilePath -> Enumerator (PktHdr, ByteString) IO b
enumPcap path step = do
  h <- tryIO $ openOffline path
  let iter = enumPcap1 h step
  Iteratee $ runIteratee iter

enumPcap1 :: PcapHandle -> Enumerator (PktHdr, ByteString) IO b
enumPcap1 h = checkContinue0 $ \lp k -> do
  pkt@(hdr, _) <- tryIO $ nextBS h
  if (hdrCaptureLength hdr == 0)
    then continue k
    else k (Chunks [pkt]) >>== lp
