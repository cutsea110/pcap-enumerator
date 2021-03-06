module Network.Pcap.Enumerator 
       ( enumOffline
       , enumLive
       ) where

import Control.Monad.IO.Class
import Data.ByteString (ByteString)
import Data.ByteString.Char8 ()
import Data.Enumerator hiding (map, filter)
import Data.Int (Int64)
import Network.Pcap

enumOffline :: (MonadIO m) => FilePath -> Enumerator (PktHdr, ByteString) m b
enumOffline path step = do
  h <- tryIO $ openOffline path
  let iter = enumPcap1 h step
  Iteratee $ runIteratee iter

enumLive :: (MonadIO m) => String -> Int -> Bool -> Int64 -> Enumerator (PktHdr, ByteString) m b
enumLive name snaplen promisc timeout step = do
  h <- tryIO $ openLive name snaplen promisc timeout
  let iter = enumPcap1 h step
  Iteratee $ runIteratee iter

enumPcap1 :: (MonadIO m) => PcapHandle -> Enumerator (PktHdr, ByteString) m b
enumPcap1 h = checkContinue0 $ \lp k -> do
  pkt@(hdr, _) <- tryIO $ nextBS h
  if (hdrCaptureLength hdr == 0)
    then continue k
    else k (Chunks [pkt]) >>== lp
