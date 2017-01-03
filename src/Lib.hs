module Lib
    ( scanAndWork
    ) where

import Network.Pcap as Pcap
import Control.Monad (forever)
import Foreign.Ptr
import Control.Concurrent (threadDelay)
import Data.Word
import qualified Data.ByteString as B
import Data.Char
import qualified Data.Map as Map
import Data.Maybe

-- List of all known mac addresses.
macMap :: Map.Map String String
macMap = Map.fromList [("8C705ABA1458", "Someone's Laptop")]

-- main Method.
scanAndWork :: IO ()
scanAndWork = do
    putStrLn "Top of the morning to you!"
    handle <- Pcap.openLive "wlan0" 0 False 2000
    lists <- Pcap.listDatalinks handle  -- We output the possible operation data
    mapM_ print lists                   -- links. should be ~wlan 802_11

    forever $ do
        threadDelay 1000                 -- We don't let the main thread die.
        Pcap.dispatchBS handle 1 printPackageBS   -- We don't need the resulting number of packages read.
                                                        -- Furthermore we register the callback printPackage
                                                        -- This operation will start in a different thread.

printPackagePtr :: Pcap.PktHdr -> Ptr Word8 -> IO ()
printPackagePtr header@(Pcap.PktHdr _ _ capturedLength wireLength) body = do
    (_, bodyBS) <- Pcap.toBS (header, body)
    printPackage capturedLength wireLength bodyBS

printPackageBS :: Pcap.PktHdr -> B.ByteString -> IO ()
printPackageBS (Pcap.PktHdr _ _ capturedLength wireLength) body = printPackage capturedLength wireLength body

printPackage :: Integral a => a -> a -> B.ByteString -> IO ()
printPackage capturedLength wireLength body = do
    putStrLn $ "Package length (captured) " ++ (show $ fromIntegral capturedLength)
    putStrLn $ "Package length (on wire) " ++ (show $ fromIntegral wireLength)
    putStrLn $ "ByteString Body length: " ++ (show $ B.length body)
    putStrLn $ "Extracted Mac Address: " ++ (show $ extractMacFromBS body)
    putStrLn $ macToName $ show $ B.unpack $ extractMacFromBS body
    putStrLn "--------------------------"

-- Drops 14 bytes then takes 6 bytes from the packet. These 6 bytes represent the mac address
-- Notice: This is the senders Mac address: https://en.wikipedia.org/wiki/Ethernet_frame
extractMacFromBS = B.take 6 . B.drop 14

-- We can map a mac address to a name.
macToName :: String -> String
macToName mac
    | isJust name = fromJust name
    | isNothing name = "Unknown Device"
    where
        name = Map.lookup mac macMap