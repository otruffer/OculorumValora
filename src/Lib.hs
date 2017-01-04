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
import Foreign
import qualified Network.Pcap.Base as BPcap
import Text.Bytedump as ByteDump
import Data.Binary.Strict.Get
import qualified Data.Binary.Get as GL
import Data.Either.Unwrap

-- List of all known mac addresses.
macMap :: Map.Map String String
macMap = Map.fromList [("48db50c0c6ce", "Natel")]

-- main Method.
scanAndWork :: IO ()
scanAndWork = do
    putStrLn "Top of the morning to you!"
    handle <- Pcap.openLive "wlan0" 100 True 2000 -- we monitor wlan0 adapter. 100 bytes should be enough to get the header.
    lists <- Pcap.listDatalinks handle  -- We output the possible operation data
    mapM_ print lists                   -- links. should be ~wlan 802_11.. or some ethernet link layer protocol.
    Pcap.loopBS handle (-1) printPackageBS   -- We don't need the resulting number of packages read.
                                                        -- Furthermore we register the callback printPackage
                                                        -- This operation will start in a different thread.
    forever $ do
        threadDelay 1000                 -- We don't let the main thread die.

-- helper function if using Pointer Interface of Network.Pcap
printPackagePtr :: Pcap.PktHdr -> Ptr Word8 -> IO ()
printPackagePtr header@(Pcap.PktHdr _ _ capturedLength wireLength) body = do
    (_, bodyBS) <- Pcap.toBS (header, body)
    printPackage capturedLength wireLength bodyBS

-- helper function if using ByteString Interface of Network.Pcap
printPackageBS :: Pcap.PktHdr -> B.ByteString -> IO ()
printPackageBS (Pcap.PktHdr _ _ capturedLength wireLength) body = printPackage capturedLength wireLength body

printPackage :: Integral a => a -> a -> B.ByteString -> IO ()
printPackage capturedLength wireLength body = do
    putStrLn $ "Package length (captured) " ++ (show $ fromIntegral capturedLength)
    putStrLn $ "Package length (on wire) " ++ (show $ fromIntegral wireLength)
    putStrLn $ "Head Dump of the package (in hex): " ++ (prettyHex $ ByteDump.dumpRaw $ B.unpack $ B.take 30 body)
    putStrLn $ "RadioTab Header Length:  " ++ (show $ radioTapLength)
    putStrLn $ "Extracted Dest Mac Address: " ++ (prettyHex destAsString)
    putStrLn $ "Extracted Source Mac Address: " ++ (prettyHex sourceAsString)
    putStrLn $ macToName sourceAsString
    putStrLn "--------------------------"
    where
        radioTapLength = extractRadioTapLength body                                                 -- extract length of RadioTap Header. This is a header added in monitoring mode, we need to get rid of it.
        destAsString = ByteDump.dumpRaw $ B.unpack $ extractDestMacFromBS radioTapLength body       -- extracts the destination mac address.
        sourceAsString = ByteDump.dumpRaw $ B.unpack $ extractSourceMacFromBS radioTapLength body   -- extracts the source mac address.

-- Make my hex strings pretty again. Probably doable with a fold...
prettyHex :: String -> String
prettyHex [] = []
prettyHex (x:y:[]) = [x, y]
prettyHex (x:y:rest) = [x, y, ':'] ++ (prettyHex rest)

-- We expect to be in monitor mode thus we have a variable length radiotap header before the ethernet layer.
extractRadioTapLength :: B.ByteString -> Int
extractRadioTapLength body = fromRight $ fst $ runGet radioTapParser body

-- We expect to be in monitor mode thus we have a variable length radiotap header before the ethernet layer.
radioTapParser :: Get Int
radioTapParser = do
    skip 2                          -- First two bytes are other stuff.
    radioTabLength <- getWord16le   -- 3rd and 4th byte are what we want! :-) Little endian: 12 00 is 18. ending comes first.
    return (fromIntegral(radioTabLength) :: Int) -- Casting from 16 bit to 8 bit.... but i just hope the header is smaller than 256B, the once i've seen so far are around ~20B

--TODO: The following two methods should be handled with the Get Byte Monad.

-- Drops (radiotap header) + 4 (some ethernet stuff) + 6 (destination MAC) bytes then takes 6 bytes from the packet.
-- These 6 bytes represent the source mac address
-- Notice: This is the senders Mac address: https://en.wikipedia.org/wiki/Ethernet_frame
extractSourceMacFromBS :: Int -> B.ByteString -> B.ByteString
extractSourceMacFromBS radioTapLength = B.take 6 . B.drop (radioTapLength + 4 + 6)

-- Same for destination Mac Address
extractDestMacFromBS :: Int -> B.ByteString -> B.ByteString
extractDestMacFromBS radioTapLength = B.take 6 . B.drop (radioTapLength + 4)



-- We can map a mac address to a name.
macToName :: String -> String
macToName mac
    | isJust name = fromJust name
    | isNothing name = "Unknown Device"
    where
        name = Map.lookup mac macMap