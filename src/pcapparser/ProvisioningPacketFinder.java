/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pcapparser;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;
import pcapparser.socketinfo.PacketInfo;

/**
 *
 * @author Sodrul Amin Shaon
 */
public class ProvisioningPacketFinder extends Thread {

    public static final String APP_VERSION = "2.4.1";
    public static final String SHUTDOWN_FILE_NAME = "ShutDown.sd";
    public static final String CONFIGURATION_FILE_NAME = "DPSConfig.txt";
    public static final String HEADER_CONFIGURATION_FILE_NAME = "DPSHeader.txt";
    public static final String GRAPH_CONFIGURATION_FILE_NAME = "GRAPHConfig.txt";
    public static final int BINDINGREQUEST = 0x0001;
    public static final int BINDINGRESPONSE = 0x0101;
    public static final int CHANGEREQUEST = 0x0003;
    public static final int SOURCEADDRESS = 0x0004;
    public static final int OPERATORCODE = 0x8000;
    public static final int PRIMARYOPERATORCODE = 0x8030;
    public static final int MAPPEDADDRESS = 0x0001;
    public static final int SWITCHPORTIP = 0x8001;
    public static final int OUTBOUND_PROXYPORTIP = 0x8801;
    public static final int IVREXTENSION = 0x8002;
    public static final int SUPPORTEXTENSION = 0x8202;
    public static final int OPERATOR_NAME = 0x8003;
    public static final int OPERATOR_WEB = 0x8004;
    public static final int ADDITIONAL_OPERATOR_WEB = 0x9004;
    public static final int SMS_SERVER_PORT_IP = 0x8005;
    public static final int VADSETTING = 0x8006;
    public static final int NO_BRAND = 0x8007;
    public static final int S60_2ND = 0x8008;
    public static final int S60_3RD = 0x8009;
    //Dialer Type    
    public static final int SYMBIAN = 0x3400;
    public static final int REVE_ATA = 0x3500;
    public static final int IPHONE = 0x3600;
    public static final int BLACKBERRY = 0x3700;
    public static final int BLACKBERRY10 = 0x3701;
    public static final int ANDROID = 0x3800;
    public static final int BADA = 0x3900;
    public static final int S40 = 0x4000;
    public static final int WINDOWS_MOBILE = 0x8014;
    public static final int PC_DIALER = 0x8807;
    public static final int PC_WEB_DIALER = 0x8808;
    public static final int PC_VIDEO_DIALER = 0x8809;
    //End of Dialer Type
    public static final int ATA_FIRMWARE_UPDATE_URL = 0x3501;
    public static final int UPDATE_URL = 0X5000;
    public static final int USER_NAME = 0x8010;
    public static final int ENCODED_COMMUNICATION = 0x8011;
    public static final int ALLOW_INCOMING_CALL = 0x8012;
    public static final int BALANCE_SERVER_PORT_IP = 0x8013;

    public static final int ALLOW_IMEI_SEND = 0x8015;
    public static final int OUTGOING_MEDIA_FRAME_SIZE = 0x8016;
    public static final int RANDOM_OUTGOING_PACKET = 0x8116;
    public static final int DUPLICATE_OUTGOING_PACKET = 0x8216;

    public static final int INCOMING_MEDIA_FRAME_SIZE = 0x8036;

    public static final int SWITCHDNS = 0x8017;
    public static final int NEW_STUN_SERVER = 0x7018;//0x8018;
    public static final int HEADER_ID = 0x8019;
    public static final int FOOTER_ID = 0x8020;
    public static final int RTP_HEADER_ID = 0x8021;
    public static final int RTP_PROTOCOL_ID = 0x8022;
    public static final int JITTER_BUFFER_ID = 0x8023;
    public static final int SIGNALING_PROTOCOL_ID = 0x8024;
    public static final int RANDOM_FILLER = 0x7022;
    public static final int IMEI_ID = 0x9010;
    public static final int VERSION_ID = 0x9011;
    public static final int AMR_ID = 0x9012;

    public static final int MOBILE_TOPUP_SERVER_ID = 0x7001;

    public static final int ENABLE_CREDIT_CARD_PAYMENT = 0x9039;
    public static final int MOBILE_MONEY_SERVER_ID = 0x9040;
    public static final int CHECKSUM_ID = 0x9013;

    private static boolean foundData = false;

    String pcapFileName;
    public static HashMap<String, String> checkSomes = new HashMap<String, String>();
    //ArrayList<String> provisioningIpList;
    private HashMap<String, String> resultMap;
    String logFile = "PcapResults.txt";
    private String currentFile;

    public ProvisioningPacketFinder(String str) {
        pcapFileName = str;
        //provisioningIpList = new ArrayList<>();

    }

    public void updateCheckSomeList() throws Exception {

        FileReader fr = new FileReader("checkSums.txt");
        BufferedReader br = new BufferedReader(fr);
        String line;
        while ((line = br.readLine()) != null) {
            if (line == null || line.length() == 0) {
                continue;
            }
            String[] str = line.split("=");
            if (str.length == 2) {
                checkSomes.put(str[0], str[1]);
            }
        }
    }

    class Pair implements Comparable {

        public long t;
        public File f;

        public Pair(File file) {
            f = file;
            t = file.lastModified();
        }

        public int compareTo(Object o) {
            long u = ((Pair) o).t;
            return t < u ? 1 : t == u ? 0 : -1;
        }
    };

    public void log(String message) {
        String newMessage = message + "\n";
        try {
            Files.write(Paths.get(logFile), newMessage.getBytes(), StandardOpenOption.APPEND);
        } catch (IOException e) {
            //exception handling left as an exercise for the reader
        }
    }

    @Override
    public void run() {

        try {
            resultMap = new HashMap<>();
            foundData = false;
            updateCheckSomeList();
            File folder = new File(System.getProperty("user.dir"));

            File logFile1 = new File(logFile);
            if (!logFile1.exists()) {
                logFile1.createNewFile();
            }

            File[] listOfFiles = folder.listFiles();
            //File file;
            Pair[] pairs = new Pair[listOfFiles.length];
            for (int i = 0; i < listOfFiles.length; i++) {
                pairs[i] = new Pair(listOfFiles[i]);
            }

            // Sort them by timestamp.
            Arrays.sort(pairs);

            // Take the sorted pairs and extract only the file part, discarding the timestamp.
            for (int i = 0; i < listOfFiles.length; i++) {
                listOfFiles[i] = pairs[i].f;
            }
            int totalFileProcessed = 0;
            for (int i = 0; i < listOfFiles.length; i++) {
                foundData = false;
                if (listOfFiles[i].isFile()) {
                    String file = listOfFiles[i].getName();
                    if (file.endsWith(".pcap")) {
                        currentFile = file;
                        totalFileProcessed++;
                        try{
                            Pcap pcap = Pcap.openStream(file);
                            MyPacketHandler packetHandler = new MyPacketHandler();
                            pcap.loop(packetHandler);
                            if (!foundData) {
                                log(currentFile + ",0,0,0");
                            }
                        }catch(Exception e){}
                    }

                }

            }
            
            System.out.println("Total File Processed: "+totalFileProcessed);
            Set<String> keySet = resultMap.keySet();
            for(String str: keySet){
                System.out.println(str);
            }

//            if (!foundData) {
//                System.out.println("No stun record found. Please try to take dialer log again.");
//            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
//    private class SocketAddress{
//        public InetAddress address;
//        public int port;
//        
//        String getString(){
//            return ""+address.toString()+" "+port;
//        }
//    }

    private class MyPacketHandler implements PacketHandler {

        //SocketAddress pcapSocketAddress;
        String dstIP;
        int dstPort;

        public MyPacketHandler() {
            //pcapSocketAddress=new SocketAddress();
        }

        @Override
        public boolean nextPacket(Packet packet) throws IOException {
            if (packet.hasProtocol(Protocol.UDP)) {

                UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                //InetAddress address = InetAddress.getByName(udpPacket.getDestinationIP());
                dstIP = null;
                //System.out.println("address: "+address);
                //if (isProvisioningPacket(address)) 
                {
                    //System.out.println("Found provisioningIP "+address);
                    byte[] stunEncodedData = udpPacket.getPayload().getArray();
                    String query = decodeData(stunEncodedData, 1);
                    stunEncodedData = udpPacket.getPayload().getArray();
                    String query2 = decodeData(stunEncodedData, 2);
                    if (query != null) {
                        //System.out.println(query);
                        foundData = true;
                        dstIP = udpPacket.getDestinationIP();
                    } else if (query2 != null) {
                        //System.out.println(query2);
                        foundData = true;
                        dstIP = udpPacket.getDestinationIP();
                    }
                }
                if(dstIP != null){
                    resultMap.put(dstIP, dstIP);
                }
            }
            return true;
        }

    }

    private String decodeData(byte[] data, int serverType) {
        if (data.length <= 20) {
            return null;
        }
        ///////////////////////////////////////////////
        String operatorCode = null;
        int dataLength = data.length;
        Version version = new Version();
        String primaryOperatorCode = null;

        operatorCode = null;
        version.init();

        int startIndex = 0;
        long checksum = 0;
        int dialerType = 0;
        //System.out.println("Data before decoding: \n"+Functions.bytesToHex(data));
//Start of Data Decoding                
        if (serverType == 1) {
            if (dataLength < 28) {
                return null;
            }
            int data5 = data[5] & 0x00FF;
            int data10 = data[10] & 0x00FF;
            int data13 = data[13] & 0x00FF;
            int data18 = data[18] & 0x00FF;
            if ((data5 == 0x03 || data5 == 0xa9) && (data10 == 0xa4 || data10 == 0x21) && (data13 == 0x00 || data13 == 0x13) && (data18 == 0xbe || data18 == 0x12)) {
                for (int i = 20; i < dataLength; i++) {
                    data[i] = (byte) ((data[i] ^ data[i % 20]) & 0x00FF);
                }
                //System.out.println("New XOR Format. ServerType 1");
            }
            startIndex = 20;
        } else if (serverType == 2) {
            for (int i = 4; i < dataLength; i++) {
                data[i] = (byte) ((data[i] ^ data[i % 4]) & 0x00FF);
            }
            startIndex = 4;
            //System.out.println("New XOR Format. ServerType 2");
        }
        // End of Data Decoding  
        //System.out.println("Data after decoding: \n"+Functions.bytesToHex(data));
        for (int i = startIndex; i < dataLength - 4;) {
            int index;

            int attributeType = Functions.twoByteToInt(data, i);
            i += 2;
            int attributeLength = Functions.twoByteToInt(data, i);
            i += 2;

            index = i;
            i += attributeLength;
            if (i > dataLength) {
                break;
            }
            if (attributeType == OPERATORCODE) {
                operatorCode = new String(data, index, attributeLength);
                //System.out.println("Operator Code:"+operatorCode);
            } //	            else if(attributeType==NO_BRAND)
            //	            {
            //	                NO_BRAND_Value = data[index];                        
            //	                //if(debug)logger.debug("No Brand:"+NO_BRAND_Value);
            //	            }
            //	            else if(attributeType== S60_2ND)
            //	            {
            //	            	dialerType = SYMBIAN;
            //	            	symbianFamily = S60_2ND;                                                
            //	            	//if(debug)logger.debug("Symbian S60 2nd");
            //	            }
            //	            else if(attributeType== S60_3RD)
            //	            {
            //	            	dialerType = SYMBIAN;
            //	            	symbianFamily=S60_3RD;
            //	            	//if(debug)logger.debug("Symbian S60 3rd");
            //	            }
            //	            else if(attributeType==DialerProvisionServer.SYMBIAN)
            //	            {
            //	            	dialerType = SYMBIAN;
            //	            	//if(debug)logger.debug("Symbian Dialer");
            //	            }
            //	            else if(attributeType==REVE_ATA)
            //	            {
            //	            	dialerType = REVE_ATA;                        
            //	            	//if(debug)logger.debug("Reve ATA");
            //	            }
            //	            else if(attributeType==IPHONE)
            //	            {
            //	            	dialerType = IPHONE;                        
            //	            	//if(debug)logger.debug("iPhone");
            //	            }
            //	            else if(attributeType==BLACKBERRY)
            //	            {
            //	            	dialerType = BLACKBERRY;                        
            //	            	//if(debug)logger.debug("BlackBerry");
            //	            }
            //	            else if(attributeType==BLACKBERRY10)
            //	            {
            //	            	dialerType = BLACKBERRY10;                        
            //	            	//if(debug)logger.debug("BlackBerry 10");
            //	            }
            //	            
            else if (attributeType == ANDROID) {
                dialerType = ANDROID;
                //if(debug)logger.debug("Android Dialer");
            } //	            else if(attributeType==BADA)
            //	            {
            //	            	dialerType = BADA;                        
            //	            	//if(debug)logger.debug("BADA");
            //	            }
            //	            else if(attributeType==S40)
            //	            {
            //	            	dialerType = S40;                        
            //	            	//if(debug)logger.debug("S40");
            //	            }
            //	            else if(attributeType==WINDOWS_MOBILE)
            //	            {
            //	            	dialerType = WINDOWS_MOBILE;                        
            //	            	//if(debug)logger.debug("Windows Mobile");
            //	            }
            //	            else if(attributeType ==PC_DIALER)
            //	            {
            //	            	dialerType = PC_DIALER;
            //	            	//if(debug)logger.debug("PC Dialer");
            //	            }
            //	            else if(attributeType ==PC_WEB_DIALER)
            //	            {
            //	            	dialerType = PC_WEB_DIALER;
            //	            	//if(debug)logger.debug("PC Web Dialer");
            //	            }
            //	            else if(attributeType ==PC_VIDEO_DIALER)
            //	            {
            //	            	dialerType = PC_VIDEO_DIALER;
            //	            	//if(debug)logger.debug("PC Video Dialer");
            //	            }                    
            else if (attributeType == VERSION_ID) {
                version.parse(data, index, attributeLength);
                //System.out.println("Version:"+version);                    	
            } //	            else if(attributeType == IMEI_ID)
            //	            {
            //	                imeiLength = attributeLength;
            //	                for(int j=0;j<attributeLength;j++)
            //	                {
            //	                    imei[j] = data[index+j];
            //	                } 
            //	                //if(debug)logger.debug("IMEI:"+new String(imei,0,imeiLength));
            //	            }
            //	            else if(attributeType==AMR_ID)
            //	            {
            //	                useAMRSwitch=true;
            //	                //if(debug)logger.debug("Dialer Using AMR ");
            //	            }
            else if(attributeType==PRIMARYOPERATORCODE)
            {
                primaryOperatorCode = new String(data,index,attributeLength);
                //if(debug)logger.debug("PrimaryOperatorCode:"+primaryOperatorCode);
            }
            //	            else if (attributeType == SOURCE_DIALER_IP_HEADER)
            //	            {                      
            //	              for(int j=0;j<sourceAddressByte.length;j++)
            //	              {
            //	                sourceAddressByte[j] = data[index + j];
            //	              }
            //	              
            //	              //if(debug)logger.debug("Got SourceDialerAddress:"+InetAddress.getByAddress(sourceAddressByte).getHostName());
            //	            }
            //	            else if (attributeType == SOURCE_DIALER_PORT_HEADER)
            //	            {
            //	              sourcePort = data[index] & 0x00ff;
            //	              sourcePort = (sourcePort << 8) | (data[index+1] & 0x00ff);
            //	              
            //	              //if(debug)logger.debug("Got SourceDialerPort :"+sourcePort);
            //	            }
            //	            else if(attributeType == BSS_RECEIVE_PORT_HEADER)
            //	            {
            //	              bssReceivePort = data[index] & 0x00ff;
            //	              bssReceivePort = (bssReceivePort << 8) | (data[index+1] & 0x00ff);
            //	              //if(debug)logger.debug("bssReceivePort:"+bssReceivePort); 
            //	            }
            else if (attributeType == CHECKSUM_ID) {
                checksum = data[index] & 0x00FF;
                checksum = (checksum << 8) | (data[index + 1] & 0x00FF);
                checksum = (checksum << 8) | (data[index + 2] & 0x00FF);
                checksum = (checksum << 8) | (data[index + 3] & 0x00FF);
                //System.out.println("CheckSUM:"+checksum);                    	
            }
//	            else if(attributeType==MOBILE_NUMBER)
//	            {
//	            	String tmpMobileNumber = new String(data,index,attributeLength);
//	            	int startMnumberIndex=0;
//	            	if(tmpMobileNumber!=null && tmpMobileNumber.length()>0)
//	            	{
//	            		for(int jj=0;jj<tmpMobileNumber.length();jj++)
//	            		{
//	            			if(tmpMobileNumber.charAt(jj)>='0' && tmpMobileNumber.charAt(jj)<='9')
//	            				break;
//	            			startMnumberIndex++;
//	            		}
//	            		if(tmpMobileNumber.length()>startMnumberIndex)
//	            			mobileNumber = tmpMobileNumber.substring(startMnumberIndex);
//	            	}
//	            	
//	            	//ger.debug("Got original Mobile Number: "+tmpMobileNumber +"\t modified Mobile Number: "+mobileNumber);
//	            }
//            else if(attributeType == SOURCE_NETWORK_ID)
//            {
//              networkID = data[index] & 0x00ff;
//              networkID = (networkID << 8) | (data[index+1] & 0x00ff);
//              //if(debug)logger.debug("Got Network ID: "+networkID);
//            }

        }
        
//End of Data Parsing
        if (operatorCode == null || checksum == 0 || version.toString().equals("0.0.0")) {
            //System.out.println("Request do not contain operator code");
            return null;
        }
        System.out.println("Operator Code: "+operatorCode+" version: "+version.toString()+" primaryOperatorCode: "+primaryOperatorCode);
//        String hashString = operatorCode + "," + version.toString() + "," + checksum;
//        if(!resultMap.containsKey(hashString)){
//            log(currentFile+","+hashString);
//            resultMap.put(hashString, hashString);
//        }
        //System.out.println();
        String query = "insert into vbValidDialerInfo values (ID, '" + operatorCode + "', " + dialerType + ", " + version.toInt() + ", " + checksum + ");";
        String checkSum = checkSomes.get(version.toString());
        if (checkSum == null) {
            if (version.major == 7) {
                checkSum = "1787636127";
            } else if (version.major == 5) {
                checkSum = "4226923172";
            } else if (version.major == 3) {
                checkSum = "1661993078";
            } else {
                checkSum = "0";
            }
        }
        //System.out.println("insert into vbValidDialerInfo values (ID, '" + operatorCode + "', " + dialerType + ", " + version.toInt() + ", " + checkSum + ");");
        return query;
    }

//    private boolean isProvisioningPacket(InetAddress socketAddress) {
////        System.out.println(""+followedSocket.size());
//        for (String socketAddress1 : provisioningIpList) {
//            if (socketAddress1.equals(socketAddress.toString().substring(1))) {
//                return true;
//            }
//        }
//
//        return false;
//    }
}
