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
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import static pcapparser.Functions.downloadFile;
import pcapparser.socketinfo.PacketInfo;

/**
 *
 * @author Sodrul Amin Shaon
 */
public class ClientUdpSimulation extends Thread{
    HashMap<String,DatagramSocket> socketMap;
    HashMap<String, SocketAddress> addressMap;
    ArrayList<DatagramSocket> socketList;
    String fileName;
    ArrayList<SocketAddress> followedSocket;
    ArrayList<PacketInfo> packetList;
    int receivedCount,shouldReceive,sentCount;
    long lastReceived,startTime;
    ArrayList<UdpReceiver> threadList;
    public ClientUdpSimulation(){
        fileName=null;
        socketMap=new HashMap<>();
        followedSocket=new ArrayList<>();
        addressMap=new HashMap<>();
        packetList=new ArrayList<>();
        threadList=new ArrayList<>();
        socketList=new ArrayList<>();
        receivedCount=0;
        shouldReceive=0;
        sentCount=0;
        lastReceived=0;
    }
    
    
    @Override
    public void run(){
        readClientConfiguration();
        //downloadFile(fileName);
        try {
            startTime=System.currentTimeMillis();
            Pcap pcap = Pcap.openStream(fileName);
            MyPacketHandler packetHandler=new MyPacketHandler();
            pcap.loop(packetHandler);
            
            for(SocketAddress socketAddress: followedSocket){
                UdpReceiver thread=new UdpReceiver(socketMap.get(socketAddress.getString()));//.start();
                threadList.add(thread);
                thread.start();
            }
            long virtualStartTime=packetList.get(0).time,realStartTime=System.currentTimeMillis(),virtualSendTime,realSendTime;
            SocketAddress socketAddress=new SocketAddress(),sendAddress;
            DatagramSocket socket;
            
            System.out.println("Should receive "+shouldReceive);
            
            for(PacketInfo packetInfo:packetList){
                socketAddress.address=packetInfo.srcAddress;
                socketAddress.port=packetInfo.srcPort;
                socket=socketMap.get(socketAddress.getString());
                socketAddress.address=packetInfo.dstAddress;
                socketAddress.port=packetInfo.dstPort;
                sendAddress=addressMap.get(socketAddress.getString());
                virtualSendTime=packetInfo.time;
                realSendTime=realStartTime+(virtualSendTime-virtualStartTime)/1000;
                Thread.sleep(Math.max(realSendTime-System.currentTimeMillis(),0));
//                while(System.currentTimeMillis()<(realSendTime)){
                    //System.out.println(realSendTime+" --- "+System.currentTimeMillis());
//                }
                
                socket.send(createPacket(sendAddress, packetInfo.data));
                sentCount++;
                System.out.println("Packet sent len "+packetInfo.data.length+" count ---------- "+ sentCount);
            }
            
            new EndChecker().start();
            
        } catch (IOException ex) {
            Logger.getLogger(ClientUdpSimulation.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedException ex) {
            Logger.getLogger(ClientUdpSimulation.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    private DatagramPacket createPacket(SocketAddress dstAddress,byte [] data){
        
        return new DatagramPacket(data, data.length,dstAddress.address,dstAddress.port);
    }
    public void readClientConfiguration(){
        //downloadFile("client.config");
        try {
            FileReader fr=new FileReader("client.config");
            BufferedReader br = new BufferedReader(fr);
            String line;
            line=br.readLine();
            if(line!=null)
                fileName=line;
            else{
                System.out.println("client.config file is unreadable\nPut the pcap file in the first line.");
                return;
            }
            line=br.readLine();
            if(line==null){
                System.out.println("client.config file in bad format.\nPut socket count after file name");
                return;
            }
            int socketCount=Integer.parseInt(line),port;
            while(socketCount>0 && (line = br.readLine()) != null){
                if(line==null)continue;
                SocketAddress socketAddress=new SocketAddress();
                
                line=line.substring(line.indexOf(":")+1);   ////reading local port number to create datagram socket
                port=Integer.parseInt(line.substring(0, line.indexOf(" ")));
                line=line.substring(line.indexOf("srcIP")+6); ////reading src ip to be followd of the pcap file
                socketAddress.address=InetAddress.getByName(line.substring(0,line.indexOf(" ")));
                line=line.substring(line.indexOf("srcPort")+8); ///reading src port to be followed ot the pcap file
                socketAddress.port=Integer.parseInt(line);
                followedSocket.add(socketAddress);            ////allowed sockets amongs all the sockets in the pcap file
                if(port!=0){
                    DatagramSocket socket=new DatagramSocket(port);
                    socketMap.put(socketAddress.getString(), socket);
                    socketList.add(socket);
                    socketCount--;
                }
            }
            System.out.println("Following these sockets.");
            for(SocketAddress socketAddress:followedSocket){
                System.out.println(""+socketAddress.address.toString()+" "+socketAddress.port);
            }
            while((line = br.readLine()) != null) {
                if(line.length()<1)continue;
                SocketAddress pcapSocketAddress=new SocketAddress();
                SocketAddress serverSocketAddress=new SocketAddress();
                line=line.substring(line.indexOf("dstIP")+6);
                pcapSocketAddress.address=InetAddress.getByName(line.substring(0, line.indexOf(" ")));
                line=line.substring(line.indexOf("dstPort")+8);
                pcapSocketAddress.port=Integer.parseInt(line.substring(0,line.indexOf(" ")));
                line=line.substring(line.indexOf("simIP")+6);
                serverSocketAddress.address=InetAddress.getByName(line.substring(0, line.indexOf(" ")));
                line=line.substring(line.indexOf("simPort")+8);
                serverSocketAddress.port=Integer.parseInt(line.substring(0));
                
                addressMap.put(pcapSocketAddress.getString(), serverSocketAddress);
                System.out.println("Mapping "+pcapSocketAddress.getString()+" to "+serverSocketAddress.getString()+" len "+addressMap.size());
            }
            System.out.println(""+addressMap.size());
        } catch (FileNotFoundException ex) {
            Logger.getLogger(PcapParser.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(PcapParser.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    private class SocketAddress{
        public InetAddress address;
        public int port;
        
        String getString(){
            return ""+address.toString()+" "+port;
        }
    }
    private class MyPacketHandler implements PacketHandler{
        SocketAddress pcapSocketAddress;
        InetAddress dstIP;
        int dstPort;

        public MyPacketHandler() {
            pcapSocketAddress=new SocketAddress();
        }
        

        @Override
        public boolean nextPacket(Packet packet) throws IOException {
            //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
            if (packet.hasProtocol(Protocol.TCP)) {
                    
                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    
                    if(tcpPacket.isPSH()){
                        Buffer buffer = tcpPacket.getPayload();
//                        System.out.println("TCP: " + buffer);
                    }
                } else if (packet.hasProtocol(Protocol.UDP)) {

                    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                    //System.out.println(stream.getString()+" ::::::"+st.getString());
                    pcapSocketAddress.address=InetAddress.getByName(udpPacket.getSourceIP());
                    pcapSocketAddress.port=udpPacket.getSourcePort();
                    //System.out.println("Printing if followed Socket contains "+pcapSocketAddress.getString()+" "+followedSocket.contains(pcapSocketAddress));
                    
                    if(isFollowed(pcapSocketAddress)){
                        dstIP=InetAddress.getByName(udpPacket.getDestinationIP());
                        dstPort=udpPacket.getDestinationPort();
                        //System.out.println(pcapSocketAddress.getString());
                        PacketInfo packetInfo=new PacketInfo(pcapSocketAddress.address,dstIP,pcapSocketAddress.port,dstPort,udpPacket.getArrivalTime(),udpPacket.getPayload().getArray());
                        packetList.add(packetInfo);
                    }
                    pcapSocketAddress.address=InetAddress.getByName(udpPacket.getDestinationIP());
                    pcapSocketAddress.port=udpPacket.getDestinationPort();
                    if(isFollowed(pcapSocketAddress))shouldReceive++;
                }
                return true;
        }
        
    }
    private boolean isFollowed(SocketAddress socketAddress){
//        System.out.println(""+followedSocket.size());
        for(SocketAddress socketAddress1:followedSocket){
            if(socketAddress1.getString().equals(socketAddress.getString()))return true;
        }
        
        return false;
    }
    
    private class EndChecker extends Thread{
        @Override
        public void run(){
            while(System.currentTimeMillis()<lastReceived+3000);
            System.out.println("Total Received = "+receivedCount);
            System.out.println("Should receive = "+shouldReceive);
            double lossPercent=((double)(shouldReceive-receivedCount)/(double)shouldReceive)*100;
            System.out.println("% of loss = "+lossPercent);
            for(UdpReceiver thread:threadList){
                thread.interrupt();
            }
            String result=">>>>>>>> Test count "+PcapParser.testCount+" && sleep time "+(PcapParser.sleepTime*PcapParser.testCount)+" <<<<<<<<<<<<<\n"+startTime+"\n";
            for(DatagramSocket socket:socketList){
                result=result+" "+socket.getLocalSocketAddress().toString();
                socket.close();
            }
            result=result+"\nTotal Received = "+receivedCount+"\nShould receive = "+shouldReceive+"\n% of loss = "+lossPercent+"\n\n\n\n";
            
            
            try {
                Files.write(Paths.get("config.dib"), result.getBytes(), StandardOpenOption.APPEND);
            }catch (IOException e) {
                //exception handling left as an exercise for the reader
            }
        }
    }
    private class UdpReceiver extends Thread{
        DatagramPacket packet;
        DatagramSocket socket;

        public UdpReceiver(DatagramSocket so) {
            socket=so;
            packet=new DatagramPacket(new byte[2000], 2000);
            System.out.println("Udp receiver started at "+socket.getLocalSocketAddress().toString());
        }
        
        @Override
        public void run(){
            try {
                //socket.setSoTimeout(3000);
                while(true){

                        socket.receive(packet);
                        lastReceived=System.currentTimeMillis();
                        receivedCount++;
                        System.out.println("Packet received length = "+packet.getLength()+" count -------- "+receivedCount);

                }
            } catch (IOException ex) {
                //Logger.getLogger(ServerPcapSimulator.class.getName()).log(Level.SEVERE, null, ex);
                System.out.println("Receiver Stopped at "+socket.getLocalSocketAddress());
            }
        }
    }
    private void printList(){
        for(PacketInfo packetInfo:packetList){
            System.out.println("srcIp:"+packetInfo.srcAddress.toString()+" srcPort:"+packetInfo.srcPort+" dstIP:"+packetInfo.dstAddress.toString()+" dstPort:"+packetInfo.dstPort+" len:"+packetInfo.data.length+" time "+packetInfo.time);
        }
    }
    
}
