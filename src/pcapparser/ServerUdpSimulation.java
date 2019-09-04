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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
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
public class ServerUdpSimulation extends Thread{
    String fileName;
    ArrayList<SocketAddress> followedSocket;
    ArrayList<DatagramSocket> socketList;
    ArrayList<UdpReceiver> threadList;
    HashMap<String,DatagramSocket> socketMap;
    HashMap<String, SocketAddress> addressMap;
    ArrayList<PacketInfo> packetList;
    ArrayList<String> receivedSequence;
    ArrayList<String> realTimeReceivedSequence;
    boolean started;
    
    int receivedCount,shouldReceive,sentCount;
    long lastReceived,startTime;
    
    public ServerUdpSimulation(){
        fileName="";
        followedSocket=new ArrayList<>();
        socketMap=new HashMap<>();
        packetList=new ArrayList<>();
        addressMap=new HashMap<>();
        receivedSequence=new ArrayList<>();
        threadList=new ArrayList<>();
        socketList=new ArrayList<>();
        realTimeReceivedSequence=new ArrayList<>();
        
        receivedCount=0;
        shouldReceive=0;
        sentCount=0;
        started=false;
        lastReceived=0;
    }
    
    @Override
    public void run(){
        readServerConfiguration();
        try {
            //downloadFile(fileName);
            Pcap pcap = Pcap.openStream(fileName);
            MyPacketHandler packetHandler=new MyPacketHandler();
            pcap.loop(packetHandler);
            System.out.println(receivedSequence.size());
            for(SocketAddress socketAddress: followedSocket){
                UdpReceiver thread=new UdpReceiver(socketMap.get(socketAddress.getString()));//.start();
                threadList.add(thread);
                thread.start();
            }
            for(String str:receivedSequence){
                System.out.println(""+str);
            }
            
            System.out.println("Should receive "+shouldReceive);
            System.out.println("Sending "+packetList.size());
            while(!started){
                Thread.sleep(1);
            }
            startTime=System.currentTimeMillis();
            System.out.println("Server started");
            long virtualStartTime=packetList.get(0).time,realStartTime=System.currentTimeMillis(),virtualSendTime,realSendTime;
            SocketAddress socketAddress=new SocketAddress(),sendAddress;
            DatagramSocket socket;
            for(PacketInfo packetInfo:packetList){
                virtualSendTime=packetInfo.time;
                realSendTime=realStartTime+(virtualSendTime-virtualStartTime)/1000;
                Thread.sleep(Math.max(realSendTime-System.currentTimeMillis(),0));
//                while(System.currentTimeMillis()<(realSendTime)){
                    //System.out.println(realSendTime+" --- "+System.currentTimeMillis());
//                }
                ///retrieving socket
                socketAddress.address=packetInfo.srcAddress;
                socketAddress.port=packetInfo.srcPort;
                socket=socketMap.get(socketAddress.getString());
                
                
                ///retrieving sending address
                socketAddress.address=packetInfo.dstAddress;
                socketAddress.port=packetInfo.dstPort;
                sendAddress=addressMap.get(socketAddress.getString());
                
                sentCount++;
                if(sendAddress==null){
                    System.out.println("Send address is null so data is not sent properly..................");
                    continue;
                }
                socket.send(createPacket(sendAddress, packetInfo.data));
                
                System.out.println("Packet sent len "+packetInfo.data.length+" count ---------- "+ sentCount);
            }
            new EndChecker().start();
        } catch (IOException ex) {
            Logger.getLogger(ClientUdpSimulation.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedException ex) {
            Logger.getLogger(ServerUdpSimulation.class.getName()).log(Level.SEVERE, null, ex);
        }
        
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
            String result=">>>>>>>> Test count "+PcapParser.testCount+" && start time "+startTime+" <<<<<<<<<<<<<\n";
            for(DatagramSocket socket:socketList){
                result=result+" "+socket.getLocalSocketAddress().toString();
                while(!socket.isClosed()){
                    try{
                        socket.close();
                    }catch(Exception e){
                    }
                }
            }
            result=result+"\nTotal Received = "+receivedCount+"\nShould receive = "+shouldReceive+"\n% of loss = "+lossPercent+"\n\n\n\n";
            
            try {
                File file=new File("config.dib");
                if(!file.exists()){
                    file.createNewFile();
                }
                Files.write(Paths.get("config.dib"), result.getBytes(), StandardOpenOption.APPEND);
            }catch (IOException e) {
            }
        }
    }
    private class UdpReceiver extends Thread{
        DatagramPacket packet;
        DatagramSocket socket;
        SocketAddress socketAddress;

        public UdpReceiver(DatagramSocket so) {
            socketAddress=new SocketAddress();
            socket=so;
            packet=new DatagramPacket(new byte[2000], 2000);
            System.out.println("Udp receiver started at "+socket.getLocalSocketAddress().toString());
        }
        
        @Override
        public void run(){
            try {
                while(true){
                    socket.receive(packet);
                    if(!started){
                        started=true;
                        System.out.println("Server started");
                    }
                    receivedCount++;
                    lastReceived=System.currentTimeMillis();
                    socketAddress.address=packet.getAddress();
                    socketAddress.port=packet.getPort();
                    if(!realTimeReceivedSequence.contains(socketAddress.getString())){
                        realTimeReceivedSequence.add(socketAddress.getString());
                        addressMap.put(receivedSequence.get(realTimeReceivedSequence.indexOf(socketAddress.getString())), socketAddress);
                    }
                    System.out.println("Packet received length = "+packet.getLength()+" count -------- "+receivedCount);
                }
            } catch (IOException ex) {
                //Logger.getLogger(ServerPcapSimulator.class.getName()).log(Level.SEVERE, null, ex);
                System.out.println("Receiver stopped at "+socket.getLocalSocketAddress());
            }
        }
    }
    public void readServerConfiguration(){
        //downloadFile("server.config");
        try {
            FileReader fr=new FileReader("server.config");
            BufferedReader br = new BufferedReader(fr);
            String line;
            line=br.readLine();
            if(line!=null)
                fileName=line;
            else{
                System.out.println("server.config file is unreadable\nPut the pcap file in the first line.");
                return;
            }
            line=br.readLine();
            if(line==null){
                System.out.println("server.config file in bad format.\nPut socket count after file name");
                return;
            }
            int socketCount=Integer.parseInt(line),port;
            InetAddress address;
            while(socketCount>0 && (line = br.readLine()) != null){
                if(line==null)continue;
                SocketAddress socketAddress=new SocketAddress();
                line=line.substring(line.indexOf("simIP")+6); ///reading local ip address to create datagram socket
                address=InetAddress.getByName(line.substring(0,line.indexOf(" ")));
                line=line.substring(line.indexOf("simPort")+8);   ////reading local port number to create datagram socket
                port=Integer.parseInt(line.substring(0, line.indexOf(" ")));
                line=line.substring(line.indexOf("srcIP")+6); ////reading src ip to be followd of the pcap file
                socketAddress.address=InetAddress.getByName(line.substring(0,line.indexOf(" ")));
                line=line.substring(line.indexOf("srcPort")+8); ///reading src port to be followed ot the pcap file
                socketAddress.port=Integer.parseInt(line);
                followedSocket.add(socketAddress);            ////allowed sockets amongs all the sockets in the pcap file
                if(port!=0){
                    DatagramSocket socket=new DatagramSocket(port,address);
                    socketMap.put(socketAddress.getString(), socket);
                    socketList.add(socket);
                    socketCount--;
                }
            }
            System.out.println("Following these sockets.");
            for(SocketAddress socketAddress:followedSocket){
                System.out.println(""+socketAddress.address.toString()+" "+socketAddress.port);
            }
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
        SocketAddress pcapSocketAddress,dstSocketAddress;
        InetAddress dstIP;
        int dstPort;

        public MyPacketHandler() {
            pcapSocketAddress=new SocketAddress();
            dstSocketAddress=new SocketAddress();
        }
        

        @Override
        public boolean nextPacket(Packet packet) throws IOException {
            //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
            if (packet.hasProtocol(Protocol.TCP)) {
                    
                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    
                    if(tcpPacket.isPSH()){
                        Buffer buffer = tcpPacket.getPayload();
                        //System.out.println("TCP: " + buffer);
                    }
                } else if (packet.hasProtocol(Protocol.UDP)) {

                    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                    //System.out.println(stream.getString()+" ::::::"+st.getString());
                    pcapSocketAddress.address=InetAddress.getByName(udpPacket.getSourceIP());
                    pcapSocketAddress.port=udpPacket.getSourcePort();
                    //System.out.println("Printing if followed Socket contains "+pcapSocketAddress.getString()+" "+followedSocket.contains(pcapSocketAddress));
                    dstSocketAddress.address=InetAddress.getByName(udpPacket.getDestinationIP());
                    dstSocketAddress.port=udpPacket.getDestinationPort();
                    
                    if(isFollowed(pcapSocketAddress)){
                        dstIP=InetAddress.getByName(udpPacket.getDestinationIP());
                        dstPort=udpPacket.getDestinationPort();
                        //System.out.println(pcapSocketAddress.getString());
                        PacketInfo packetInfo=new PacketInfo(pcapSocketAddress.address,dstIP,pcapSocketAddress.port,dstPort,udpPacket.getArrivalTime(),udpPacket.getPayload().getArray());
                        packetList.add(packetInfo);
                    }
                    else if(isFollowed(dstSocketAddress)){
                        shouldReceive++;
                        if(!receivedSequence.contains(pcapSocketAddress.getString())){
                            receivedSequence.add(pcapSocketAddress.getString());
                        }
                    }
                }
                return true;
        }
        
    }
    private boolean isFollowed(SocketAddress socketAddress){
        //System.out.println(""+followedSocket.size());
        for(SocketAddress socketAddress1:followedSocket){
            if(socketAddress1.getString().equals(socketAddress.getString()))return true;
        }
        
        return false;
    }
    private DatagramPacket createPacket(SocketAddress dstAddress,byte [] data){
        
        return new DatagramPacket(data, data.length,dstAddress.address,dstAddress.port);
    }
    
}
