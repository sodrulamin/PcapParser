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
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Sodrul Amin Shaon
 */
public class ClientPcapSimulator implements Runnable{
    private static int staticPort=13545;
    String filename;
    DatagramSocket socket;
    private long lastFound,startTime,senderSleepTime;
    Map addressMap;
    int dstPort;
    static int sentCount=0,receivedCount=0;
    ArrayList<UdpPacketStream> udpPacketStream;
    Stream stream;
    InetAddress dstAddress;
    

    public ClientPcapSimulator(InetAddress address,int port,String fname,Stream st) {
        filename="F:\\Wirshark Capture\\BOTIM Logs\\BotIM3_Original.pcap";
        stream=st;
        filename=fname;
        try {
            socket=new DatagramSocket(staticPort++);
            System.out.println("PcapSimulatorUDP server started at "+socket.getLocalSocketAddress());
            dstAddress=address;
            dstPort=port;
            
        } catch (SocketException ex) {
            Logger.getLogger(ServerPcapSimulator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public ClientPcapSimulator(InetAddress address,int port,String fname,Stream st,DatagramSocket s) {
        filename="F:\\Wirshark Capture\\BOTIM Logs\\BotIM3_Original.pcap";
        stream=st;
        filename=fname;
        socket=s;
        System.out.println("PcapSimulatorUDP server started at "+socket.getLocalSocketAddress());
        dstAddress=address;
        dstPort=port;
    }
    
    public void run(){
        try {
            getStream();
            //printList();
            DatagramPacket packet=new DatagramPacket(new byte[2000], 2000);
            new Thread(new UdpReceiver(packet)).start();
            new Thread(new UdpSender()).start();
        } catch (IOException ex) {
            Logger.getLogger(ServerPcapSimulator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    private class UdpReceiver implements Runnable{
        DatagramPacket packet;

        public UdpReceiver(DatagramPacket p) {
            packet=p;
        }
        
        
        public void run(){
            while(true){
                try {
                    socket.receive(packet);
                    receivedCount++;
                    System.out.println("Packet received length = "+packet.getLength()+" count -------- "+receivedCount);
                } catch (IOException ex) {
                    Logger.getLogger(ServerPcapSimulator.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }
    private class UdpSender implements Runnable{
        
        public void run(){
            DatagramPacket packet;
            try {
                Thread.sleep(senderSleepTime);
                System.out.println("Sleep time ========= "+senderSleepTime);
            } catch (InterruptedException ex) {
                Logger.getLogger(ClientPcapSimulator.class.getName()).log(Level.SEVERE, null, ex);
            }
            for (UdpPacketStream packetStream : udpPacketStream) {
                try {
                    Thread.sleep(packetStream.sleepTime);
                    packet=createPacket(packetStream.packet, dstAddress, dstPort);
                    socket.send(packet);
                    sentCount++;
                    System.out.println("Packet sent len "+packet.getLength()+" count ---------- "+ sentCount);
                } catch (InterruptedException ex) {
                    Logger.getLogger(ServerPcapSimulator.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(ServerPcapSimulator.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            System.out.println("Simulation Completed");
        }
    }
    private void getStream() throws IOException{
        final Pcap pcap = Pcap.openStream(filename);
        udpPacketStream=new ArrayList<>();
        lastFound=0;
        startTime=0;
        pcap.loop(new PacketHandler() {

            @Override
            public boolean nextPacket(Packet packet) throws IOException {
                if(startTime==0)startTime=packet.getArrivalTime();
                if (packet.hasProtocol(Protocol.TCP)) {
                    
                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    
                    if(tcpPacket.isPSH()){
                        Buffer buffer = tcpPacket.getPayload();
                        //System.out.println("TCP: " + buffer);
                    }
                } else if (packet.hasProtocol(Protocol.UDP)) {

                    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                    Stream st=new Stream(udpPacket.getSourceIP(),udpPacket.getSourcePort(),udpPacket.getDestinationIP(),udpPacket.getDestinationPort(),stream.streamId);
                    //System.out.println(stream.getString()+" ::::::"+st.getString());
                    if(stream.getString().contentEquals(st.getString())){
                        if(lastFound==0){
                            lastFound=udpPacket.getArrivalTime();
                            senderSleepTime=(lastFound-startTime)/1000;
                        }
                        UdpPacketStream udp=new UdpPacketStream();
                        udp.packet=udpPacket;
                        udp.sleepTime=udpPacket.getArrivalTime()-lastFound;
                        udp.sleepTime=udp.sleepTime/1000;
                        lastFound=udpPacket.getArrivalTime();
                        udpPacketStream.add(udp);
                    }
                }
                return true;
            }
        });
        
    }
    private void printList(){
        //System.out.println(udpPacketStream.size());
        for (UdpPacketStream udpPacketStream1 : udpPacketStream) {
            //System.out.println(udpPacketStream1.packet.getSourceIP()+":"+udpPacketStream1.packet.getSourcePort()+"----"+udpPacketStream1.packet.getDestinationIP()+":"+udpPacketStream1.packet.getDestinationPort());
            System.out.println(udpPacketStream1.sleepTime);
        }
    }
    private class UdpPacketStream{
        UDPPacket packet;
        long sleepTime;
    }
    private DatagramPacket createPacket(UDPPacket packet,InetAddress address,int port){
        byte[] data=packet.getPayload().getArray();
        return new DatagramPacket(data, data.length,address,port);
    }
}
