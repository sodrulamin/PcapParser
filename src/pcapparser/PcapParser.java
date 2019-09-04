/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pcapparser;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Sodrul Amin Shaon
 */
public class PcapParser extends Thread{

    /**
     * @param args the command line arguments
     */
    static long sleepTime=0;
    static int testCount=0;
    public static void main(String[] args) {
        // TODO code application logic here
//        PcapParser parser=new PcapParser();
//        parser.readServerConfigFile();
//        parser.readClientConfigFile();
//        testCount=0;
//        sleepTime=0;
//        PcapParser pcapParser=new PcapParser();
//        pcapParser.start();
        if(args.length>0){
            String fileName = args[0];
            new ProvisioningPacketFinder(fileName).start();
        }else{
            new ProvisioningPacketFinder("test.pcap").start();
        }
//        FileLineReplacer.test();
        
    }
    @Override
    public void run(){
        while(true){
            
            try {
                //Thread.sleep(sleepTime*testCount);
                Thread.sleep(sleepTime);
            } catch (InterruptedException ex) {
                Logger.getLogger(PcapParser.class.getName()).log(Level.SEVERE, null, ex);
            }
            System.out.println("TestCount "+testCount);
            testCount++;
            ClientUdpSimulation clientUdpSimulation=new ClientUdpSimulation();
            ServerUdpSimulation serverUdpSimulation=new ServerUdpSimulation();
            clientUdpSimulation.start();
            //serverUdpSimulation.start();
            try {
                //clientUdpSimulation.join();
                serverUdpSimulation.join();
            } catch (InterruptedException ex) {
                Logger.getLogger(PcapParser.class.getName()).log(Level.SEVERE, null, ex);
            }
            sleepTime=300000;
//            if(testCount>=100)
                break;
            //break;
        }
    }
    
    
    
    
    private void readServerConfigFile(){
        String fileName="";
        try {
            BufferedReader br = new BufferedReader(new FileReader("server.config"));
            InetAddress srcIP,dstIP,simIP;
            int srcPort,dstPort,simPort,socketNumber;
            String line;
            int index;
            line=br.readLine();
            if(line!=null)
                fileName=line;
            else{
                System.out.println("server.config file is unreadable\nPut the pcap file in the first line.");
                return;
            }
            line=br.readLine();
            if(line==null){
                System.out.println("client.config file in bad format.\nPut socket count after file name");
                return;
            }
            int socketCount=Integer.parseInt(line);
            ArrayList<DatagramSocket> socketList=new ArrayList<>();
            while(socketCount>0 && (line = br.readLine()) != null){
                if(line==null)continue;
                line=line.substring(line.indexOf("simIP")+6);
                simIP=InetAddress.getByName(line.substring(0, line.indexOf(" ")));
                line=line.substring(line.indexOf("simPort")+8);
                simPort=Integer.parseInt(line.substring(0));
                
                DatagramSocket socket=new DatagramSocket(simPort,simIP);
                socketList.add(socket);
                socketCount--;
                
            }
            index=0;
            while((line = br.readLine()) != null) {
                if(line.length()<1)continue;
                line=line.substring(line.indexOf("srcIP")+6);
                srcIP=InetAddress.getByName(line.substring(0, line.indexOf(" ")));
                line=line.substring(line.indexOf("srcPort")+8);
                srcPort=Integer.parseInt(line.substring(0,line.indexOf(" ")));
                line=line.substring(line.indexOf("dstIP")+6);
                dstIP=InetAddress.getByName(line.substring(0, line.indexOf(" ")));
                line=line.substring(line.indexOf("dstPort")+8);
                dstPort=Integer.parseInt(line.substring(0,line.indexOf(" ")));
                Stream stream=new Stream(srcIP,srcPort,dstIP,dstPort,index++);
                line=line.substring(line.indexOf("socketNumber")+13);
                socketNumber=Integer.parseInt(line.substring(0));
                new Thread(new ServerPcapSimulator(socketList.get(socketNumber),fileName,stream)).start();
                System.out.println(srcIP.toString()+" "+srcPort+" "+dstIP.toString()+" "+dstPort);
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(PcapParser.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(PcapParser.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    private void readClientConfigFile(){
        String fileName="";
        try {
            BufferedReader br = new BufferedReader(new FileReader("client.config"));
            InetAddress srcIP,dstIP,simIP;
            int srcPort,dstPort,simPort,socketNumber,index;
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
            int socketCount=Integer.parseInt(line);
            ArrayList<DatagramSocket> socketList=new ArrayList<>();
            while(socketCount>0 && (line = br.readLine()) != null){
                if(line==null)continue;
                int port=Integer.parseInt(line);
                if(port!=0){
                    DatagramSocket socket=new DatagramSocket(port);
                    socketList.add(socket);
                    socketCount--;
                }
            }
            index=0;
            while((line = br.readLine()) != null) {
                if(line.length()<1)continue;
                line=line.substring(line.indexOf("srcIP")+6);
                srcIP=InetAddress.getByName(line.substring(0, line.indexOf(" ")));
                line=line.substring(line.indexOf("srcPort")+8);
                srcPort=Integer.parseInt(line.substring(0,line.indexOf(" ")));
                line=line.substring(line.indexOf("dstIP")+6);
                dstIP=InetAddress.getByName(line.substring(0, line.indexOf(" ")));
                line=line.substring(line.indexOf("dstPort")+8);
                dstPort=Integer.parseInt(line.substring(0,line.indexOf(" ")));
                line=line.substring(line.indexOf("simIP")+6);
                simIP=InetAddress.getByName(line.substring(0, line.indexOf(" ")));
                line=line.substring(line.indexOf("simPort")+8);
                simPort=Integer.parseInt(line.substring(0,line.indexOf(" ")));
                Stream stream=new Stream(srcIP,srcPort,dstIP,dstPort,index++);
                line=line.substring(line.indexOf("socketNumber")+13);
                socketNumber=Integer.parseInt(line.substring(0));
                
                new Thread(new ClientPcapSimulator(simIP,simPort,fileName,stream,socketList.get(socketNumber))).start();
                System.out.println(srcIP.toString()+" "+srcPort+" "+dstIP.toString()+" "+dstPort+" "+" "+simPort);
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(PcapParser.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(PcapParser.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
