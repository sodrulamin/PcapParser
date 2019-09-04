/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pcapparser.socketinfo;

import java.net.DatagramSocket;
import java.net.InetAddress;

/**
 *
 * @author Sodrul Amin Shaon
 */
public class PacketInfo {
    public InetAddress srcAddress,dstAddress;
    public int srcPort,dstPort;
    public long time;
    public byte [] data;

    public PacketInfo() {
        this.srcAddress = null;
        this.dstAddress = null;
        this.srcPort = 0;
        this.dstPort = 0;
        this.time = 0;
        this.data = null;
    }

    public PacketInfo(InetAddress srcAddress, InetAddress dstAddress, int srcPort, int dstPort, long time, byte[] data) {
        this.srcAddress = srcAddress;
        this.dstAddress = dstAddress;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.time = time;
        this.data = data;
    }
    PacketInfo(PacketInfo packetInfo){
        this.srcAddress = packetInfo.srcAddress;
        this.dstAddress = packetInfo.dstAddress;
        this.srcPort = packetInfo.srcPort;
        this.dstPort = packetInfo.dstPort;
        this.time = packetInfo.time;
        this.data = packetInfo.data;
    }
    
}
