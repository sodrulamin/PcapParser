/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pcapparser.socketinfo;

import java.net.InetAddress;
import java.net.Socket;

/**
 *
 * @author Sodrul Amin Shaon
 */
public class SocketClass {
    Socket socket;
    InetAddress srcAddr,dstAddr;
    int srcPort,dstPort;

    public SocketClass() {
        socket=null;
        srcAddr=null;
        dstAddr=null;
    }
    
    
}
