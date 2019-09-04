/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pcapparser;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Sodrul Amin Shaon
 */
public class Stream {
    InetAddress srcAddress;
    InetAddress dstAddress;
    int srcPort;
    int dstPort;
    int streamId;

    public Stream() {
    }
    public Stream(String srca,int srcp,String dsta,int dstp,int id){
        try {
            srcAddress=InetAddress.getByName(srca);
            srcPort=srcp;
            dstAddress=InetAddress.getByName(dsta);
            dstPort=dstp;
            streamId=id;
        } catch (UnknownHostException ex) {
            Logger.getLogger(Stream.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public Stream(InetAddress srca,int srcp,InetAddress dsta,int dstp,int id){
        srcAddress=srca;
        srcPort=srcp;
        dstAddress=dsta;
        dstPort=dstp;
        streamId=id;
    }
    public String getString(){
        return srcAddress.toString()+":"+srcPort+" "+dstAddress.toString()+":"+dstPort;
    }
}
