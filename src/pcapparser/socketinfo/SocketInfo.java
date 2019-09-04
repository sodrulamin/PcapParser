/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pcapparser.socketinfo;

import java.util.ArrayList;

/**
 *
 * @author Sodrul Amin Shaon
 */
public class SocketInfo {
    ArrayList<SocketClass> socketMap=new ArrayList<>();

    public ArrayList<SocketClass> getSocketMap() {
        return socketMap;
    }
    
    public SocketClass getSocket(int srcPort,int dstPort){
        for(SocketClass socketClass:socketMap){
            if(socketClass.srcPort==srcPort && socketClass.dstPort==dstPort)return socketClass;
        }
        return null;
    }
    public boolean addInstance(int srcPort,int dstPort){
        if(getSocket(srcPort, dstPort)!=null)return false;
        SocketClass socketClass=new SocketClass();
        socketClass.srcPort=srcPort;
        socketClass.dstPort=dstPort;
        
        socketMap.add(socketClass);
        return true;
    }
    public boolean addInstance(SocketClass socketClass){
        socketMap.add(socketClass);
        return true;
    }
    public void deleteInstance(SocketClass socketClass){
        socketMap.remove(socketClass);
    }
}
