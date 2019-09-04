/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pcapparser;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashSet;

/**
 *
 * @author Sodrul Amin Shaon
 */
public class FileLineReplacer {
    public static String fileName = "provisioning_ip_list_1122.txt";
    public static HashSet<String> headers;
    public static void test(){
        readLine();
    }
    
    public static void readLine(){
        try {
            File file = new File(fileName);
            if(!file.exists()){
                System.out.println("System could not find file "+fileName);
                return;
            }
            headers = new HashSet<>();
            String line = null;
            FileReader fileReader = new FileReader(file);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            
            while((line = bufferedReader.readLine()) != null) {
                if(line.length()<1)continue;
                line  = "ip addr add "+line+"/24 dev enp2s0f0";
                headers.add(line);
                System.out.println(line);
            }

            // Always close files.
            bufferedReader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
