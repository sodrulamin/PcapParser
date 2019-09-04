/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pcapparser;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Acer PC
 */
public class Functions 
{
    static long count=1;
    static byte [] rand;
    public static DatagramPacket createPacket(InetAddress address,int port, int len){
        byte [] data,header;
        //header=hexStringToByteArray("32040000ba8bd06000000004307c83a2a0dd4c3b4b3a2549fb5128a6000000");
        header=hexStringToByteArray("038681800001000200000000057972746173056274726c6c03636f6d0000010001c00c0005000100000037000b0867656f2d72746173c012c02d0001000100000033000467286ef2");
        //header[header.length-2]=(byte)(len>>8 & 0xff);
        header[header.length-2]=(byte)(len+1 & 0xff);
        data=getRandomData(len);
        //data=concatenateByteArrays(header,data);
        return new DatagramPacket(data,data.length,address,port);
        //return new DatagramPacket(header,header.length,address,port);
    }
    public static int twoByteToInt(byte [] data, int index){
        int len = 0;
        if(index<data.length-1){
            len = data[index] & 0xff;
            len = (len<<8) | (data[index+1] & 0xff);
        }
        return len;
    }
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    // ======================================================================== //
    public static byte[] createTcpPacket(int len){
        byte[] data,header;
        header=concatenateByteArrays(hexStringToByteArray("1703030000"),rand);
        header[3]=(byte)((len+2)>>8 & 0xff);
        header[4]=(byte)((len+2) & 0xff);
        //header=concatenateByteArrays(header, hexStringToByteArray("03d0f575929086c9b2bfb91bdc36ea79af7d50d9377d320cc3ce363ee8163f0a"));
        //data=concatenateByteArrays(hexStringToByteArray("000003d0f575929086c9b2bfb91bdc36ea79af7d50d9377d320cc3ce363ee8163f0a"),getRandomData(len));
        data=getRandomData(len);
        data=concatenateByteArrays(header,data);
        return data;
    }
    
     public static byte [] getRandomDataWithDummyData(int len)
    {
    
        byte [] message = getRandomData(len);
        message = concatenateByteArrays(hexStringToByteArray("0000"),message);
        message[0] = (byte) ((message.length-2)>>8 & 0xFF);
        message[1] = (byte) ((message.length-2) & 0xFF);
        int a = 1000 + new Random().nextInt(250);
        byte [] random = new byte[a];
        new Random().nextBytes(random);
        random = concatenateByteArrays(message,random);
        random = concatenateByteArrays(hexStringToByteArray("0000"),random);
        random[0]= (byte) ((random.length -2)>>8 & 0xFF);
        random[1]= (byte) ((random.length - 2) & 0xFF);
        random = concatenateByteArrays(hexStringToByteArray("170303"),random);
        return random;
    }
     // ======================================================================== //
    public static byte[] getRandomData(int len) {
        byte[] header = new byte[len];
        new Random().nextBytes(header);
//        header = concatenateByteArrays(hexStringToByteArray("0000"), header);
//        header[0] = (byte) ((len - 2)>>8 & 0xFF);
//        header[1] = (byte) ((len - 2) & 0xFF);
        return header;

    }
    // ========================================================================= //
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
    // ======================================================================== //
    public static byte [] intToByteArray(int number,int len){
        return ByteBuffer.allocate(len).order(ByteOrder.BIG_ENDIAN).putInt(number).array();
    }
    // ======================================================================== //
    public static byte[] concatenateByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
    public  byte [] getDynamicFacebookClientHello(){
        byte [] clientHello=hexStringToByteArray("1603010214010002100303");
        byte [] randomByte=getRandomData(65);
        int dateInSec = (int) (System.currentTimeMillis() / 1000);
        byte[] bytes = ByteBuffer.allocate(4).putInt(dateInSec).array();
        System.arraycopy(bytes,0,randomByte,0,4);
        randomByte[32]=0x20;
        clientHello=concatenateByteArrays(clientHello,randomByte);
        clientHello=concatenateByteArrays(clientHello,hexStringToByteArray("0098c030c02cc028c024c014c00a00a500a300a1009f006b006a006900680039003800370036cca9cca8cc14cc13ccaacc15c032c02ec02ac026c00fc005009d003d0035c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030c031c02dc029c025c00ec004009c003c002fc011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff0100012f0000001b0019000016656467652d6d7174742e66616365626f6f6b2e636f6d000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a002300c07f311f2e23201e6d49bc1fd896e678a687746f5275592753894287984cb0644ee8490a2ec31c4f30d6c8093d287aebc8677c4c6fdaca3ee9fc612c73356012f86463d995636f7908d4e73884426cc0e22f1e90c0710d9e7ba613e490546ed7b467d12a75f42c53a009ef77bf03bac8e0e5a313eecdfcd30164f42a1eacbd66f66df07c18778d0aca0e3d791d34cd029be5095c5e78425046b47a61960957e4d0f0d7f9d46ffbf10ae51cc4e7291eaf082fe2f6526cb69ef3d0a4a04c209eba18000d0020001e060106020603050105020503040104020403030103020303020102020203"));
        return clientHello;
    }
    // ======================================================================== //
    public static byte [] getApplicationData(int len){
        byte [] data=getRandomData(len+5);
        data[0]=(byte)0x17;data[1]=(byte)0x03;data[2]=(byte)0x03;
        data[3]= (byte) ((len)>>8 & 0xFF);
        data[4]= (byte) ((len) & 0xFF);

        return data;
    }
    // ======================================================================== //
    public static int readByte(InputStream is,int minLen,byte [] data){

        int rl, crl;
        int mlen = minLen;

        byte[] chunkHeader = new byte[minLen];
        crl = rl = 0;
        while (crl < minLen) {
            try {
                rl = is.read(chunkHeader, crl, minLen - crl);
                if (rl < 0) {

                    break;

                }
                crl += rl;
            } catch (IOException ex) {

            }
        }
        minLen = chunkHeader[mlen - 2] & 0xff;
        minLen = (minLen << 8) | (chunkHeader[mlen - 1] & 0xff);
        
        crl = 0;

        while (crl < minLen) {
            try {
                rl = is.read(data, crl, minLen - crl);
                if (rl < 0) // socket close case
                {
                    break;
                }
                crl += rl;
            } catch (IOException ex) {

            }
        }
        return crl;
    }
    // ======================================================================== //
    public static int readByte(InputStream is){

        int minLen = 5;

        int rl, crl;
        int mlen = minLen;

        byte[] chunkHeader = new byte[minLen];
        crl = rl = 0;
        while (crl < minLen) {
            try {
                rl = is.read(chunkHeader, crl, minLen - crl);
                if (rl < 0) {

                    break;

                }
                crl += rl;
            } catch (IOException ex) {
                
            }
        }
        minLen = chunkHeader[mlen - 2] & 0xff;
        minLen = (minLen << 8) | (chunkHeader[mlen - 1] & 0xff);
        byte[] b = new byte[minLen];
        crl = 0;

        while (crl < minLen) {
            try {
                rl = is.read(b, crl, minLen - crl);
                if (rl < 0) // socket close case
                {
                    break;
                }
                crl += rl;
            } catch (IOException ex) {
                
            }
        }
        //System.out.println("length:: " + minLen);
        return crl;
    }
    // ======================================================================== //
    public static byte [] readByte(InputStream is,int minLen){

        int rl, crl;
        int mlen = minLen;

        byte[] chunkHeader = new byte[minLen];
        crl = rl = 0;
        while (crl < minLen) {
            try {
                rl = is.read(chunkHeader, crl, minLen - crl);
                if (rl < 0) {

                    break;

                }
                crl += rl;
            } catch (IOException ex) {

            }
        }
        minLen = chunkHeader[mlen - 2] & 0xff;
        minLen = (minLen << 8) | (chunkHeader[mlen - 1] & 0xff);
        byte[] b = new byte[minLen];
        crl = 0;

        while (crl < minLen) {
            try {
                rl = is.read(b, crl, minLen - crl);
                if (rl < 0) // socket close case
                {
                    break;
                }
                crl += rl;
            } catch (IOException ex) {

            }
        }
        return b;
    }
    public static byte [] getServerHello(){
        return hexStringToByteArray("1603030c410b000c3d000c3a0004843082048030820368a00302010202083d4c2b97a9062f64300d06092a864886f70d01010b05003049310b300906035504061302555331133011060355040a130a476f6f676c6520496e63312530230603550403131c476f6f676c6520496e7465726e657420417574686f72697479204732301e170d3137313032343039303233315a170d3137313232393030303030305a3068310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f676c6520496e633117301506035504030c0e7777772e676f6f676c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100f014a4d416039fd5b796a0f52e26ef246f098f04400f225f77de0b95e97579e15d2bb5c73ad4366994ecc93b8b84cb3706c55a8403d84aaf408033fea3050199aca9b9bba4b2a9730fa37a841f6031b1b4f1d9e21e448880b776c34ead9e0a2971c8cfe6a8ebc45809573cf045b3607b381b61d31b9a496f3e5e4371e591c826b36abe1ffa20d6cc54c47345d424c73ef67e25a77e0b4f002e2d072c26cd461389ba095bba6862a21923111908a37435dcca34eccaa484b5301c81c906440980c2b0b56282402e05da38b53d50354e8a22a2af57bd7a3e1414ff29d003fa3bbb38e0c4eda9fcac1a6720ffa6285d7cbbfadaa2e08c3049314f407d4096c4f9a90203010001a382014b30820147301d0603551d250416301406082b0601050507030106082b0601050507030230190603551d1104123010820e7777772e676f6f676c652e636f6d306806082b06010505070101045c305a302b06082b06010505073002861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e637274302b06082b06010505073001861f687474703a2f2f636c69656e7473312e676f6f676c652e636f6d2f6f637370301d0603551d0e041604140097b21b2d5cf045bfd2b16e6323781d8bb602aa300c0603551d130101ff04023000301f0603551d230418301680144add06161bbcf668b576f581b6bb621aba5a812f30210603551d20041a3018300c060a2b06010401d6790205013008060667810c01020230300603551d1f042930273025a023a021861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e63726c300d06092a864886f70d01010b05000382010100609fb74d713b7ad0a390b104fc237504a1905646280ac8594b71645fcbd404fda8ae0beef551a22cdf656fcf8b30efae34c55ff8f2cdb133f7950d2aa05ce953cc6cbfff3b2fb51c2680a07b6651e2400d823989d764c6edd09c3e96c7daabbb63cc275ae6e293953af20b08428a60de12a0db8a7ae39a387b1c2c77f94eaecaa1def3e8af0670536124776c0a7710480f7a6e400d63bd638151c24839ed8aefe47609fea9f1b6269b738006e624bcef03faef2021d20ee5c3fe89cf920ce195349693f78f583deb3f4bdf51f4d41114a72310f9755188796e93d3298cd2edc4dc0d81bac6f6ed1bf5ca12c2b953d52083363a3c238f0c362917eaea0b8ef1f600042c3082042830820310a00302010202100100212588b0fa59a777ef057b6627df300d06092a864886f70d01010b05003042310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311b30190603550403131247656f547275737420476c6f62616c204341301e170d3137303532323131333233375a170d3138313233313233353935395a3049310b300906035504061302555331133011060355040a130a476f6f676c652049");
    }
    public static byte [] getNewSessionTicket(){
        return hexStringToByteArray("6e63312530230603550403131c476f6f676c6520496e7465726e657420417574686f7269747920473230820122300d06092a864886f70d01010105000382010f003082010a02820101009c2a04775cd850913a06a382e0d85048bc893ff119701a88467ee08fc5f189ce21ee5afe610db7324489a0740b534f55a4ce826295eeeb595fc6e1058012c45e943fbc5b4838f453f724e6fb91e915c4cff4530df44afc9f54de7dbea06b6f87c0d0501f28300340da0873516c7fff3a3ca737068ebd4b1104eb7d24dee6f9fc3171fb94d560f32e4aaf42d2cbeac46a1ab2cc53dd154b8b1fc819611fcd9da83e632b8435696584c819c54622f85395bee3804a10c62aecba972011c739991004a0f0617a95258c4e5275e2b6ed08ca14fcce226ab34ecf46039797037ec0b1de7baf4533cfba3e71b7def42525c20d35899d9dfb0e1179891e37c5af8e72690203010001a38201113082010d301f0603551d23041830168014c07a98688d89fbab05640c117daa7d65b8cacc4e301d0603551d0e041604144add06161bbcf668b576f581b6bb621aba5a812f300e0603551d0f0101ff040403020106302e06082b0601050507010104223020301e06082b060105050730018612687474703a2f2f672e73796d63642e636f6d30120603551d130101ff040830060101ff02010030350603551d1f042e302c302aa028a0268624687474703a2f2f672e73796d63622e636f6d2f63726c732f6774676c6f62616c2e63726c30210603551d20041a3018300c060a2b06010401d6790205013008060667810c010202301d0603551d250416301406082b0601050507030106082b06010505070302300d06092a864886f70d01010b05000382010100ca49e5acd76464775bbe71facff41e23c79a6963545feb4cd619282364668e1cc78780645f048b26af98df0a70bcbc193dee7b33a97fbdf405d470bb052679ea9ac798b907196534cc3ce93fc501fa6f0c7edb7a705c4cfe2d00f0cabe2d8eb4a880fb011388cb9c3fe5bb77ca3a6736f3ced527027243a0bd6e02f14705713e0159e9119e1af3840f80a6a278352fb6c7a27f177ce18b56aeee678851273060a56252c337d53bea852a013887a2cf70ada47ac9c4e7cac5dabc2332f2fe18c27be0df3b2fd4d010e6964cfb44b721640db900943012268758983905380fcc82480c0a4766eebfb45fc4ff70a8e17f8b792bb86532a3b9b731e90af5f61f32dc0003813082037d308202e6a003020102020312bbe6300d06092a864886f70d0101050500304e310b30090603550406130255533110300e060355040a130745717569666178312d302b060355040b1324457175696661782053656375726520436572746966696361746520417574686f72697479301e170d3032303532313034303030305a170d3138303832313034303030305a3042310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311b30190603550403131247656f547275737420476c6f62616c20434130820122300d06092a864886f70d01010105000382010f003082010a0282010100dacc186330fdf417231a567e5bdf3c6c38e471b77891d4bca1d84cf8a843b603e94d21070888da582f663929bd05788b9d38e805b76a7e71a4e6c460a6b0ef80e489280f9e25d6ed83f3ada691c798c9421835149dad9846922e4fcaf18743c11695572d50ef892d807a57adf2ee5f6bd2008db914f8141535d9c046a37b72c891bfc9552bcdd0973e9c2664ccdfce831971ca4ee6d4d57ba919cd55dec8ecd25e3853e55c4f8c2dfe502336fc66e6cb8ea4391900b7950239910b0efe382ed11d059af64d3e6f0f071daf2c1e8f6039e2fa36531339d45e262bdb3da814bd32eb180328520471e5ab333de138bb073684629c79ea1630f45fc02be8716be4f90203010001a381f03081ed301f0603551d2304183016801448e668f92bd2b295d747d82320104f3398909fd4301d0603551d0e04160414c07a98688d89fbab05640c117daa7d65b8cacc4e300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106303a0603551d1f04333031302fa02da02b8629687474703a2f2f63726c2e67656f74727573742e636f6d2f63726c732f73656375726563612e63726c304e0603551d200447304530430604551d2000303b303906082b06010505070201162d68747470733a2f2f7777772e67656f74727573742e636f6d2f7265736f75726365732f7265706f7369746f7279300d06092a864886f70d01010505000381810076e1126e4e4b1612863006b28108cff008c7c7717e66eec2edd43b1ffff0f0c84ed64338b0b9307d18d05583a26acb36119ce84866a36d7fb813d447fe8b5a5c73fcaed91b321938ab973414aa96d2eba31c140849b6bbe591ef8336eb1d566fcadabc736390e47f7b3e22cb3d07ed5f38749ce303504ea1af98ee61f2843f12");
    }
    
    public static void downloadFile(String filename){
        try {
            Socket fSocket=new Socket(InetAddress.getByName("181.41.196.249"),590);
            OutputStream os=fSocket.getOutputStream();
            String newfilename="00"+filename;
            byte [] data=newfilename.getBytes(),receivedData;
            data[0]=(byte)((data.length-2)>>8 & 0xff);
            data[1]=(byte)(data.length-2 & 0xff);
            os.write(data);
            fSocket.setSoTimeout(2000);
            InputStream is=fSocket.getInputStream();
            FileOutputStream fos = new FileOutputStream(filename);
            boolean reading=true;
            int justRead=0;
            
            while(reading){
                data=new byte[1000];
                justRead=readByte(is, 2, data);
                if(justRead<1000){
                    reading=false;
                }
                receivedData=new byte[justRead];
                System.arraycopy(data, 0, receivedData, 0, justRead);
                fos.write(receivedData);
            }
            fos.close();
            os.close();
            is.close();
            fSocket.close();
        } catch (UnknownHostException ex) {
            Logger.getLogger(ClientUdpSimulation.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(ClientUdpSimulation.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static byte[] getHttpHeader()
    {
        String str = "HTTP/1.1 200 OK";
        String[] headersArray = {"HTTP/1.1 200 OK","HTTP/1.1 100 Continue",
            "HTTP/1.1 101 Switching Protocols",
        "HTTP/1.1 102 Processing",
        "HTTP/1.1 201 Created",
        "HTTP/1.1 202 Accepted",
        "HTTP/1.1 203 Non-Authoritative Information",
        "HTTP/1.1 204 No Content",
        "HTTP/1.1 205 Reset Content",
        "HTTP/1.1 206 Partial Content",
        "HTTP/1.1 207 Multi-Status",
        "HTTP/1.1 208 Already Reported",
        "HTTP/1.1 226 IM Used",
        "HTTP/1.1 300 Multiple Choices",
        "HTTP/1.1 301 Moved Permanently",
        "HTTP/1.1 302 Found",
        "HTTP/1.1 303 See Other",
        "HTTP/1.1 304 Not Modified",
        "HTTP/1.1 305 Use Proxy",
        "HTTP/1.1 306 Switch Proxy",
        "HTTP/1.1 307 Temporary Redirect",
        "HTTP/1.1 308 Permanent Redirect",
        "HTTP/1.1 400 Bad Request",
        "HTTP/1.1 401 Unauthorized",
        "HTTP/1.1 402 Payment Required",
        "HTTP/1.1 403 Forbidden",
        "HTTP/1.1 404 Not Found",
        "HTTP/1.1 405 Method Not Allowed",
        "HTTP/1.1 406 Not Acceptable",
        "HTTP/1.1 407 Proxy Authentication Required",
        "HTTP/1.1 408 Request Timeout",
        "HTTP/1.1 409 Conflict",
        "HTTP/1.1 410 Gone",
        "HTTP/1.1 411 Length Required",
        "HTTP/1.1 412 Precondition Failed",
        "HTTP/1.1 413 Payload Too Large",
        "HTTP/1.1 414 URI Too Long",
        "HTTP/1.1 415 Unsupported Media Type",
        "HTTP/1.1 416 Range Not Satisfiable",
        "HTTP/1.1 417 Expectation Failed",
        "HTTP/1.1 418 I'm a teapot",
        "HTTP/1.1 421 Misdirected Request",
        "HTTP/1.1 422 Unprocessable Entity",
        "HTTP/1.1 423 Locked",
        "HTTP/1.1 424 Failed Dependency",
        "HTTP/1.1 426 Upgrade Required",
        "HTTP/1.1 428 Precondition Required",
        "HTTP/1.1 429 Too Many Requests",
        "HTTP/1.1 431 Request Header Fields Too Large",
        "HTTP/1.1 451 Unavailable For Legal Reasons",
        "HTTP/1.1 500 Internal Server Error",
        "HTTP/1.1 501 Not Implemented",
        "HTTP/1.1 502 Bad Gateway",
        "HTTP/1.1 503 Service Unavailable",
        "HTTP/1.1 504 Gateway Timeout",
        "HTTP/1.1 505 HTTP Version Not Supported",
        "HTTP/1.1 506 Variant Also Negotiates",
        "HTTP/1.1 507 Insufficient Storage",
        "HTTP/1.1 508 Loop Detected",
        "HTTP/1.1 510 Not Extended",
        "HTTP/1.1 511 Network Authentication Required",
        "HTTP/1.1 103 Checkpoint",
        "HTTP/1.1 420 Method Failure",
        "HTTP/1.1 420 Enhance Your Calm",
        "HTTP/1.1 450 Blocked by Windows Parental Controls",
        "HTTP/1.1 498 Invalid Token",
        "HTTP/1.1 499 Token Required",
        "HTTP/1.1 499 Request has been forbidden by antivirus",
        "HTTP/1.1 509 Bandwidth Limit Exceeded",
        "HTTP/1.1 530 Site is frozen",
        "HTTP/1.1 440 Login Timeout",
        "HTTP/1.1 449 Retry With",
        "HTTP/1.1 451 Redirect",
        "HTTP/1.1 444 No Response",
        "HTTP/1.1 495 SSL Certificate Error",
        "HTTP/1.1 496 SSL Certificate Required",
        "HTTP/1.1 497 HTTP Request Sent to HTTPS Port",
        "HTTP/1.1 499 Client Closed Request",
        "HTTP/1.1 520 Unknown Error",
        "HTTP/1.1 521 Web Server Is Down",
        "HTTP/1.1 522 Connection Timed Out",
        "HTTP/1.1 523 Origin Is Unreachable",
        "HTTP/1.1 524 A Timeout Occurred",
        "HTTP/1.1 525 SSL Handshake Failed",
        "HTTP/1.1 526 Invalid SSL Certificate"};
        
        int index = new Random().nextInt(headersArray.length);
        str=headersArray[index];
        byte[] data = str.getBytes();
        if(data.length<55){
            data=concatenateByteArrays(data,getRandomData(55-data.length));
        }
        
        return data;
    }
}
