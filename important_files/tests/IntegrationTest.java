import java.net.*;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.math.*;
import java.util.*;
import java.security.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public final class IntegrationTest {
    static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);}
    record P2Result(long[][] vectors,long[] triples,long flag){}
    static P2Result p2Side(ServerSocket listener,boolean first)throws Exception{
        try(Socket s=listener.accept()){
            s.setSoTimeout(10000);
            DataInputStream in=new DataInputStream(new BufferedInputStream(s.getInputStream()));
            DataOutputStream out=new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
            if(first){out.writeLong(1);out.writeLong(0);out.writeLong(2);out.writeLong(1);out.flush();}
            int[] sizes={2,2,2,2,4,4};long[][] vectors=new long[6][];
            for(int k=0;k<sizes.length;k++){
                vectors[k]=new long[sizes[k]];
                for(int i=0;i<sizes[k];i++)vectors[k][i]=in.readLong();
            }
            check(in.readLong()==5,"triple count should be 5 (one comparison)");
            long[] triples=new long[15];for(int i=0;i<triples.length;i++)triples[i]=in.readLong();
            out.writeLong(first?0:-1);out.flush();
            long f=in.readLong();
            out.writeLong(0);out.flush();
            return new P2Result(vectors,triples,f);
        }
    }
    static void testP2()throws Exception{
        ExecutorService threads=Executors.newFixedThreadPool(2);
        try(ServerSocket l0=new ServerSocket();ServerSocket l1=new ServerSocket()){
            l0.setReuseAddress(true);l1.setReuseAddress(true);
            l0.bind(new InetSocketAddress("127.0.0.1",6001));l1.bind(new InetSocketAddress("127.0.0.1",6002));
            Future<P2Result> f0=threads.submit(()->p2Side(l0,true));
            Future<P2Result> f1=threads.submit(()->p2Side(l1,false));
            Process proc=new ProcessBuilder("java","-cp",System.getProperty("java.class.path"),"P2").redirectErrorStream(true).start();
            P2Result a=f0.get(15,TimeUnit.SECONDS),b=f1.get(15,TimeUnit.SECONDS);
            check(proc.waitFor(10,TimeUnit.SECONDS)&&proc.exitValue()==0,"P2 process: "+new String(proc.getInputStream().readAllBytes()));
            long[] w=new long[4];for(int i=0;i<4;i++)w[i]=a.vectors()[5][i]+b.vectors()[5][i];
            check(w[0]+w[1]==1&&w[2]+w[3]==1&&w[0]+w[2]==1&&w[1]+w[3]==1,"W must be permutation matrix");
            for(int i=0;i<15;i+=3){
                long x=a.triples()[i]+b.triples()[i],y=a.triples()[i+1]+b.triples()[i+1],z=a.triples()[i+2]+b.triples()[i+2];
                check(x*y==z,"Beaver triple at "+i);
            }
            check(a.flag()+b.flag()==1,"P2 descending swap flag");
            System.out.println("PASS: P2 two TCP channels / share vectors / permutation / Beaver triples / compare flag");
        }finally{threads.shutdownNow();}
    }
    static void testProver()throws Exception{
        Path dir=Files.createTempDirectory("prover-java-test-");
        SecureRandom rng=new SecureRandom();
        BigInteger priv=BigInteger.valueOf(29),nonce=BigInteger.valueOf(197);
        Path privFile=dir.resolve("key.hex");
        Files.writeString(privFile,HexFormat.of().formatHex(Secp256k1Ecies.to32(priv)));
        byte[] eph=Secp256k1Ecies.compress(Secp256k1Ecies.publicFromPrivate(nonce));
        byte[] key=MessageDigest.getInstance("SHA-256").digest(Secp256k1Ecies.to32(Secp256k1Ecies.mul(nonce,Secp256k1Ecies.publicFromPrivate(priv)).x));
        String plain=SimpleJson.stringify(SimpleJson.map("sender","p0","party_id",0,"session_id",22,"dataset_kind",1,"payload_type","perm_smoke_test"));
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");byte[] iv=new byte[12];rng.nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));
        byte[] c=cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        String transport=SimpleJson.stringify(SimpleJson.map("sender","p0","party_id",0,"session_id",22,"dataset_kind",1,
            "eph_pub_hex",HexFormat.of().formatHex(eph),"iv_hex",HexFormat.of().formatHex(iv),
            "tag_hex",HexFormat.of().formatHex(Arrays.copyOfRange(c,c.length-16,c.length)),
            "ciphertext_hex",HexFormat.of().formatHex(Arrays.copyOfRange(c,0,c.length-16))));
        int port=7959;
        Process proc=new ProcessBuilder("java","-cp",System.getProperty("java.class.path"),"ProverParty",
            "--listen",Integer.toString(port),"--priv",privFile.toString(),"--out-dir",dir.resolve("out").toString(),
            "--no-make-input","--once").redirectErrorStream(true).start();
        try{
            Socket s=null;
            for(int i=0;i<80;i++){
                try{s=Wire.connect("127.0.0.1",port,500);break;}
                catch(IOException ex){Thread.sleep(50);}
            }
            check(s!=null,"ProverParty listener not ready");
            try(Socket socket=s){
                DataOutputStream out=new DataOutputStream(socket.getOutputStream());
                DataInputStream in=new DataInputStream(socket.getInputStream());
                Wire.writeString(out,transport);out.flush();
                Map<String,Object> ack=SimpleJson.object(Wire.readString(in));
                check(Boolean.TRUE.equals(ack.get("ok")),"prover ACK: "+ack);
                check(Files.readString(Path.of((String)ack.get("decrypted"))).equals(plain),"signed plaintext file");
            }
            check(proc.waitFor(8,TimeUnit.SECONDS)&&proc.exitValue()==0,"Prover process failed");
            System.out.println("PASS: ProverParty TCP / secp256k1 ECDH / authenticated decryption / output / ACK");
        }finally{proc.destroyForcibly();}
    }
    public static void main(String[] args)throws Exception{testP2();testProver();}
}
