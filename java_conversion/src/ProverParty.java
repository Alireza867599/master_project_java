import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Java 21 port of prover_party.cpp. Uses Secp256k1Ecies for interoperable transport. */
public final class ProverParty {
    private static final class Args {
        int listen=7800, maxN=128;
        Path priv=Path.of("keys/ProverParty.elg.priv");
        Path outDir=Path.of("zk-snark/perm_payloads"), sendedDir=Path.of("zk-snark");
        String node="node",tool="js/prover_payload_tool_babyjub_split_v2.cjs";
        boolean makeInput=true,once=false;
    }
    private static int parsePort(String v){int n=Integer.parseInt(v);if(n<1||n>65535)throw new IllegalArgumentException("bad port");return n;}
    private static Args parseArgs(String[] argv){
        Args a=new Args();
        for(int i=0;i<argv.length;i++){
            String f=argv[i];
            if(f.equals("--once")){a.once=true;continue;}
            if(f.equals("--no-make-input")){a.makeInput=false;continue;}
            if(f.equals("--help")||f.equals("-h")){
                System.out.println("Usage: java ProverParty [--listen PORT] [--priv PATH] [--out-dir PATH] [--sended-dir PATH] [--node NODE] [--perm-payload-tool PATH] [--max-n N] [--no-make-input] [--once]");
                System.exit(0);
            }
            if(i+1>=argv.length)throw new IllegalArgumentException("missing value for "+f);
            String v=argv[++i];
            switch(f){
                case "--listen"->a.listen=parsePort(v);
                case "--priv"->a.priv=Path.of(v);
                case "--out-dir"->a.outDir=Path.of(v);
                case "--sended-dir"->a.sendedDir=Path.of(v);
                case "--node"->a.node=v;
                case "--perm-payload-tool"->a.tool=v;
                case "--max-n"->{a.maxN=Integer.parseInt(v);if(a.maxN<1)throw new IllegalArgumentException("bad max-n");}
                default->throw new IllegalArgumentException("unknown argument: "+f);
            }
        }
        return a;
    }
    private static void write(Path path,String text)throws IOException{
        if(path.getParent()!=null)Files.createDirectories(path.getParent());
        Files.writeString(path,text,StandardCharsets.UTF_8);
    }
    private static String safeSender(String sender,long party){
        if(sender.equalsIgnoreCase("p0"))return "p0";
        if(sender.equalsIgnoreCase("p1"))return "p1";
        if(party==0)return "p0";if(party==1)return "p1";
        return "unknown";
    }
    private static String execute(String...args)throws Exception{
        Process p=new ProcessBuilder(args).redirectErrorStream(true).start();
        String stdout;
        try(InputStream input=p.getInputStream()){stdout=new String(input.readAllBytes(),StandardCharsets.UTF_8);}
        int status=p.waitFor();
        if(status!=0)throw new IOException("subprocess failed ("+status+"): "+stdout);
        return stdout;
    }
    @SuppressWarnings("unchecked")
    private static void upsert(Path file,String sender,long party,long session,long dataset,Path encrypted,Path decrypted,Map<String,Object> signed)throws IOException{
        Map<String,Object> rec=SimpleJson.map(
            "received_at_ms",System.currentTimeMillis(),"sender",sender,
            "party_id",new BigInteger(Long.toUnsignedString(party)),
            "session_id",new BigInteger(Long.toUnsignedString(session)),
            "dataset_kind",new BigInteger(Long.toUnsignedString(dataset)),
            "encrypted_received",encrypted.toString(),
            "decrypted_signed_payload_file",decrypted.toString(),"signed_payload",signed);
        List<Object> records=new ArrayList<>();
        if(Files.exists(file)){
            String old=Files.readString(file);
            if(!old.isBlank()){
                Object existing=SimpleJson.object(old).get("records");
                if(!(existing instanceof List<?> list))throw new IOException("invalid canonical records file");
                for(Object item:list){
                    if(!(item instanceof Map<?,?> m))throw new IOException("invalid canonical record");
                    Map<String,Object> prior=(Map<String,Object>)m;
                    if(SimpleJson.uint(prior,"party_id",-1)==party
                        && SimpleJson.uint(prior,"session_id",-1)==session
                        && SimpleJson.uint(prior,"dataset_kind",-1)==dataset)continue;
                    records.add(prior);
                }
            }
        }
        records.add(rec);
        String content=SimpleJson.stringify(SimpleJson.map("protocol","SFDAC-ProverReceivedAuctioneerData-v1","sender",sender,"records",records))+"\n";
        Path parent=file.getParent();if(parent!=null)Files.createDirectories(parent);
        Path tmp=Files.createTempFile(parent==null?Path.of("."):parent,"sended-",".tmp");
        try{
            Files.writeString(tmp,content,StandardCharsets.UTF_8);
            try{Files.move(tmp,file,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}
            catch(AtomicMoveNotSupportedException e){Files.move(tmp,file,StandardCopyOption.REPLACE_EXISTING);}
        }finally{Files.deleteIfExists(tmp);}
    }
    private static Map<String,Object> handleOne(Args a,String encryptedJson)throws Exception{
        Map<String,Object> enc=SimpleJson.object(encryptedJson);
        long transportParty=SimpleJson.uint(enc,"party_id",999999),
            transportDataset=SimpleJson.uint(enc,"dataset_kind",999999),
            transportSession=SimpleJson.uint(enc,"session_id",0);
        String transportSender=SimpleJson.string(enc,"sender","");
        String signedJson=Secp256k1Ecies.decrypt(encryptedJson,a.priv);
        Map<String,Object> plain=SimpleJson.object(signedJson);
        long party=SimpleJson.uint(plain,"party_id",transportParty),
            dataset=SimpleJson.uint(plain,"dataset_kind",transportDataset),
            session=SimpleJson.uint(plain,"session_id",transportSession);
        String sender=safeSender(SimpleJson.string(plain,"sender",transportSender),party);
        if(party>1||dataset>1)throw new IllegalArgumentException("invalid party_id/dataset_kind");
        if(transportParty!=999999&&transportParty!=party)throw new IllegalArgumentException("transport/plaintext party mismatch");
        if(transportDataset!=999999&&transportDataset!=dataset)throw new IllegalArgumentException("transport/plaintext dataset mismatch");
        if(transportSession!=0&&transportSession!=session)throw new IllegalArgumentException("transport/plaintext session mismatch");
        if(!transportSender.isEmpty()&&!safeSender(transportSender,transportParty).equals(sender))throw new IllegalArgumentException("sender mismatch");
        String type=SimpleJson.string(plain,"payload_type",SimpleJson.string(enc,"payload_type",""));
        boolean split=type.equals("auctioneer_dataset_reveal_split_signatures");
        boolean reveal=split||type.equals("auctioneer_dataset_reveal");
        Files.createDirectories(a.outDir);
        String base=sender+(reveal?"_auctioneer_dataset_session_":"_perm_session_")+Long.toUnsignedString(session)+"_dataset_"+Long.toUnsignedString(dataset);
        Path encPath=a.outDir.resolve(base+".encrypted.received.json"),
            decPath=a.outDir.resolve(base+".signed.decrypted.json"),
            inputPath=a.outDir.resolve(base+".input.json"),
            revealPath=a.outDir.resolve(base+".share_bids_randomness.json"),
            sendedPath=a.sendedDir.resolve("sended_"+sender+"data.json");
        write(encPath,encryptedJson);write(decPath,signedJson);
        if(split){
            if(!SimpleJson.string(plain,"signature_profile","").equals("babyjub-eddsa-poseidon-split-dataset-v2"))
                throw new IllegalArgumentException("unexpected split-signature profile");
            String checked=execute(a.node,a.tool,"verify-signed","--in",decPath.toString());
            // Verifier must explicitly report ok=true, not just exit 0.
            boolean verified=false;
            try{verified=Boolean.TRUE.equals(SimpleJson.object(checked.trim()).get("ok"));}catch(Exception ignored){}
            for(String line:checked.split("\\R")){
                try{verified|=Boolean.TRUE.equals(SimpleJson.object(line.trim()).get("ok"));}
                catch(Exception ignored){}
            }
            if(!verified)throw new IOException("split-signature verification failed: "+checked);
        }
        if(reveal){write(revealPath,signedJson);upsert(sendedPath,sender,party,session,dataset,encPath,decPath,plain);}
        else if(a.makeInput){System.out.println("Prover: make-input: "+execute(a.node,a.tool,"make-input","--in",decPath.toString(),"--out",inputPath.toString(),"--max-n",Integer.toString(a.maxN)));}
        System.out.println("Prover: received payload sender="+sender+" party_id="+party+" session_id="+Long.toUnsignedString(session)+" dataset_kind="+dataset+" payload_type="+type);
        return SimpleJson.map("ok",true,"sender",sender,"party_id",party,"session_id",new BigInteger(Long.toUnsignedString(session)),
            "dataset_kind",dataset,"payload_type",type,
            "encrypted_received",encPath.toString(),"decrypted",decPath.toString(),
            "share_bids_randomness",reveal?revealPath.toString():"",
            "canonical_sended_data",reveal?sendedPath.toString():"",
            "input",!reveal&&a.makeInput?inputPath.toString():"");
    }
    private static void serve(Args a)throws Exception{
        try(ServerSocket listener=new ServerSocket()){
            listener.setReuseAddress(true);
            listener.bind(new InetSocketAddress("0.0.0.0",a.listen),64);
            System.out.println("Prover: listening on 0.0.0.0:"+a.listen);
            do{
                try(Socket sock=listener.accept()){
                    sock.setSoTimeout(30000);
                    DataInputStream input=new DataInputStream(new BufferedInputStream(sock.getInputStream()));
                    DataOutputStream output=new DataOutputStream(new BufferedOutputStream(sock.getOutputStream()));
                    Map<String,Object> ack;
                    try{ack=handleOne(a,Wire.readString(input));}
                    catch(Exception e){ack=SimpleJson.map("ok",false,"error",e.toString());System.err.println("Prover: error: "+e);}
                    Wire.writeString(output,SimpleJson.stringify(ack));output.flush();
                }catch(IOException e){System.err.println("Prover: connection error: "+e);}
            }while(!a.once);
        }
    }
    public static void main(String[] argv){
        try{serve(parseArgs(argv));}
        catch(Exception e){System.err.println("Prover fatal error: "+e);System.exit(1);}
    }
}
