import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Java 21 port of bidderboss.cpp. Preserves V2 bidder/auctioneer wire framing. */
public final class BidderBoss {
    static final String WIRE_MAGIC="SFDAC-BIDDER-PACKET-V2";
    static final String RELAY_MAGIC="SFDAC-MERKLE-EVIDENCE-V1";
    static final int MAX_CIPHER=4096;
    static final class Args {
        String mode="run",p0="127.0.0.1",p1="127.0.0.1",chainRpc="",registry="",ethPriv="";
        String signReceipt="scripts/sign_commitment_receipt.js",signEvidence="scripts/sign_merkle_evidence.js";
        String signVector="scripts/sign_commitment_vector.js",submitRoots="scripts/submit_commitment_roots.js";
        String answerChallenge="scripts/answer_commitment_challenge.js",metaDir="onchain",metaUri="file://onchain",pathFile="";
        int nbuyers=0,nsellers=0,listen=7500,revealPort=7700;
        long sessionId=0,challengeId=0;
    }
    static Args args(String[] argv){
        Args a=new Args();
        for(int i=0;i<argv.length;i++){
            String f=argv[i];if(i+1>=argv.length)throw new IllegalArgumentException("missing value for "+f);
            String v=argv[++i];
            switch(f){
                case "--mode"->a.mode=v;case "--nbuyers"->a.nbuyers=Integer.parseInt(v);
                case "--nsellers"->a.nsellers=Integer.parseInt(v);case "--listen"->a.listen=port(v);
                case "--reveal-port"->a.revealPort=port(v);
                case "--session-id"->a.sessionId=Long.parseUnsignedLong(v);
                case "--p0"->a.p0=v;case "--p1"->a.p1=v;case "--chain-rpc"->a.chainRpc=v;
                case "--auction-registry","--registry"->a.registry=v;case "--eth-priv"->a.ethPriv=v;
                case "--sign-receipt-tool"->a.signReceipt=v;
                case "--sign-merkle-evidence-tool"->a.signEvidence=v;
                case "--sign-commitment-vector-tool"->a.signVector=v;
                case "--submit-roots-tool"->a.submitRoots=v;
                case "--answer-challenge-tool"->a.answerChallenge=v;
                case "--metadata-dir"->a.metaDir=v;case "--metadata-uri-prefix"->a.metaUri=v;
                case "--challenge-id"->a.challengeId=Long.parseUnsignedLong(v);
                case "--path-file"->a.pathFile=v;
                default->throw new IllegalArgumentException("unknown argument: "+f);
            }
        }
        if(!Set.of("run","answer-challenge","finalize-challenge").contains(a.mode))throw new IllegalArgumentException("bad --mode");
        if(a.chainRpc.isEmpty()||a.registry.isEmpty()||a.ethPriv.isEmpty())throw new IllegalArgumentException("--chain-rpc --auction-registry --eth-priv required");
        if(a.mode.equals("run")&&(a.nbuyers<0||a.nsellers<0||a.nbuyers+a.nsellers==0))throw new IllegalArgumentException("run requires --nbuyers/--nsellers");
        if(a.mode.equals("answer-challenge")&&a.pathFile.isEmpty())throw new IllegalArgumentException("answer-challenge requires --path-file");
        return a;
    }
    static int port(String v){int n=Integer.parseInt(v);if(n<1||n>65535)throw new IllegalArgumentException("invalid port");return n;}
    static String u(long v){return Long.toUnsignedString(v);}
    static final class HybridCiphertext {
        byte[] eph,iv,tag,ct;
        static HybridCiphertext receive(DataInputStream in)throws IOException{
            HybridCiphertext h=new HybridCiphertext();
            h.eph=Wire.readFixed(in,33);h.iv=Wire.readFixed(in,12);h.tag=Wire.readFixed(in,16);
            h.ct=Wire.readBlob(in,MAX_CIPHER);return h;
        }
        void send(DataOutputStream out)throws IOException{
            out.write(eph);out.write(iv);out.write(tag);Wire.writeBlob(out,ct);
        }
    }
    static final class PartyPacket {
        HybridCiphertext encBid,encId;
        String ax,ay,z,ethSig,commitmentSig,sigmaJson,reserved;
        byte[] edSig;
        static PartyPacket receive(DataInputStream in)throws IOException{
            PartyPacket p=new PartyPacket();
            p.encBid=HybridCiphertext.receive(in);p.encId=HybridCiphertext.receive(in);
            p.ax=Wire.readString(in);p.ay=Wire.readString(in);p.z=Wire.readString(in);
            p.edSig=Wire.readFixed(in,64);p.ethSig=Wire.readString(in);p.commitmentSig=Wire.readString(in);
            p.sigmaJson=Wire.readString(in);p.reserved=Wire.readString(in);
            return p;
        }
        void send(DataOutputStream out)throws IOException{
            encBid.send(out);encId.send(out);Wire.writeString(out,ax);Wire.writeString(out,ay);Wire.writeString(out,z);
            out.write(edSig);Wire.writeString(out,ethSig);Wire.writeString(out,commitmentSig);
            Wire.writeString(out,sigmaJson);Wire.writeString(out,reserved);
        }
    }
    static final class Evidence {
        String receiptHash="",leafHash="",receiptSignature="",root="",evidenceSignature="",vectorSignature="";
        List<String> elements=new ArrayList<>();List<Long> directions=new ArrayList<>();
    }
    static final class Entry {
        Socket socket;DataOutputStream output;long sessionId,bidderId;
        String role,name,commitDomain,c0x,c0y,c1x,c1y,r0,r1;
        PartyPacket p0,p1;
        Evidence m0=new Evidence(),m1=new Evidence();
        Evidence evidence(int p){return p==0?m0:m1;}
        PartyPacket packet(int p){return p==0?p0:p1;}
        static Entry receive(Socket socket,DataInputStream in,DataOutputStream out)throws IOException{
            if(!Wire.readString(in).equals(WIRE_MAGIC))throw new IOException("incorrect bidder magic");
            Entry e=new Entry();e.socket=socket;e.output=out;
            e.sessionId=Wire.readU64(in);e.role=Wire.readString(in);e.name=Wire.readString(in);
            e.bidderId=Wire.readU64(in);e.commitDomain=Wire.readString(in);
            e.c0x=Wire.readString(in);e.c0y=Wire.readString(in);e.c1x=Wire.readString(in);e.c1y=Wire.readString(in);
            e.r0=Wire.readString(in);e.r1=Wire.readString(in);
            e.p0=PartyPacket.receive(in);e.p1=PartyPacket.receive(in);
            if(!e.role.equals("buyer")&&!e.role.equals("seller"))throw new IOException("invalid bidder role");
            return e;
        }
    }
    static String execute(String... args)throws Exception{
        Process p=new ProcessBuilder(args).redirectErrorStream(true).start();
        String stdout;
        try(InputStream in=p.getInputStream()){stdout=new String(in.readAllBytes(),StandardCharsets.UTF_8);}
        int status=p.waitFor();
        if(status!=0)throw new IOException("external command failed ("+status+"): "+Arrays.toString(args)+"\n"+stdout);
        return stdout;
    }
    static String jsField(String output,String field){
        Map<String,Object> obj;
        try{obj=SimpleJson.object(output.trim());}
        catch(Exception e){
            int pos=output.lastIndexOf('{');
            if(pos<0)throw new IllegalArgumentException("invalid JS output: "+output,e);
            obj=SimpleJson.object(output.substring(pos).trim());
        }
        Object v=obj.get(field);if(!(v instanceof String))throw new IllegalArgumentException("missing JSON field "+field);
        return (String)v;
    }
    static String norm32(String hex){String h=hex.strip();return h.startsWith("0x")?h:"0x"+h;}
    static String receipt(Args a,Entry e,int party)throws Exception{
        return execute("node",a.signReceipt,
            "--rpc",a.chainRpc,"--contract",a.registry,"--priv-file",a.ethPriv,
            "--session-id",u(e.sessionId),"--party-id",Integer.toString(party),
            "--role",e.role,"--name",e.name,"--bidder-id",u(e.bidderId),
            "--commit-domain",e.commitDomain,"--c0x",e.c0x,"--c0y",e.c0y,"--c1x",e.c1x,"--c1y",e.c1y);
    }
    static String vectorSignature(Args a,String role,int party,String root,int count)throws Exception{
        return jsField(execute("node",a.signVector,"--rpc",a.chainRpc,"--contract",a.registry,
            "--priv-file",a.ethPriv,"--session-id",u(a.sessionId),"--party-id",Integer.toString(party),
            "--role",role,"--root",root,"--count",Integer.toString(count)),"signature");
    }
    static String evidenceSignature(Args a,Entry e,int party)throws Exception{
        Evidence m=e.evidence(party);
        return jsField(execute("node",a.signEvidence,"--rpc",a.chainRpc,"--contract",a.registry,
            "--priv-file",a.ethPriv,"--session-id",u(e.sessionId),"--party-id",Integer.toString(party),
            "--role",e.role,"--name",e.name,"--bidder-id",u(e.bidderId),
            "--receipt-hash",m.receiptHash,"--root",m.root,
            "--path-elements",String.join(",",m.elements),
            "--path-directions",String.join(",",m.directions.stream().map(String::valueOf).toList())),"signature");
    }
    static final class MerkleTree {
        List<List<byte[]>> levels=new ArrayList<>();
        MerkleTree(List<String> leaves)throws Exception{
            List<byte[]> current=new ArrayList<>();
            for(String s:leaves)current.add(hex32(s));
            if(current.isEmpty())current.add(new byte[32]);
            levels.add(current);
            while(current.size()>1){
                List<byte[]> next=new ArrayList<>();
                for(int i=0;i<current.size();i+=2)next.add(hashPair(current.get(i),current.get(i+1<current.size()?i+1:i)));
                current=next;levels.add(current);
            }
        }
        String root(){return bytes32(levels.get(levels.size()-1).get(0));}
        void path(Evidence m,int leaf){
            m.root=root();m.elements.clear();m.directions.clear();
            int idx=leaf;
            for(int level=0;level+1<levels.size();level++){
                List<byte[]> nodes=levels.get(level);boolean right=(idx&1)==1;
                int sibling=right?idx-1:idx+1;
                if(sibling>=nodes.size())sibling=idx;
                m.elements.add(bytes32(nodes.get(sibling)));m.directions.add(right?1L:0L);
                idx/=2;
            }
        }
    }
    static byte[] hex32(String hex){
        String h=hex.startsWith("0x")?hex.substring(2):hex;
        if(h.length()!=64)throw new IllegalArgumentException("expected bytes32: "+hex);
        return HexFormat.of().parseHex(h);
    }
    static String bytes32(byte[] b){return "0x"+HexFormat.of().formatHex(b);}
    static byte[] sha256(byte[] x)throws Exception{return MessageDigest.getInstance("SHA-256").digest(x);}
    static byte[] hashPair(byte[] a,byte[] b)throws Exception{
        byte[] data=new byte[64];System.arraycopy(a,0,data,0,32);System.arraycopy(b,0,data,32,32);
        return sha256(data);
    }
    static void sendReceipt(Entry e)throws IOException{
        for(int p=0;p<=1;p++){
            Evidence m=e.evidence(p);Wire.writeString(e.output,m.receiptHash);
            Wire.writeString(e.output,m.leafHash);Wire.writeString(e.output,m.receiptSignature);
        }
        e.output.flush();
    }
    static void sendPath(Entry e)throws IOException{
        for(int p=0;p<=1;p++){
            Evidence m=e.evidence(p);Wire.writeString(e.output,m.root);Wire.writeU64(e.output,m.elements.size());
            for(int i=0;i<m.elements.size();i++){
                Wire.writeString(e.output,m.elements.get(i));Wire.writeU64(e.output,m.directions.get(i));
            }
            Wire.writeString(e.output,m.evidenceSignature);
        }
        e.output.flush();
    }
    static Socket connectRetry(String host,int port,String label)throws Exception{
        IOException last=null;
        for(int i=1;i<=180;i++){
            try{return Wire.connect(host,port,20000);}catch(IOException e){last=e;}
            if(i==1||i%10==0||i==180)System.out.println("[BOSS] waiting for "+label+" "+host+":"+port+" attempt "+i+"/180");
            Thread.sleep(500);
        }
        throw new IOException("could not connect to "+label,last);
    }
    static void relay(String host,int port,Entry e,int party)throws Exception{
        try(Socket s=connectRetry(host,port,"auctioneer Merkle evidence")){
            s.setSoTimeout(20000);
            DataOutputStream out=new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
            Evidence m=e.evidence(party);
            Wire.writeString(out,RELAY_MAGIC);Wire.writeU64(out,e.sessionId);Wire.writeU64(out,party);
            Wire.writeString(out,e.role);Wire.writeString(out,e.name);Wire.writeU64(out,e.bidderId);
            Wire.writeString(out,e.commitDomain);
            for(String c:List.of(e.c0x,e.c0y,e.c1x,e.c1y))Wire.writeString(out,c);
            Wire.writeString(out,m.receiptHash);Wire.writeString(out,m.leafHash);Wire.writeString(out,m.receiptSignature);
            Wire.writeString(out,m.root);Wire.writeU64(out,m.elements.size());
            for(int i=0;i<m.elements.size();i++){Wire.writeString(out,m.elements.get(i));Wire.writeU64(out,m.directions.get(i));}
            Wire.writeString(out,m.evidenceSignature);Wire.writeString(out,m.vectorSignature);
            e.packet(party).send(out);out.flush();
        }
    }
    static void write(Path file,String text)throws IOException{
        if(file.getParent()!=null)Files.createDirectories(file.getParent());
        Files.writeString(file,text,StandardCharsets.UTF_8);
    }
    static void writePath(Args a,Entry e,int party)throws IOException{
        Evidence m=e.evidence(party);
        Path f=Path.of(a.metaDir,"merkle_path_session"+u(e.sessionId)+"_"+e.role+"_p"+party+"_"+e.name+".json");
        write(f,SimpleJson.stringify(SimpleJson.map("partyId",party,"pathElements",m.elements,"pathDirections",m.directions,
            "root",m.root,"evidenceSignature",m.evidenceSignature))+"\n");
    }
    static String metadata(Args a,List<Entry> entries,String b0,String b1,String s0,String s1){
        // Match the C++ metadata JSON byte-for-byte, as its SHA-256 goes on chain.
        StringBuilder out=new StringBuilder();
        out.append("{\n  \"sessionId\": \"").append(u(a.sessionId)).append("\",\n")
            .append("  \"buyerP0Root\": \"").append(b0).append("\",\n")
            .append("  \"buyerP1Root\": \"").append(b1).append("\",\n")
            .append("  \"sellerP0Root\": \"").append(s0).append("\",\n")
            .append("  \"sellerP1Root\": \"").append(s1).append("\",\n")
            .append("  \"entries\": [\n");
        for(int i=0;i<entries.size();i++){
            Entry e=entries.get(i);if(i>0)out.append(",\n");
            out.append("    {\"role\":").append(SimpleJson.quote(e.role)).append(",\"name\":").append(SimpleJson.quote(e.name))
                .append(",\"bidderId\":\"").append(u(e.bidderId)).append("\",\"commitDomain\":").append(SimpleJson.quote(e.commitDomain))
                .append(",\"c0x\":\"").append(e.c0x).append("\",\"c0y\":\"").append(e.c0y)
                .append("\",\"c1x\":\"").append(e.c1x).append("\",\"c1y\":\"").append(e.c1y)
                .append("\",\"p0ReceiptHash\":\"").append(e.m0.receiptHash)
                .append("\",\"p0LeafHash\":\"").append(e.m0.leafHash)
                .append("\",\"p0ReceiptSignature\":\"").append(e.m0.receiptSignature)
                .append("\",\"p1ReceiptHash\":\"").append(e.m1.receiptHash)
                .append("\",\"p1LeafHash\":\"").append(e.m1.leafHash)
                .append("\",\"p1ReceiptSignature\":\"").append(e.m1.receiptSignature).append("\"}");
        }
        return out.append("\n  ]\n}\n").toString();
    }
    static void submit(Args a,String b0,String b1,String s0,String s1,int bc,int sc,String hash,String uri)throws Exception{
        System.out.println(execute("node",a.submitRoots,"--rpc",a.chainRpc,"--contract",a.registry,"--priv-file",a.ethPriv,
            "--session-id",u(a.sessionId),"--buyer-p0-root",b0,"--buyer-p1-root",b1,
            "--seller-p0-root",s0,"--seller-p1-root",s1,"--buyer-count",Integer.toString(bc),
            "--seller-count",Integer.toString(sc),"--metadata-hash",hash,"--metadata-uri",uri));
    }
    static void serveReveal(int port,List<Entry> entries)throws Exception{
        try(ServerSocket server=new ServerSocket()){
            server.setReuseAddress(true);server.bind(new InetSocketAddress(port),128);
            System.out.println("[BOSS] reveal server on port "+port);
            while(true){
                try(Socket s=server.accept()){
                    s.setSoTimeout(30000);
                    DataInputStream in=new DataInputStream(new BufferedInputStream(s.getInputStream()));
                    DataOutputStream out=new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
                    String who=Wire.readString(in);long party=Wire.readU64(in);
                    Wire.writeU64(out,entries.size());
                    for(Entry e:entries){Wire.writeString(out,e.role);Wire.writeString(out,e.name);Wire.writeU64(out,e.bidderId);Wire.writeString(out,party==0?e.r0:e.r1);}
                    out.flush();System.out.println("[BOSS] served randomness to "+who+" party="+party);
                }catch(Exception e){System.err.println("[BOSS] reveal error: "+e.getMessage());}
            }
        }
    }
    static void run(Args a)throws Exception{
        Files.createDirectories(Path.of(a.metaDir));
        List<Entry> entries=new ArrayList<>();int buyer=0,seller=0;
        try(ServerSocket server=new ServerSocket()){
            server.setReuseAddress(true);server.bind(new InetSocketAddress(a.listen),128);
            System.out.println("[BOSS] listening on "+a.listen);
            while(buyer<a.nbuyers||seller<a.nsellers){
                Socket socket=server.accept();socket.setSoTimeout(180000);
                try{
                    DataInputStream in=new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                    DataOutputStream out=new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
                    Entry e=Entry.receive(socket,in,out);
                    if(e.sessionId!=a.sessionId)throw new IOException("wrong session id");
                    if(e.role.equals("buyer")&&buyer>=a.nbuyers)throw new IOException("too many buyers");
                    if(e.role.equals("seller")&&seller>=a.nsellers)throw new IOException("too many sellers");
                    for(int p=0;p<=1;p++){
                        String json=receipt(a,e,p);Evidence m=e.evidence(p);
                        m.receiptHash=norm32(jsField(json,"receiptHash"));
                        m.leafHash=norm32(jsField(json,"leafHash"));
                        m.receiptSignature=jsField(json,"signature");
                    }
                    sendReceipt(e);entries.add(e);
                    if(e.role.equals("buyer"))buyer++;else seller++;
                    System.out.println("[BOSS] accepted "+e.role+" "+e.name);
                }catch(Exception ex){System.err.println("[BOSS] receive error: "+ex);socket.close();}
            }
        }
        List<Entry> buyers=entries.stream().filter(e->e.role.equals("buyer")).toList();
        List<Entry> sellers=entries.stream().filter(e->e.role.equals("seller")).toList();
        Map<String,MerkleTree> trees=new HashMap<>();
        for(String role:List.of("buyer","seller")){
            List<Entry> group=role.equals("buyer")?buyers:sellers;
            for(int p=0;p<=1;p++){
                final int party=p;
                MerkleTree tree=new MerkleTree(group.stream().map(e->e.evidence(party).leafHash).toList());
                trees.put(role+p,tree);
                for(int i=0;i<group.size();i++)tree.path(group.get(i).evidence(p),i);
                String sig=vectorSignature(a,role,p,tree.root(),group.size());
                for(Entry e:group)e.evidence(p).vectorSignature=sig;
            }
        }
        for(Entry e:entries){
            for(int p=0;p<=1;p++){e.evidence(p).evidenceSignature=evidenceSignature(a,e,p);writePath(a,e,p);}
        }
        String b0=trees.get("buyer0").root(),b1=trees.get("buyer1").root(),
            s0=trees.get("seller0").root(),s1=trees.get("seller1").root();
        String meta=metadata(a,entries,b0,b1,s0,s1);
        String metaName="commitment_metadata_session"+u(a.sessionId)+".json";
        write(Path.of(a.metaDir,metaName),meta);
        String hash=bytes32(sha256(meta.getBytes(StandardCharsets.UTF_8)));
        submit(a,b0,b1,s0,s1,buyer,seller,hash,a.metaUri+"/"+metaName);
        for(Entry e:entries){
            try{sendPath(e);System.out.println("[BOSS] sent Merkle paths to "+e.name);}
            catch(Exception ex){System.err.println("[BOSS] send path failed: "+ex);}
            finally{e.socket.close();}
        }
        for(Entry e:entries){
            relay(a.p0,e.role.equals("buyer")?7000:7002,e,0);
            relay(a.p1,e.role.equals("buyer")?7001:7003,e,1);
            System.out.println("[BOSS] relayed evidence for "+e.role+" "+e.name);
        }
        serveReveal(a.revealPort,entries);
    }
    static void challenge(Args a,boolean finalizeOnly)throws Exception{
        List<String> cmd=new ArrayList<>(List.of("node",a.answerChallenge,"--rpc",a.chainRpc,"--contract",a.registry,
            "--priv-file",a.ethPriv,"--challenge-id",u(a.challengeId)));
        if(finalizeOnly)cmd.add("--finalize-only");else{cmd.add("--path-file");cmd.add(a.pathFile);}
        System.out.println(execute(cmd.toArray(new String[0])));
    }
    public static void main(String[] argv){
        try{Args a=args(argv);switch(a.mode){case "answer-challenge"->challenge(a,false);case "finalize-challenge"->challenge(a,true);default->run(a);}}
        catch(Exception ex){System.err.println("BidderBoss error: "+ex);System.exit(1);}
    }
}
