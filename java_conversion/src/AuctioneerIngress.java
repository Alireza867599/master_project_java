import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;

/** Java port of bidder direct/evidence reception used by P0/P1.
 *  Fail-closed: a bidder is admitted only after the two signed packet copies,
 *  the Ed25519 transcript, CCE verifier, Merkle path and on-chain root pass.
 */
public final class AuctioneerIngress {
    private static final String DIRECT="SFDAC-AUCTIONEER-DIRECT-V1";
    private static final String EVIDENCE="SFDAC-MERKLE-EVIDENCE-V1";
    private static final String SIGNED="SFDAC-BIDDER-SIGNED-PACKET-V3";
    private static final int MAX_BLOB=4096;
    public static final class Config {
        public int party; public String role;public int port,expected;
        public Path privateKey=Path.of("keys/p0.elg.priv"),pubKeys=Path.of("pubkeys.json");
        public String node="node",rootTool="scripts/read_commitment_root.js",rpc="http://127.0.0.1:8545",registry="",cceVerifier="js/verify_sigma_cce_local.js";
        public String cceDomain="PPCR-SIGMA-CCE-v1",commitDomain="SFDAC-BabyJub-Pedersen-v1",disputeContract="",ethPriv="",cceDisputeTool="js/submit_sigma_cce_dispute.js";
        public boolean reportCce=true;
        public long session;public int socketTimeoutMillis=30000;
    }
    public record Bidder(String role,String name,long id,long bidShare,long idShare) {}
    public static final class Good {
        public final List<Bidder> values=new ArrayList<>();
        public List<String> names(){return values.stream().map(Bidder::name).toList();}
        public AuctioneerMpc.Dataset asDataset(int kind){long[] b=new long[values.size()],id=new long[values.size()];for(int i=0;i<values.size();i++){b[i]=values.get(i).bidShare();id[i]=values.get(i).idShare();}return new AuctioneerMpc.Dataset(kind,names(),b,id);}
        public void align(List<String> own,List<String> other){Set<String> allowed=new HashSet<>(other);Map<String,Bidder> by=new HashMap<>();for(Bidder d:values)by.put(d.name(),d);List<Bidder> common=new ArrayList<>();for(String s:own)if(allowed.contains(s)&&by.containsKey(s))common.add(by.get(s));values.clear();values.addAll(common);}
    }
    public static final class Packet {
        public byte[] ephBid,ivBid,tagBid,ctBid,ephId,ivId,tagId,ctId,edSignature,transcript;
        public String ax,ay,z,ethSig,commitSig,sigmaJson,publicJson;
    }
    static final class Record {
        String magic,role,name,domain,c0x,c0y,c1x,c1y,receiptHash,leafHash,receiptSig,root,evidenceSig,vectorSig;
        long id,session;int party;
        List<String> siblings=new ArrayList<>();List<Long> directions=new ArrayList<>();Packet packet;
        String key(){return role+"/"+name+"/"+Long.toUnsignedString(id);}
    }
    private static void transcriptString(DataOutput out,String s)throws IOException{Wire.writeString(out,s);}
    static Packet packet(DataInputStream in,Record r)throws IOException{
        Packet p=new Packet();ByteArrayOutputStream buf=new ByteArrayOutputStream();DataOutputStream tr=new DataOutputStream(buf);
        transcriptString(tr,SIGNED);tr.writeLong(r.session);tr.writeLong(r.party);
        transcriptString(tr,r.role);transcriptString(tr,r.name);tr.writeLong(r.id);transcriptString(tr,r.domain);
        transcriptString(tr,r.party==0?r.c0x:r.c1x);transcriptString(tr,r.party==0?r.c0y:r.c1y);
        p.ephBid=readSigned(in,tr,33);p.ivBid=readSigned(in,tr,12);p.tagBid=readSigned(in,tr,16);
        p.ctBid=readSignedBlob(in,tr);
        p.ephId=readSigned(in,tr,33);p.ivId=readSigned(in,tr,12);p.tagId=readSigned(in,tr,16);
        p.ctId=readSignedBlob(in,tr);
        p.ax=readSignedString(in,tr);p.ay=readSignedString(in,tr);p.z=readSignedString(in,tr);
        p.edSignature=Wire.readFixed(in,64);
        p.ethSig=Wire.readString(in);p.commitSig=Wire.readString(in);
        p.sigmaJson=Wire.readString(in);p.publicJson=Wire.readString(in);
        transcriptString(tr,p.sigmaJson);transcriptString(tr,p.ethSig);transcriptString(tr,p.commitSig);
        p.transcript=buf.toByteArray();return p;
    }
    static byte[] readSigned(DataInputStream in,DataOutput tr,int count)throws IOException{byte[] b=Wire.readFixed(in,count);tr.write(b);return b;}
    static byte[] readSignedBlob(DataInputStream in,DataOutput tr)throws IOException{long n=Wire.readU64(in);if(n<0||n>MAX_BLOB)throw new IOException("invalid ciphertext length");tr.writeLong(n);return readSigned(in,tr,(int)n);}
    static String readSignedString(DataInputStream in,DataOutput tr)throws IOException{long n=Wire.readU64(in);if(n<0||n>128L*1024*1024)throw new IOException("signed string too large");tr.writeLong(n);byte[] b=readSigned(in,tr,(int)n);return new String(b,StandardCharsets.UTF_8);}
    static Record readRecord(Socket s,Config c)throws IOException{
        DataInputStream in=new DataInputStream(new BufferedInputStream(s.getInputStream(),65536));
        Record r=new Record();r.magic=Wire.readString(in);r.session=Wire.readU64(in);r.party=(int)Wire.readU64(in);
        if(r.session!=c.session||r.party!=c.party)throw new IOException("session/party mismatch");
        r.role=Wire.readString(in);r.name=Wire.readString(in);r.id=Wire.readU64(in);
        r.domain=Wire.readString(in);r.c0x=Wire.readString(in);r.c0y=Wire.readString(in);r.c1x=Wire.readString(in);r.c1y=Wire.readString(in);
        if(DIRECT.equals(r.magic)){r.packet=packet(in,r);return r;}
        if(!EVIDENCE.equals(r.magic))throw new IOException("invalid incoming magic: "+r.magic);
        r.receiptHash=Wire.readString(in);r.leafHash=Wire.readString(in);r.receiptSig=Wire.readString(in);r.root=Wire.readString(in);
        long depth=Wire.readU64(in);if(depth<0||depth>1024)throw new IOException("invalid Merkle depth");
        for(int i=0;i<depth;i++){r.siblings.add(Wire.readString(in));r.directions.add(Wire.readU64(in));}
        r.evidenceSig=Wire.readString(in);r.vectorSig=Wire.readString(in);r.packet=packet(in,r);return r;
    }
    static byte[] hex32(String s){byte[] b=Secp256k1Ecies.hex(s);if(b.length!=32)throw new IllegalArgumentException("invalid 32 byte Merkle hash");return b;}
    public static boolean verifyMerkle(String leaf,String root,List<String> sib,List<Long> directions)throws Exception{
        if(sib.size()!=directions.size())return false;
        byte[] cur=hex32(leaf);MessageDigest md=MessageDigest.getInstance("SHA-256");
        for(int i=0;i<sib.size();i++){
            byte[] peer=hex32(sib.get(i));long dir=directions.get(i);if(dir!=0&&dir!=1)return false;
            md.reset();if(dir==0){md.update(cur);md.update(peer);}else{md.update(peer);md.update(cur);}cur=md.digest();
        }
        return MessageDigest.isEqual(cur,hex32(root));
    }
    static boolean verifyEd(byte[] rawKey,byte[] message,byte[] signature)throws Exception{
        if(rawKey.length!=32 || signature.length!=64)return false;
        byte[] head=Secp256k1Ecies.hex("302a300506032b6570032100");
        byte[] enc=Arrays.copyOf(head,head.length+32);System.arraycopy(rawKey,0,enc,head.length,32);
        PublicKey pub=KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(enc));
        Signature ed=Signature.getInstance("Ed25519");ed.initVerify(pub);ed.update(message);return ed.verify(signature);
    }
    static Map<String,byte[]> keys(Path path)throws IOException{
        Map<String,byte[]> out=new HashMap<>();
        Map<String,Object> json=SimpleJson.object(Files.readString(path));
        for(var entry:json.entrySet())if(entry.getValue() instanceof String s){byte[] k=Secp256k1Ecies.hex(s);if(k.length==32)out.put(entry.getKey(),k);}
        return out;
    }
    static String execute(String... args)throws Exception{
        ProcessBuilder pb=new ProcessBuilder(args).redirectErrorStream(true);
        Process proc=pb.start();String result;
        try(InputStream in=proc.getInputStream()){result=new String(in.readAllBytes(),StandardCharsets.UTF_8);}
        if(!proc.waitFor(90,TimeUnit.SECONDS)){proc.destroyForcibly();throw new IOException("external tool timed out: "+args[1]);}
        if(proc.exitValue()!=0)throw new IOException("external command failed ["+proc.exitValue()+"]: "+String.join(" ",Arrays.copyOf(args,2))+" output="+result);
        return result.trim();
    }
    static String readRoot(Config cfg,String role)throws Exception{
        String output=execute(cfg.node,cfg.rootTool,"--rpc",cfg.rpc,"--contract",cfg.registry,
            "--session-id",Long.toUnsignedString(cfg.session),"--party-id",Integer.toString(cfg.party),"--role",role);
        int begin=output.indexOf('{');if(begin<0)throw new IOException("root tool returned no JSON");
        return SimpleJson.string(SimpleJson.object(output.substring(begin)),"root","");
    }
    public record CceResult(boolean signatureOk,boolean proofOk){}
    static CceResult verifyCce(Config cfg,Packet p)throws Exception{
        // A cryptographically invalid CCE is not an I/O failure; verifier may exit nonzero.
        List<String> cmd=List.of(cfg.node,cfg.cceVerifier,"--rpc",cfg.rpc,"--contract",cfg.registry,
            "--sigma-proof-json",p.sigmaJson,"--signature",p.ethSig);
        Process proc=new ProcessBuilder(cmd).redirectErrorStream(true).start();String output;
        try(InputStream in=proc.getInputStream()){output=new String(in.readAllBytes(),StandardCharsets.UTF_8);}
        if(!proc.waitFor(90,TimeUnit.SECONDS)){proc.destroyForcibly();throw new IOException("CCE verifier timeout");}
        int pos=output.indexOf('{');if(pos<0)throw new IOException("CCE verifier returned no JSON: "+output);
        Map<String,Object> js=SimpleJson.object(output.substring(pos).trim());
        if(!(js.get("signatureOk") instanceof Boolean)||!(js.get("proofOk") instanceof Boolean))throw new IOException("CCE verifier missing signatureOk/proofOk");
        return new CceResult(Boolean.TRUE.equals(js.get("signatureOk")),Boolean.TRUE.equals(js.get("proofOk")));
    }
    static void reportBadCce(Config cfg,Record r)throws Exception{
        if(!cfg.reportCce)return;
        String contract=cfg.disputeContract.isEmpty()?cfg.registry:cfg.disputeContract;
        List<String> cmd=new ArrayList<>(List.of(cfg.node,cfg.cceDisputeTool,
            "--rpc",cfg.rpc,"--contract",contract,"--priv-file",cfg.ethPriv,
            "--session-id",Long.toUnsignedString(cfg.session),"--party-id",Integer.toString(cfg.party),
            "--role",r.role,"--name",r.name,"--bidder-id",Long.toUnsignedString(r.id),
            "--commit-domain",r.domain,"--cce-domain",cfg.cceDomain,
            "--c0x",r.c0x,"--c0y",r.c0y,"--c1x",r.c1x,"--c1y",r.c1y,
            "--sigma-proof-json",r.packet.sigmaJson,"--bidder-eth-sig",r.packet.ethSig,
            "--commitment-sig",r.packet.commitSig));
        System.out.println("P"+cfg.party+": CCE dispute: "+execute(cmd.toArray(String[]::new)));
    }
    private static boolean comparable(Record d,Record e){return d.c0x.equals(e.c0x)&&d.c0y.equals(e.c0y)&&d.c1x.equals(e.c1x)&&d.c1y.equals(e.c1y)&&d.domain.equals(e.domain);}
    public static Good receive(Config cfg)throws Exception{
        Map<String,byte[]> pubkeys=keys(cfg.pubKeys);
        Map<String,Record> direct=new LinkedHashMap<>(),evidence=new LinkedHashMap<>();
        try(ServerSocket server=new ServerSocket()){
            server.setReuseAddress(true);server.bind(new InetSocketAddress(cfg.port));server.setSoTimeout(120000);
            System.out.printf("P%d: listening for %d %s direct packets + Merkle evidence on %d%n",cfg.party,cfg.expected,cfg.role,cfg.port);
            while(direct.size()<cfg.expected||evidence.size()<cfg.expected){
                try(Socket socket=server.accept()){
                    socket.setSoTimeout(cfg.socketTimeoutMillis);
                    Record item=readRecord(socket,cfg);
                    if(!item.role.equals(cfg.role))throw new IOException("unexpected bidder role on "+cfg.port);
                    Map<String,Record> target=DIRECT.equals(item.magic)?direct:evidence;
                    if(target.putIfAbsent(item.key(),item)!=null)throw new IOException("duplicate record for "+item.key());
                    if(target.size()>cfg.expected)throw new IOException("too many incoming packets");
                }
            }
        }
        Good good=new Good();
        for(Record d:direct.values()){
            Record e=evidence.get(d.key());boolean ok=e!=null&&comparable(d,e);
            try{
                if(!ok)throw new SecurityException("missing/mismatching signed Merkle evidence");
                if(!verifyMerkle(e.leafHash,e.root,e.siblings,e.directions))throw new SecurityException("bad Merkle path");
                String chain=readRoot(cfg,d.role);
                if(!MessageDigest.isEqual(hex32(chain),hex32(e.root)))throw new SecurityException("Merkle root not on chain");
                byte[] rawKey=pubkeys.get(d.name);
                if(rawKey==null||!verifyEd(rawKey,d.packet.transcript,d.packet.edSignature))throw new SecurityException("invalid Ed25519 bidder signature");
                long bid=Secp256k1Ecies.decryptU64(d.packet.ephBid,d.packet.ivBid,d.packet.tagBid,d.packet.ctBid,cfg.privateKey);
                CceResult cce=verifyCce(cfg,d.packet);
                if(cce.signatureOk()&&!cce.proofOk()&&cfg.reportCce){
                    try{reportBadCce(cfg,d);}catch(Exception ex){System.err.println("P"+cfg.party+": CCE on-chain dispute failed: "+ex.getMessage());}
                }
                if(!cce.signatureOk()||!cce.proofOk())throw new SecurityException("invalid Sigma-CCE proof/signature");
                long id=Secp256k1Ecies.decryptU64(d.packet.ephId,d.packet.ivId,d.packet.tagId,d.packet.ctId,cfg.privateKey);
                if(good.values.stream().anyMatch(b->b.name().equals(d.name)))throw new SecurityException("duplicate bidder name");
                good.values.add(new Bidder(d.role,d.name,d.id,bid,id));
                System.out.printf("P%d: accepted valid %s %s (ID=%s)%n",cfg.party,d.role,d.name,Long.toUnsignedString(d.id));
            }catch(Exception ex){System.err.printf("P%d: bidder %s rejected: %s%n",cfg.party,d.name,ex.getMessage());}
        }
        return good;
    }
}
