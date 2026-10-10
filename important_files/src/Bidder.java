import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Java 21 port of bidder.cpp. Uses existing BabyJub and Ethereum Node helpers. */
public final class Bidder {
    static final String WIRE_MAGIC="SFDAC-BIDDER-PACKET-V2",DIRECT_MAGIC="SFDAC-AUCTIONEER-DIRECT-V1";
    static final String DOMAIN="SFDAC-BIDDER-SIGNED-PACKET-V3";
    static final BigInteger BABYJUB_ORDER=new BigInteger("2736030358979909402780800718157159386076813972158567259200215660948447373041");
    static final SecureRandom RNG=new SecureRandom();
    static final String ZERO="0x"+"00".repeat(32);
    static final class Args {
        String mode="submit",boss="127.0.0.1",p0Host="127.0.0.1",p1Host="127.0.0.1";
        int port=7500,p0BuyerPort=7000,p1BuyerPort=7001,p0SellerPort=7002,p1SellerPort=7003;
        long session=0,bid=0,id=0,invalidDelta=1,inconsistentDelta=1,pathDelay=60;
        String role="",name="",p0Pub="keys/p0.elg.pub",p1Pub="keys/p1.elg.pub",edDir="keys",ethDir="keys";
        String commitDomain="SFDAC-BabyJub-Pedersen-v1",cceDomain="PPCR-SIGMA-CCE-v1";
        String chainRpc="",registry="",disputeManager="",ethPriv="";
        String cceSignTool="js/sign_sigma_cce_packet.js",commitSignTool="js/sign_commitment_packet.js";
        String sigmaProofTool="js/sigma_cce_prove.js",deriveHTool="js/derive_commitment_H.js";
        String p0BabyPub="keys/p0.babyjub.pub.json",p1BabyPub="keys/p1.babyjub.pub.json";
        String challengeTool="scripts/challenge_commitment_exclusion.js",readRootTool="scripts/read_commitment_root.js";
        String out="receipt.json",receiptFile="";
        boolean invalid0=false,invalid1=false,inconsistent0=false,inconsistent1=false;
    }
    static int port(String x){return BidderBoss.port(x);}
    static Args parse(String[] argv){
        Args a=new Args();
        for(int i=0;i<argv.length;i++){
            String f=argv[i];
            switch(f){
                case "--invalid-cce-p0"->{a.invalid0=true;continue;}
                case "--invalid-cce-p1"->{a.invalid1=true;continue;}
                case "--invalid-cce-both"->{a.invalid0=true;a.invalid1=true;continue;}
                case "--inconsistent-p0-commitment"->{a.inconsistent0=true;continue;}
                case "--inconsistent-p1-commitment"->{a.inconsistent1=true;continue;}
                case "--inconsistent-both-commitments"->{a.inconsistent0=true;a.inconsistent1=true;continue;}
            }
            if(i+1>=argv.length)throw new IllegalArgumentException("missing value for "+f);
            String v=argv[++i];
            switch(f){
                case "--mode"->a.mode=v;case "--boss"->a.boss=v;case "--port"->a.port=port(v);
                case "--p0-host"->a.p0Host=v;case "--p1-host"->a.p1Host=v;
                case "--p0-buyer-port"->a.p0BuyerPort=port(v);case "--p1-buyer-port"->a.p1BuyerPort=port(v);
                case "--p0-seller-port"->a.p0SellerPort=port(v);case "--p1-seller-port"->a.p1SellerPort=port(v);
                case "--session-id"->a.session=Long.parseUnsignedLong(v);
                case "--role"->a.role=v;case "--name"->a.name=v;
                case "--bid"->a.bid=Long.parseUnsignedLong(v);case "--id"->a.id=Long.parseUnsignedLong(v);
                case "--p0pub"->a.p0Pub=v;case "--p1pub"->a.p1Pub=v;
                case "--ed25519-priv-dir"->a.edDir=v;case "--bidder-eth-priv-dir"->a.ethDir=v;
                case "--commit-domain"->a.commitDomain=v;case "--cce-domain"->a.cceDomain=v;
                case "--chain-rpc"->a.chainRpc=v;case "--auction-registry","--registry"->a.registry=v;
                case "--dispute-manager"->a.disputeManager=v;
                case "--cce-packet-sign-tool"->a.cceSignTool=v;
                case "--commitment-packet-sign-tool"->a.commitSignTool=v;
                case "--sigma-cce-proof-tool"->a.sigmaProofTool=v;
                case "--derive-commitment-h-tool"->a.deriveHTool=v;
                case "--p0-babyjub-pub"->a.p0BabyPub=v;
                case "--p1-babyjub-pub"->a.p1BabyPub=v;
                case "--challenge-tool"->a.challengeTool=v;
                case "--read-root-tool"->a.readRootTool=v;
                case "--path-check-delay-sec"->a.pathDelay=Long.parseUnsignedLong(v);
                case "--invalid-cce-delta"->a.invalidDelta=Long.parseUnsignedLong(v);
                case "--inconsistent-commitment-delta"->a.inconsistentDelta=Long.parseUnsignedLong(v);
                case "--eth-priv"->a.ethPriv=v;case "--out"->a.out=v;case "--receipt-file"->a.receiptFile=v;
                default->throw new IllegalArgumentException("unknown arg: "+f);
            }
        }
        if(!a.mode.equals("submit")&&!a.mode.equals("challenge"))throw new IllegalArgumentException("mode must be submit or challenge");
        if(a.mode.equals("submit")&&(!Set.of("buyer","seller").contains(a.role)||a.name.isEmpty()))throw new IllegalArgumentException("submit requires --role buyer|seller and --name");
        if(a.mode.equals("challenge")&&a.receiptFile.isEmpty())throw new IllegalArgumentException("challenge requires --receipt-file");
        if(a.chainRpc.isEmpty()||a.registry.isEmpty()||a.ethPriv.isEmpty())throw new IllegalArgumentException("--chain-rpc --auction-registry --eth-priv required");
        if(a.disputeManager.isEmpty())a.disputeManager=a.registry;
        return a;
    }
    record Point(String x,String y) {}
    static String u(long l){return Long.toUnsignedString(l);}
    static String hex(byte[] bytes){return HexFormat.of().formatHex(bytes);}
    static String fileHex(String path)throws IOException{return Files.readString(Path.of(path),StandardCharsets.UTF_8).strip();}
    static Point jsonPoint(String raw,String x,String y){Map<String,Object> j=SimpleJson.object(raw);return new Point(SimpleJson.string(j,x,""),SimpleJson.string(j,y,""));}
    static Point babyPub(String file)throws IOException{return jsonPoint(Files.readString(Path.of(file)),"x","y");}
    static String node(String tool,String...args)throws Exception{
        String[] cmd=new String[args.length+2];cmd[0]="node";cmd[1]=tool;
        System.arraycopy(args,0,cmd,2,args.length);return BidderBoss.execute(cmd);
    }
    static String field(String out,String key){return BidderBoss.jsField(out,key);}
    static Point commit(Args a,long val,String random)throws Exception{
        return jsonPoint(node("babyjub_commit.js",a.commitDomain,u(val),random),"Cx","Cy");
    }
    static String scalar(){return new BigInteger(256,RNG).mod(BABYJUB_ORDER).toString();}
    static BidderBoss.HybridCiphertext encrypt(long v,byte[] publicKey)throws Exception{
        BigInteger nonce;
        do{nonce=new BigInteger(256,RNG);}while(nonce.signum()==0||nonce.compareTo(Secp256k1Ecies.N)>=0);
        Secp256k1Ecies.Point eph=Secp256k1Ecies.publicFromPrivate(nonce);
        Secp256k1Ecies.Point shared=Secp256k1Ecies.mul(nonce,Secp256k1Ecies.decode(publicKey));
        byte[] key=MessageDigest.getInstance("SHA-256").digest(Secp256k1Ecies.to32(shared.x));
        BidderBoss.HybridCiphertext h=new BidderBoss.HybridCiphertext();
        h.eph=Secp256k1Ecies.compress(eph);h.iv=new byte[12];RNG.nextBytes(h.iv);
        Cipher aes=Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,h.iv));
        byte[] ctTag=aes.doFinal(ByteBuffer.allocate(8).putLong(v).array());
        h.ct=Arrays.copyOf(ctTag,ctTag.length-16);
        h.tag=Arrays.copyOfRange(ctTag,ctTag.length-16,ctTag.length);
        return h;
    }
    static Point deriveH(Args a)throws Exception{return jsonPoint(node(a.deriveHTool,a.commitDomain),"Hx","Hy");}
    static String proof(Args a,int party,long share,Point c,String r,Point h,Point auctionPub,boolean invalid)throws Exception{
        String path="onchain/sigma_cce_"+a.name.replaceAll("[^a-zA-Z0-9_-]","_")+"_p"+party+(invalid?"_BAD":"")+".json";
        List<String> arg=new ArrayList<>(List.of("--rpc",a.chainRpc,"--contract",a.registry,"--session-id",u(a.session),
            "--party-id",Integer.toString(party),"--role",a.role,"--name",a.name,"--bidder-id",u(a.id),
            "--commit-domain",a.commitDomain,"--cce-domain",a.cceDomain,"--x",u(share),"--r",r,
            "--Cx",c.x,"--Cy",c.y,"--Hx",h.x,"--Hy",h.y,
            "--auctioneer-pub-x",auctionPub.x,"--auctioneer-pub-y",auctionPub.y,"--out",path));
        if(invalid)arg.add("--invalid-proof");
        node(a.sigmaProofTool,arg.toArray(String[]::new));
        return Files.readString(Path.of(path));
    }
    static void appendString(DataOutputStream out,String s)throws IOException{Wire.writeString(out,s);}
    static byte[] signEd25519(byte[] seed,byte[] payload)throws Exception{
        if(seed.length!=32)throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        byte[] prefix=HexFormat.of().parseHex("302e020100300506032b657004220420");
        byte[] pkcs8=new byte[prefix.length+seed.length];
        System.arraycopy(prefix,0,pkcs8,0,prefix.length);System.arraycopy(seed,0,pkcs8,prefix.length,seed.length);
        PrivateKey privateKey=KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        Signature signer=Signature.getInstance("Ed25519");signer.initSign(privateKey);signer.update(payload);
        return signer.sign();
    }
    static BidderBoss.PartyPacket makePacket(Args a,int party,byte[] pub,byte[] edSeed,long share,long idShare,Point c,String r,Point h,Point auctionPub,boolean invalid)throws Exception{
        BidderBoss.PartyPacket p=new BidderBoss.PartyPacket();
        p.encBid=encrypt(share,pub);p.encId=encrypt(idShare,pub);
        String open=node("babyjub_schnorr_open.js",a.commitDomain,a.cceDomain,a.role,a.name,c.x,c.y,u(share),r,
            hex(p.encBid.eph),hex(p.encBid.iv),hex(p.encBid.tag),hex(p.encBid.ct));
        p.ax=field(open,"Ax");p.ay=field(open,"Ay");p.z=field(open,"z");
        p.sigmaJson=proof(a,party,share,c,r,h,auctionPub,invalid);
        String ethFile=Path.of(a.ethDir,a.name+".eth.priv").toString();
        p.ethSig=field(node(a.cceSignTool,"--rpc",a.chainRpc,"--contract",a.registry,"--priv-file",ethFile,
            "--sigma-proof-json",p.sigmaJson),"signature");
        p.commitmentSig=field(node(a.commitSignTool,"--rpc",a.chainRpc,"--contract",a.registry,
            "--priv-file",ethFile,"--session-id",u(a.session),"--party-id",Integer.toString(party),
            "--role",a.role,"--name",a.name,"--bidder-id",u(a.id),
            "--commit-domain",a.commitDomain,"--Cx",c.x,"--Cy",c.y),"signature");
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        DataOutputStream out=new DataOutputStream(bytes);
        appendString(out,DOMAIN);out.writeLong(a.session);out.writeLong(party);appendString(out,a.role);appendString(out,a.name);
        out.writeLong(a.id);appendString(out,a.commitDomain);appendString(out,c.x);appendString(out,c.y);
        p.encBid.send(out);p.encId.send(out);
        appendString(out,p.ax);appendString(out,p.ay);appendString(out,p.z);
        appendString(out,p.sigmaJson);appendString(out,p.ethSig);appendString(out,p.commitmentSig);out.flush();
        p.edSig=signEd25519(edSeed,bytes.toByteArray());
        p.reserved="";
        return p;
    }
    static Socket retry(String host,int port,String label,int attempts)throws Exception{
        IOException last=null;
        for(int i=0;i<attempts;i++){
            try{return Wire.connect(host,port,20000);}catch(IOException e){last=e;}
            if(i==0||i%10==9)System.out.println("[BIDDER] waiting for "+label+" attempt "+(i+1)+"/"+attempts);
            Thread.sleep(500);
        }
        throw new IOException("could not connect to "+label,last);
    }
    static void sendDirect(Args a,int party,Point c0,Point c1,BidderBoss.PartyPacket packet)throws Exception{
        String host=party==0?a.p0Host:a.p1Host;
        int targetPort=party==0?(a.role.equals("buyer")?a.p0BuyerPort:a.p0SellerPort):
            (a.role.equals("buyer")?a.p1BuyerPort:a.p1SellerPort);
        try(Socket socket=retry(host,targetPort,"P"+party+" direct port",180)){
            DataOutputStream out=new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            Wire.writeString(out,DIRECT_MAGIC);Wire.writeU64(out,a.session);Wire.writeU64(out,party);
            Wire.writeString(out,a.role);Wire.writeString(out,a.name);Wire.writeU64(out,a.id);
            Wire.writeString(out,a.commitDomain);
            for(String c:List.of(c0.x,c0.y,c1.x,c1.y))Wire.writeString(out,c);
            packet.send(out);out.flush();
        }
    }
    static final class MerkleInfo {
        String receiptHash,leafHash,receiptSignature,root=ZERO,evidenceSignature="";
        List<String> elements=new ArrayList<>();List<Long> directions=new ArrayList<>();boolean received=false;
        void receipt(DataInputStream input)throws IOException{
            receiptHash=Wire.readString(input);leafHash=Wire.readString(input);receiptSignature=Wire.readString(input);
        }
        void path(DataInputStream input)throws IOException{
            root=Wire.readString(input);long count=Wire.readU64(input);
            if(count<0||count>64)throw new IOException("Merkle path too long");
            for(int i=0;i<count;i++){elements.add(Wire.readString(input));directions.add(Wire.readU64(input));}
            evidenceSignature=Wire.readString(input);received=true;
        }
        boolean check()throws Exception{
            byte[] hash=BidderBoss.hex32(leafHash);
            for(int i=0;i<elements.size();i++){
                byte[] sibling=BidderBoss.hex32(elements.get(i));
                if(directions.get(i)==1)hash=BidderBoss.hashPair(sibling,hash);
                else if(directions.get(i)==0)hash=BidderBoss.hashPair(hash,sibling);
                else return false;
            }
            return normalize(BidderBoss.bytes32(hash)).equals(normalize(root));
        }
    }
    static String normalize(String hex){return "0x"+HexFormat.of().formatHex(BidderBoss.hex32(hex));}
    static String onchainRoot(Args a,int party)throws Exception{
        return field(node(a.readRootTool,"--rpc",a.chainRpc,"--contract",a.registry,"--session-id",u(a.session),
            "--role",a.role,"--party-id",Integer.toString(party)),"root");
    }
    static String challenge(Args a,String file)throws Exception{
        return node(a.challengeTool,"--rpc",a.chainRpc,"--contract",a.registry,
            "--priv-file",a.ethPriv,"--session-id",u(a.session),"--receipt-file",file);
    }
    static void saveReceipt(Args a,Point c0,Point c1,MerkleInfo p0,MerkleInfo p1,int challengeParty)throws Exception{
        Map<String,Object> out=SimpleJson.map("sessionId",u(a.session),"role",a.role,"name",a.name,"bidderId",u(a.id),
            "commitDomain",a.commitDomain,"c0x",c0.x,"c0y",c0.y,"c1x",c1.x,"c1y",c1.y,
            "challengePartyId",Integer.toString(challengeParty),"p0ReceiptHash",p0.receiptHash,"p0LeafHash",p0.leafHash,
            "p0Signature",p0.receiptSignature,"p0Root",p0.root,
            "p0PathElements",p0.elements,"p0PathDirections",p0.directions,"p0EvidenceSignature",p0.evidenceSignature,
            "p1ReceiptHash",p1.receiptHash,"p1LeafHash",p1.leafHash,"p1Signature",p1.receiptSignature,
            "p1Root",p1.root,"p1PathElements",p1.elements,"p1PathDirections",p1.directions,
            "p1EvidenceSignature",p1.evidenceSignature);
        MerkleInfo target=challengeParty==1?p1:p0;
        out.put("receiptHash",target.receiptHash);out.put("leafHash",target.leafHash);
        out.put("signature",target.receiptSignature);out.put("root",target.root);
        // Preserve the C++ compatibility aliases, where the generic path arrays are empty.
        out.put("pathElements",List.of());out.put("pathDirections",List.of());
        Path file=Path.of(a.out);
        if(file.getParent()!=null)Files.createDirectories(file.getParent());
        Files.writeString(file,SimpleJson.stringify(out)+"\n",StandardCharsets.UTF_8);
    }
    static void runSubmit(Args a)throws Exception{
        byte[] pk0=Secp256k1Ecies.hex(fileHex(a.p0Pub)),pk1=Secp256k1Ecies.hex(fileHex(a.p1Pub));
        if(pk0.length!=33||pk1.length!=33)throw new IllegalArgumentException("public keys must be 33 bytes");
        byte[] ed=Secp256k1Ecies.hex(fileHex(Path.of(a.edDir,a.name+".priv").toString()));
        if(ed.length!=32)throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        Point h=deriveH(a),jp0=babyPub(a.p0BabyPub),jp1=babyPub(a.p1BabyPub);
        long bid0=RNG.nextLong(),bid1=a.bid-bid0,id0=RNG.nextLong(),id1=a.id-id0;
        String r0=scalar(),r1=scalar();Point c0=commit(a,bid0,r0),c1=commit(a,bid1,r1);
        BidderBoss.PartyPacket p0=makePacket(a,0,pk0,ed,a.invalid0?(bid0+a.invalidDelta==bid0?bid0^1:bid0+a.invalidDelta):bid0,id0,c0,r0,h,jp0,a.invalid0);
        BidderBoss.PartyPacket p1=makePacket(a,1,pk1,ed,a.invalid1?(bid1+a.invalidDelta==bid1?bid1^1:bid1+a.invalidDelta):bid1,id1,c1,r1,h,jp1,a.invalid1);
        Point dc0=c0,dc1=c1;BidderBoss.PartyPacket dp0=p0,dp1=p1;
        if(a.inconsistent0){long newBid=bid0+a.inconsistentDelta;if(newBid==bid0)newBid=bid0^1;
            String nr=scalar();dc0=commit(a,newBid,nr);dp0=makePacket(a,0,pk0,ed,newBid,id0,dc0,nr,h,jp0,false);}
        if(a.inconsistent1){long newBid=bid1+a.inconsistentDelta;if(newBid==bid1)newBid=bid1^1;
            String nr=scalar();dc1=commit(a,newBid,nr);dp1=makePacket(a,1,pk1,ed,newBid,id1,dc1,nr,h,jp1,false);}
        try(Socket sock=retry(a.boss,a.port,"BidderBoss",120)){
            // Boss holds the connection while it builds trees and pushes roots to the chain.
            sock.setSoTimeout(180000);
            DataOutputStream out=new DataOutputStream(new BufferedOutputStream(sock.getOutputStream()));
            DataInputStream in=new DataInputStream(new BufferedInputStream(sock.getInputStream()));
            Wire.writeString(out,WIRE_MAGIC);Wire.writeU64(out,a.session);Wire.writeString(out,a.role);
            Wire.writeString(out,a.name);Wire.writeU64(out,a.id);Wire.writeString(out,a.commitDomain);
            for(String s:List.of(c0.x,c0.y,c1.x,c1.y,r0,r1))Wire.writeString(out,s);
            p0.send(out);p1.send(out);out.flush();
            MerkleInfo m0=new MerkleInfo(),m1=new MerkleInfo();m0.receipt(in);m1.receipt(in);
            System.out.println("[BIDDER] received BidderBoss receipts p0Leaf="+m0.leafHash+" p1Leaf="+m1.leafHash);
            sendDirect(a,0,dc0,c1,dp0);sendDirect(a,1,c0,dc1,dp1);
            if(a.pathDelay>0)Thread.sleep(Math.multiplyExact(a.pathDelay,1000));
            try{m0.path(in);m1.path(in);}catch(Exception e){System.err.println("[BIDDER] Merkle path receipt failure: "+e);}
            boolean p0Included=false,p1Included=false;
            try{p0Included=m0.received&&m0.check()&&normalize(onchainRoot(a,0)).equals(normalize(m0.root));}
            catch(Exception e){System.err.println("[BIDDER] P0 path/onchain root check failed: "+e);}
            try{p1Included=m1.received&&m1.check()&&normalize(onchainRoot(a,1)).equals(normalize(m1.root));}
            catch(Exception e){System.err.println("[BIDDER] P1 path/onchain root check failed: "+e);}
            int party=!p0Included&&!m0.evidenceSignature.isEmpty()?0:(!p1Included&&!m1.evidenceSignature.isEmpty()?1:-1);
            saveReceipt(a,c0,c1,m0,m1,party<0?0:party);
            System.out.println("[BIDDER] inclusion P0="+p0Included+" P1="+p1Included+" receipt="+a.out);
            if(party>=0){
                System.out.println("[BIDDER] submitting signed Merkle challenge: "+challenge(a,a.out));
            }
        }
    }
    public static void main(String[] args){
        try{Args a=parse(args);if(a.mode.equals("challenge"))System.out.println(challenge(a,a.receiptFile));else runSubmit(a);}
        catch(Exception e){System.err.println("Bidder error: "+e);System.exit(1);}
    }
}
