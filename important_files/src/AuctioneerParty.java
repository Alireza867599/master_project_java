import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/** P0/P1 shared orchestration around the Java MPC and fail-closed bidder receiver. */
public final class AuctioneerParty {
    private AuctioneerParty(){}
    static final class Options {
        final int party;
        boolean buyers=false,sellers=false;
        int nbuyers=0,nsellers=0,p0port=6000,p2port,proverPort=7800,bossRevealPort=7700;
        String p0Host="127.0.0.1",proverHost="127.0.0.1",bossHost="127.0.0.1",node="node";
        String pubkeys="pubkeys.json", privateKey,sharebidsOut,poseidon="poseidon_hash.js";
        String rpc="http://127.0.0.1:8545",registry="0x5FbDB2315678afecb367f032d93F642f64180aa3",ethPriv;
        String cceVerifier="js/verify_sigma_cce_local.js",rootTool="scripts/read_commitment_root.js";
        String cceDisputeTool="js/submit_sigma_cce_dispute.js",disputeManager="",cceDomain="PPCR-SIGMA-CCE-v1",commitDomain="SFDAC-BabyJub-Pedersen-v1";
        boolean reportCce=true;
        String checkTool="js/check_split_registry_compatibility.js",sortedShareTool="js/submit_sorted_share_bids_hash.js";
        String resultTool="js/submit_auction_result.js",winnerTool="js/submit_winner_ids_poseidon_hashes.js";
        String vectorTool="js/submit_split_dataset_signature_hashes.js",payloadTool="js/prover_payload_tool_babyjub_split_v2.cjs";
        String proverPub="keys/ProverParty.elg.pub",payloadOut="zk-snark/perm_payloads",signingSeed,revealOut;
        String submitHashTool="js/submit_perm_hash.js",finalizeCceTool="js/finalize_cce_check_requests.js";
        long session=0,maxN=128;
        boolean sendToProver=true,chainVector=true,chainSorted=true,chainResult=true,chainWinner=true,chainPerm=false,finalizeCce=false;
        String testSharesJson=null; // Explicit test harness only, never used in normal operation.
        Options(int party){this.party=party;p2port=6001+party;privateKey="keys/p"+party+".elg.priv";
            sharebidsOut="zk-snark/circuits/circomlib/sharebids_p"+party+".json";
            ethPriv="keys/p"+party+".eth.priv";signingSeed="keys/p"+party+".perm.babyjub.priv";
            revealOut="onchain/p"+party+"_revealed_randomness.json";}
    }
    public static Options parse(int party,String[] args){
        Options a=new Options(party);
        for(int i=0;i<args.length;i++){
            String f=args[i];
            if(f.equals("--buyers")){a.buyers=true;continue;}
            if(f.equals("--sellers")){a.sellers=true;continue;}
            if(f.equals("--disable-prover-send")){a.sendToProver=false;continue;}
            if(f.equals("--disable-chain-submit")){a.chainVector=false;a.chainSorted=false;a.chainWinner=false;a.chainPerm=false;continue;}
            if(f.equals("--disable-result-submit")){a.chainResult=false;a.chainWinner=false;continue;}
            if(f.equals("--disable-vector-hash-submit")){a.chainVector=false;continue;}
            if(f.equals("--disable-sorted-share-bid-hash-submit")||f.equals("--disable-sorted-share-bids-hash-submit")){a.chainSorted=false;continue;}
            if(f.equals("--disable-winner-hash-submit")){a.chainWinner=false;continue;}
            if(f.equals("--disable-cce-check-finalize")){a.finalizeCce=false;continue;}
            if(f.equals("--disable-cce-dispute-report")){a.reportCce=false;continue;}
            if(f.equals("--disable-merkle-dispute-report")){continue;}
            if(f.equals("--help")){throw new IllegalArgumentException("Usage: java P"+party+" --buyers --sellers --nbuyers N --nsellers N [--disable-chain-submit --disable-result-submit --disable-prover-send]\nAdditional options include --elg-priv, --pubkeys, --perm-session-id, --chain-rpc, --perm-registry.");}
            if(++i>=args.length)throw new IllegalArgumentException("missing argument to "+f);
            String v=args[i];
            switch(f){
                case "--nbuyers" -> a.nbuyers=Integer.parseInt(v);
                case "--nsellers" -> a.nsellers=Integer.parseInt(v);
                case "--elg-priv" -> a.privateKey=v;
                case "--pubkeys" -> a.pubkeys=v;
                case "--sharebids-out" -> a.sharebidsOut=v;
                case "--node" -> a.node=v;
                case "--cce-verifier" -> a.cceVerifier=v;
                case "--cce-dispute-tool" -> a.cceDisputeTool=v;
                case "--dispute-manager" -> a.disputeManager=v;
                case "--cce-domain" -> a.cceDomain=v;
                case "--commit-domain" -> a.commitDomain=v;
                case "--poseidon-script" -> a.poseidon=v;
                case "--p0" -> a.p0Host=v;
                case "--p0-port" -> a.p0port=Integer.parseInt(v);
                case "--p2-listen-port" -> a.p2port=Integer.parseInt(v);
                case "--boss" -> a.bossHost=v;
                case "--boss-reveal-port" -> a.bossRevealPort=Integer.parseInt(v);
                case "--reveal-out" -> a.revealOut=v;
                case "--prover-host" -> a.proverHost=v;
                case "--prover-port" -> a.proverPort=Integer.parseInt(v);
                case "--prover-pub" -> a.proverPub=v;
                case "--p0-signing-seed","--p1-signing-seed","--p1-perm-signing-key" -> a.signingSeed=v;
                case "--perm-payload-tool" -> a.payloadTool=v;
                case "--perm-payload-out-dir" -> a.payloadOut=v;
                case "--perm-max-n" -> a.maxN=Long.parseUnsignedLong(v);
                case "--perm-session-id" -> a.session=Long.parseUnsignedLong(v);
                case "--chain-rpc" -> a.rpc=v;
                case "--perm-registry" -> a.registry=v;
                case "--eth-priv" -> a.ethPriv=v;
                case "--submit-hash-tool" -> a.submitHashTool=v;
                case "--submit-vector-hashes-tool" -> a.vectorTool=v;
                case "--split-registry-check-tool" -> a.checkTool=v;
                case "--submit-sorted-share-bid-hash-tool","--submit-sorted-share-bid-vector-hash-tool","--submit-sorted-share-bids-hash-tool" -> a.sortedShareTool=v;
                case "--submit-result-tool" -> a.resultTool=v;
                case "--submit-winner-hashes-tool","--submit-winner-ids-poseidon-hashes-tool" -> a.winnerTool=v;
                case "--read-root-tool" -> a.rootTool=v;
                case "--finalize-cce-checks-tool" -> a.finalizeCceTool=v;
                case "--test-shares-json" -> a.testSharesJson=v;
                default -> throw new IllegalArgumentException("Option not yet supported by Java port: "+f);
            }
        }
        if(!a.buyers&&!a.sellers)a.buyers=true;
        if(a.buyers&&a.nbuyers<1&&a.testSharesJson==null)throw new IllegalArgumentException("--nbuyers must be positive");
        if(a.sellers&&a.nsellers<1&&a.testSharesJson==null)throw new IllegalArgumentException("--nsellers must be positive");
        if(a.nbuyers<0||a.nsellers<0||a.nbuyers>2000||a.nsellers>2000)throw new IllegalArgumentException("unreasonable bidder count");
        return a;
    }
    static void writeFile(String location,Object content)throws IOException{
        Path file=Path.of(location);if(file.getParent()!=null)Files.createDirectories(file.getParent());
        Files.writeString(file,SimpleJson.stringify(content)+"\n",StandardCharsets.UTF_8);
    }
    static Object dataSetJson(AuctioneerIngress.Good data){
        if(data==null)return null;
        List<Object> records=new ArrayList<>();for(var b:data.values)records.add(SimpleJson.map("role",b.role(),"name",b.name(),"bid_share",new java.math.BigInteger(Long.toUnsignedString(b.bidShare())),"id_share",new java.math.BigInteger(Long.toUnsignedString(b.idShare()))));
        return SimpleJson.map("count",records.size(),"records",records);
    }
    static void saveShares(Options a,AuctioneerIngress.Good buyers,AuctioneerIngress.Good sellers)throws IOException{
        writeFile(a.sharebidsOut,SimpleJson.map("ts_ms",System.currentTimeMillis(),"who","p"+a.party,"buyers",dataSetJson(buyers),"sellers",dataSetJson(sellers)));
    }
    @SuppressWarnings("unchecked")
    static AuctioneerIngress.Good readTest(String source,int kind)throws IOException{
        Map<String,Object> input=SimpleJson.object(Files.readString(Path.of(source)));
        Object ds=input.get(kind==0?"buyers":"sellers");AuctioneerIngress.Good good=new AuctioneerIngress.Good();
        if(!(ds instanceof Map<?,?> map))return good;
        Object recs=map.get("records");if(!(recs instanceof List<?> list))return good;
        for(Object item:list){if(!(item instanceof Map<?,?> record))throw new IOException("bad synthetic record");
            String name=Objects.toString(record.get("name"));String role=kind==0?"buyer":"seller";
            long bid=Long.parseUnsignedLong(Objects.toString(record.get("bid_share"))),id=Long.parseUnsignedLong(Objects.toString(record.get("id_share")));
            good.values.add(new AuctioneerIngress.Bidder(role,name,id,bid,id));
        }
        return good;
    }
    static AuctioneerIngress.Config ingress(Options a,boolean buyer){
        AuctioneerIngress.Config c=new AuctioneerIngress.Config();c.party=a.party;c.role=buyer?"buyer":"seller";c.port=(buyer?7000:7002)+a.party;
        c.expected=buyer?a.nbuyers:a.nsellers;c.privateKey=Path.of(a.privateKey);c.pubKeys=Path.of(a.pubkeys);
        c.node=a.node;c.rootTool=a.rootTool;c.rpc=a.rpc;c.registry=a.registry;c.cceVerifier=a.cceVerifier;c.session=a.session;
        c.ethPriv=a.ethPriv;c.cceDisputeTool=a.cceDisputeTool;c.disputeContract=a.disputeManager;
        c.cceDomain=a.cceDomain;c.commitDomain=a.commitDomain;c.reportCce=a.reportCce;return c;
    }
    static Socket connectRetry(String host,int port)throws Exception{
        IOException last=null;
        for(int i=0;i<30;i++)try{return Wire.connect(host,port,10000);}catch(IOException err){last=err;Thread.sleep(500);}
        throw last==null?new IOException("could not connect to peer"):last;
    }
    static String csv(long[] v){return String.join(",",AuctioneerMpc.unsigned(v));}
    static List<java.math.BigInteger> unsignedNumbers(long[] v){List<java.math.BigInteger> list=new ArrayList<>();for(long n:v)list.add(new java.math.BigInteger(Long.toUnsignedString(n)));return list;}
    static String cli(Options a,String tool,String... args)throws Exception{
        List<String> cmd=new ArrayList<>(List.of(a.node,tool));cmd.addAll(List.of(args));return AuctioneerIngress.execute(cmd.toArray(String[]::new));
    }
    static void chainResult(Options a,AuctioneerMpc.Clearing r)throws Exception{
        if(!a.chainResult)return;
        cli(a,a.resultTool,"--rpc",a.rpc,"--contract",a.registry,"--priv-file",a.ethPriv,"--session-id",Long.toUnsignedString(a.session),
            "--party-id",Integer.toString(a.party),"--K",Long.toUnsignedString(r.k),"--Pb",Long.toUnsignedString(r.pb),"--Ps",Long.toUnsignedString(r.ps),
            "--winner-buyers",csv(r.buyerIds),"--winner-sellers",csv(r.sellerIds));
        if(a.chainWinner){
            int width=Math.max(0,Math.min(a.nbuyers,a.nsellers)-1);
            long[] buyer=Arrays.copyOf(r.buyerIds,width),seller=Arrays.copyOf(r.sellerIds,width);
            cli(a,a.winnerTool,"--rpc",a.rpc,"--contract",a.registry,"--priv-file",a.ethPriv,"--session-id",Long.toUnsignedString(a.session),
                "--party-id",Integer.toString(a.party),"--winner-buyers",csv(buyer),"--winner-sellers",csv(seller));
        }
    }
    static String poseidon(Options a,long[] data)throws Exception{
        List<String> cmd=new ArrayList<>(List.of(a.node,a.poseidon));cmd.addAll(AuctioneerMpc.unsigned(data));return AuctioneerIngress.execute(cmd.toArray(String[]::new));
    }
    static void hashesAndPerms(Options a,Map<Integer,AuctioneerMpc.Sorted> sorted)throws Exception{
        for(var entry:sorted.entrySet()){
            AuctioneerMpc.Sorted result=entry.getValue();
            String permHash="";try{permHash=poseidon(a,result.perm);}catch(Exception ex){
                if(a.chainPerm||a.chainSorted)throw ex;
                System.err.printf("P%d: poseidon helper unavailable; hash omitted: %s%n",a.party,ex.getMessage());}
            writeFile("permutation_"+entry.getKey()+"_p"+a.party+".json",SimpleJson.map("dataset",result.dataset.label,"n",result.perm.length,
                "perm_1based",unsignedNumbers(result.perm),"perm_hash_poseidon",permHash));
            if(a.chainPerm){cli(a,a.submitHashTool,"--rpc",a.rpc,"--contract",a.registry,"--priv-file",a.ethPriv,"--session-id",Long.toUnsignedString(a.session),
                "--dataset-kind",Integer.toString(entry.getKey()),"--party-id",Integer.toString(a.party),"--hash",permHash);}
            if(a.chainSorted){
                long[] local=new long[result.perm.length];
                for(int i=0;i<local.length;i++)local[i]=result.dataset.bidShares[(int)result.perm[i]-1];
                String hash=poseidon(a,local);
                cli(a,a.sortedShareTool,"--rpc",a.rpc,"--contract",a.registry,"--priv-file",a.ethPriv,"--session-id",Long.toUnsignedString(a.session),
                    "--dataset-kind",Integer.toString(entry.getKey()),"--party-id",Integer.toString(a.party),"--hash",hash,"--skip-if-submitted");
            }
        }
    }
    static final class Randomness {String role,name,value;long id;Randomness(String role,String name,long id,String value){this.role=role;this.name=name;this.id=id;this.value=value;}}
    static List<Randomness> reveal(Options a)throws Exception{
        List<Randomness> all=new ArrayList<>();
        try(Socket s=Wire.connect(a.bossHost,a.bossRevealPort,30000)){
            DataOutputStream out=new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
            DataInputStream in=new DataInputStream(new BufferedInputStream(s.getInputStream()));
            Wire.writeString(out,"p"+a.party);Wire.writeU64(out,a.party);out.flush();
            long total=Wire.readU64(in);if(total<0||total>1000000)throw new IOException("bad reveal count");
            for(int i=0;i<total;i++)all.add(new Randomness(Wire.readString(in),Wire.readString(in),Wire.readU64(in),Wire.readString(in)));
        }
        return all;
    }
    static void saveReveals(Options a,List<Randomness> recs,AuctioneerIngress.Good buyers,AuctioneerIngress.Good sellers)throws IOException{
        List<Object> rows=new ArrayList<>();for(Randomness r:recs)rows.add(SimpleJson.map("role",r.role,"name",r.name,"id",Long.toUnsignedString(r.id),"r_dec",r.value));
        writeFile(a.revealOut,SimpleJson.map("ts_ms",System.currentTimeMillis(),"who","p"+a.party,"which",a.party,"count",recs.size(),
            "records",rows,"share_bids",SimpleJson.map("buyers",dataSetJson(buyers),"sellers",dataSetJson(sellers))));
    }
    static Object payload(Options a,AuctioneerMpc.Sorted sorted,AuctioneerIngress.Good good,List<Randomness> recs){
        if(sorted.perm.length<1||sorted.perm.length>a.maxN)throw new IllegalArgumentException("invalid permutation length/max-n");
        List<String> share=new ArrayList<>(),id=new ArrayList<>(),randomness=new ArrayList<>();List<Object> openings=new ArrayList<>();
        for(var b:good.values){
            String r=recs.stream().filter(x->x.name.equals(b.name())&&x.role.equals(b.role())).map(x->x.value).findFirst()
                .orElseThrow(()->new IllegalArgumentException("missing revealed randomness for "+b.name()));
            share.add(Long.toUnsignedString(b.bidShare()));id.add(Long.toUnsignedString(b.idShare()));randomness.add(r);
            openings.add(SimpleJson.map("role",b.role(),"name",b.name(),"bid_share",new java.math.BigInteger(Long.toUnsignedString(b.bidShare())),
                "bid_share_dec",Long.toUnsignedString(b.bidShare()),"id_share",new java.math.BigInteger(Long.toUnsignedString(b.idShare())),
                "id_share_dec",Long.toUnsignedString(b.idShare()),"randomness_label",a.party==0?"r0_dec":"r1_dec","r_dec",r));
        }
        return SimpleJson.map("protocol","SFDAC-AuctioneerDatasetPayload-v2","payload_type","auctioneer_dataset_reveal_split_signatures",
            "signature_profile","babyjub-eddsa-poseidon-split-dataset-v2","sender","p"+a.party,"party_id",a.party,"session_id",a.session,
            "dataset_kind",sorted.dataset.kind,"dataset_label",sorted.dataset.label,"n",sorted.perm.length,"max_n",a.maxN,
            "opening_signature_request",SimpleJson.map("scheme","babyjub-eddsa-poseidon-opening-v2","domain_tag","918273646","message_layout","Poseidon(domain,session,dataset,party,shareHash,randomnessHash,idShareHash)"),
            "permutation_signature_request",SimpleJson.map("scheme","babyjub-eddsa-poseidon-permutation-v2","domain_tag","918273647","message_layout","Poseidon(domain,session,dataset,party,permutationHash)"),
            "permutation_index_1based",unsignedNumbers(sorted.perm),"share_bid_vector_dec",share.stream().map(java.math.BigInteger::new).toList(),"id_share_vector_dec",id.stream().map(java.math.BigInteger::new).toList(),"randomness_vector_dec",randomness,
            "signed_vector_note","opening signature covers share/randomness/id-share hashes; permutation signature covers only permutation hash",
            "share_bid_openings",openings);
    }
    static void sendPayload(Options a,AuctioneerMpc.Sorted result,AuctioneerIngress.Good good,List<Randomness> revealed)throws Exception{
        String dir=a.payloadOut;Files.createDirectories(Path.of(dir));
        String base=dir+"/p"+a.party+"_auctioneer_dataset_session_"+Long.toUnsignedString(a.session)+"_dataset_"+result.dataset.kind;
        String plain=base+".plain.reveal.v2.json",signed=base+".signed.reveal.v2.json",encrypted=base+".encrypted.transport.v2.json";
        writeFile(plain,payload(a,result,good,revealed));
        String output=cli(a,a.payloadTool,"sign-encrypt","--in",plain,"--sign-priv",a.signingSeed,"--prover-pub",a.proverPub,"--signed-out",signed,"--out",encrypted);
        if(!output.contains("babyjub-eddsa-poseidon-split-dataset-v2"))throw new IOException("split signature tool returned unexpected profile: "+output);
        Exception onchainError=null;
        if(a.chainVector)try{cli(a,a.vectorTool,"--rpc",a.rpc,"--contract",a.registry,"--priv-file",a.ethPriv,
            "--session-id",Long.toUnsignedString(a.session),"--dataset-kind",Integer.toString(result.dataset.kind),"--party-id",Integer.toString(a.party),"--payload",signed);}
        catch(Exception ex){onchainError=ex;System.err.println("WARNING: signed payload will be relayed but chain publication failed: "+ex.getMessage());}
        try(Socket s=Wire.connect(a.proverHost,a.proverPort,30000)){
            DataOutputStream out=new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
            DataInputStream in=new DataInputStream(new BufferedInputStream(s.getInputStream()));
            Wire.writeString(out,Files.readString(Path.of(encrypted)));out.flush();
            String ack=Wire.readString(in);
            if(!Boolean.TRUE.equals(SimpleJson.object(ack).get("ok")))throw new IOException("ProverParty failed: "+ack);
            System.out.println("P"+a.party+": ProverParty ACK: "+ack);
        }
        if(onchainError!=null)throw onchainError;
    }
    public static void start(int party,String[] cliArgs)throws Exception{
        Options a=parse(party,cliArgs);
        if(a.chainVector && a.testSharesJson==null)cli(a,a.checkTool,"--rpc",a.rpc,"--contract",a.registry);
        AuctioneerIngress.Good buyers=null,sellers=null;
        ExecutorService pool=Executors.newFixedThreadPool(2);
        try{
            Future<AuctioneerIngress.Good> bf=null,sf=null;
            if(a.testSharesJson!=null){
                if(a.buyers)buyers=readTest(a.testSharesJson,0);
                if(a.sellers)sellers=readTest(a.testSharesJson,1);
            }else{
                if(a.buyers)bf=pool.submit(()->AuctioneerIngress.receive(ingress(a,true)));
                if(a.sellers)sf=pool.submit(()->AuctioneerIngress.receive(ingress(a,false)));
                if(bf!=null)buyers=bf.get();if(sf!=null)sellers=sf.get();
            }
        }finally{pool.shutdownNow();}
        saveShares(a,buyers,sellers);
        try(Socket peer=party==0?accept(a.p0port):connectRetry(a.p0Host,a.p0port)){
            AuctioneerMpc.Channel channel=new AuctioneerMpc.Channel(peer);
            // P0 sends the canonical bidder order, and both sides discard non-intersecting names.
            if(party==0){
                List<String> bn=buyers==null?List.of():buyers.names();channel.putStrings(bn);List<String> remote=channel.getStrings();if(buyers!=null)buyers.align(bn,remote);
                List<String> sn=sellers==null?List.of():sellers.names();channel.putStrings(sn);remote=channel.getStrings();if(sellers!=null)sellers.align(sn,remote);
            }else{
                List<String> bn=channel.getStrings();channel.putStrings(buyers==null?List.of():buyers.names());if(buyers!=null)buyers.align(bn,bn);
                List<String> sn=channel.getStrings();channel.putStrings(sellers==null?List.of():sellers.names());if(sellers!=null)sellers.align(sn,sn);
            }
            saveShares(a,buyers,sellers);
            int bcount=buyers==null?0:buyers.values.size(),scount=sellers==null?0:sellers.values.size();
            if(bcount==0||scount==0||bcount!=scount){
                System.out.printf("P%d: honest buyer/seller counts zero or unequal (%d/%d), auction ends before MPC%n",party,bcount,scount);
                chainResult(a,new AuctioneerMpc.Clearing(0,0,0,new long[0],new long[0]));return;
            }
            List<AuctioneerMpc.Dataset> datasets=new ArrayList<>();if(buyers!=null)datasets.add(buyers.asDataset(0));if(sellers!=null)datasets.add(sellers.asDataset(1));
            try(ServerSocket server=new ServerSocket()){
                server.setReuseAddress(true);server.bind(new InetSocketAddress(a.p2port));
                System.out.printf("P%d: waiting for P2 at port %d%n",party,a.p2port);
                try(Socket p2=server.accept()){
                    AuctioneerMpc mpc=new AuctioneerMpc(party,peer,p2);
                    Map<Integer,AuctioneerMpc.Sorted> sorted=mpc.sort(datasets);
                    hashesAndPerms(a,sorted);
                    AuctioneerMpc.Clearing result=mpc.clear();
                    System.out.printf("P%d: clearing K=%s Pb=%s Ps=%s%n",party,Long.toUnsignedString(result.k),Long.toUnsignedString(result.pb),Long.toUnsignedString(result.ps));
                    writeFile("onchain/p"+party+"_auction_result_session"+Long.toUnsignedString(a.session)+".json",result.toJson());
                    chainResult(a,result);
                    List<Randomness> randomness=List.of();
                    try{randomness=reveal(a);saveReveals(a,randomness,buyers,sellers);}
                    catch(Exception ex){System.err.println("P"+party+": could not reveal randomness: "+ex.getMessage());if(a.sendToProver)throw ex;}
                    if(a.sendToProver)for(var entry:sorted.entrySet())sendPayload(a,entry.getValue(),entry.getKey()==0?buyers:sellers,randomness);
                }
            }
        }
    }
    static Socket accept(int port)throws IOException{
        try(ServerSocket server=new ServerSocket()){
            server.setReuseAddress(true);server.bind(new InetSocketAddress(port));return server.accept();
        }
    }
}
